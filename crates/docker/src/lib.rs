//! [`Runtime`] over the Docker Engine API through bollard. Every container this adapter creates carries the label
//! `best-peer`, so `running` and the event feed see the peer's containers and nothing else. A device is handed over
//! by the NVIDIA container toolkit when its id is an NVML UUID (`GPU-...`); other accelerators wait for their own
//! adapter. A container is confined as its spec says, in the engine's own words: capabilities dropped, no new
//! privileges, a read-only root with a private `/tmp`, ceilings on processes and on memory with swap counted in,
//! and its network. Containers are removed by the engine when they exit. Thin; proven on a host by hand, never
//! unit-tested.

use std::collections::HashMap;

use async_trait::async_trait;
use best_peer_runtime::{
    ContainerId, Event, ImageRef, Network, Progress, Published, Runtime, RuntimeError, Spec, Started,
};
use bollard::models::{ContainerCreateBody, DeviceRequest, EventMessageTypeEnum, HostConfig, PortBinding};
use bollard::query_parameters::{
    CreateImageOptionsBuilder, EventsOptionsBuilder, ListContainersOptionsBuilder, RemoveContainerOptionsBuilder,
    StopContainerOptionsBuilder,
};
use bollard::Docker;
use futures::StreamExt;
use tokio::sync::broadcast;

const LABEL: &str = "best-peer";

pub struct DockerRuntime {
    docker: Docker,
    /// The host address published ports are bound to: loopback when the peer runs on this host and reaches the
    /// engines there, every interface when the container engine is on another host (`BEST_PEER_ENGINE_HOST`).
    bind_ip: String,
    tx: broadcast::Sender<Event>,
}

impl DockerRuntime {
    /// Connects to the engine the host's defaults name (the socket, the named pipe, or `DOCKER_HOST`) and checks it
    /// answers; then follows its container events for as long as the peer runs. Published ports bind to `bind_ip`.
    pub async fn connect(bind_ip: &str) -> Result<Self, RuntimeError> {
        let docker = Docker::connect_with_local_defaults().map_err(|e| RuntimeError::Unreachable(e.to_string()))?;
        docker
            .ping()
            .await
            .map_err(|e| RuntimeError::Unreachable(format!("the Docker engine does not answer: {e}")))?;
        let (tx, _) = broadcast::channel(256);
        let me = Self {
            docker,
            bind_ip: bind_ip.into(),
            tx,
        };
        me.follow();
        Ok(me)
    }

    fn follow(&self) {
        let docker = self.docker.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            loop {
                let filters = HashMap::from([
                    ("type", vec!["container"]),
                    ("label", vec![LABEL]),
                    ("event", vec!["die", "oom"]),
                ]);
                let mut events = docker.events(Some(EventsOptionsBuilder::new().filters(&filters).build()));
                while let Some(next) = events.next().await {
                    let m = match next {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(error = %e, "the engine's event feed broke; following again");
                            break;
                        }
                    };
                    if m.typ != Some(EventMessageTypeEnum::CONTAINER) {
                        continue;
                    }
                    let Some(actor) = m.actor else { continue };
                    let Some(id) = actor.id else { continue };
                    let id = ContainerId(id);
                    match m.action.as_deref() {
                        Some("oom") => {
                            let _ = tx.send(Event::OutOfMemory { id });
                        }
                        Some("die") => {
                            let code = actor
                                .attributes
                                .as_ref()
                                .and_then(|a| a.get("exitCode"))
                                .and_then(|c| c.parse::<i64>().ok())
                                .unwrap_or(-1);
                            let _ = tx.send(Event::Exited { id, code });
                        }
                        _ => {}
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }
}

/// `name:tag` as the engine wants them apart; a reference without a tag means `latest`. A port in the registry's
/// host is not a tag. A reference pinned by digest (`name:tag@sha256:...`) is handed over whole, with no tag: the
/// digest is the name.
fn name_and_tag(image: &ImageRef) -> (String, Option<String>) {
    let r = &image.0;
    if r.contains('@') {
        return (r.clone(), None);
    }
    let after_slash = r.rfind('/').map(|i| i + 1).unwrap_or(0);
    match r[after_slash..].rfind(':') {
        Some(i) => (
            r[..after_slash + i].to_string(),
            Some(r[after_slash + i + 1..].to_string()),
        ),
        None => (r.clone(), Some("latest".into())),
    }
}

fn image_error(image: &ImageRef, message: &str) -> RuntimeError {
    let m = message.to_ascii_lowercase();
    if m.contains("not found") || m.contains("manifest unknown") || m.contains("pull access denied") {
        RuntimeError::ImageNotFound(image.0.clone())
    } else {
        RuntimeError::Engine(message.into())
    }
}

#[async_trait]
impl Runtime for DockerRuntime {
    async fn pull(&self, image: &ImageRef, progress: Progress) -> Result<(), RuntimeError> {
        let (name, tag) = name_and_tag(image);
        let mut options = CreateImageOptionsBuilder::new().from_image(&name);
        if let Some(tag) = &tag {
            options = options.tag(tag);
        }
        let mut stream = self.docker.create_image(Some(options.build()), None, None);
        // Progress across every layer, not per layer: the engine reports each layer's own bytes.
        let mut layers: HashMap<String, (i64, i64)> = HashMap::new();
        let mut last: Option<u8> = None;
        while let Some(next) = stream.next().await {
            let info = next.map_err(|e| image_error(image, &e.to_string()))?;
            if let Some(err) = info.error_detail.and_then(|d| d.message) {
                return Err(image_error(image, &err));
            }
            if let (Some(layer), Some(p)) = (info.id, info.progress_detail) {
                if let (Some(c), Some(t)) = (p.current, p.total) {
                    if t > 0 {
                        layers.insert(layer, (c.clamp(0, t), t));
                    }
                }
            }
            let (done, total) = layers.values().fold((0i64, 0i64), |(d, t), (c, lt)| (d + c, t + lt));
            if let Some(share) = (done * 100).checked_div(total) {
                let pct = Some(share.clamp(0, 100) as u8);
                if pct != last {
                    last = pct;
                    progress(pct);
                }
            }
        }
        Ok(())
    }

    async fn holds(&self, image: &ImageRef) -> Result<bool, RuntimeError> {
        match self.docker.inspect_image(&image.0).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(false),
            Err(e) => Err(RuntimeError::Engine(format!(
                "the container engine cannot say whether it holds {}: {e}",
                image.0
            ))),
        }
    }

    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError> {
        let mut device_requests = Vec::new();
        for d in &spec.devices {
            if !d.0.starts_with("GPU-") {
                return Err(RuntimeError::DeviceUnavailable(format!(
                    "{}: this adapter hands over NVIDIA devices (GPU-...) only",
                    d.0
                )));
            }
            device_requests.push(DeviceRequest {
                driver: Some("nvidia".into()),
                device_ids: Some(vec![d.0.clone()]),
                capabilities: Some(vec![vec!["gpu".into()]]),
                ..Default::default()
            });
        }
        let port_bindings: HashMap<String, Option<Vec<PortBinding>>> = spec
            .ports
            .iter()
            .map(|p| {
                (
                    format!("{p}/tcp"),
                    Some(vec![PortBinding {
                        host_ip: Some(self.bind_ip.clone()),
                        host_port: Some(String::new()),
                    }]),
                )
            })
            .collect();
        let confinement = &spec.confinement;
        let body = ContainerCreateBody {
            image: Some(spec.image.0.clone()),
            cmd: (!spec.args.is_empty()).then(|| spec.args.clone()),
            env: Some(spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect()),
            exposed_ports: Some(spec.ports.iter().map(|p| format!("{p}/tcp")).collect()),
            labels: Some(HashMap::from([(LABEL.to_string(), "1".to_string())])),
            host_config: Some(HostConfig {
                auto_remove: Some(true),
                port_bindings: Some(port_bindings),
                device_requests: (!device_requests.is_empty()).then_some(device_requests),
                cap_drop: confinement.drop_capabilities.then(|| vec!["ALL".into()]),
                security_opt: confinement.no_new_privileges.then(|| vec!["no-new-privileges".into()]),
                readonly_rootfs: Some(confinement.read_only_root),
                tmpfs: confinement
                    .read_only_root
                    .then(|| HashMap::from([("/tmp".to_string(), "rw,nosuid,nodev,size=1g".to_string())])),
                pids_limit: confinement.pids.map(|p| p as i64),
                // One ceiling for memory and swap together: a ceiling that swap can exceed is none.
                memory: confinement.memory_bytes.map(|m| m as i64),
                memory_swap: confinement.memory_bytes.map(|m| m as i64),
                network_mode: match &confinement.network {
                    Network::None => Some("none".into()),
                    Network::Default => None,
                },
                // An init as PID 1 reaps and forwards signals, so a stop reaches an image that did not expect to be it.
                init: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let created = self.docker.create_container(None, body).await.map_err(|e| match e {
            bollard::errors::Error::DockerResponseServerError { status_code: 404, .. } => {
                RuntimeError::ImageNotFound(spec.image.0.clone())
            }
            other => RuntimeError::Engine(other.to_string()),
        })?;
        let id = ContainerId(created.id);
        if let Err(e) = self.docker.start_container(&id.0, None).await {
            let _ = self
                .docker
                .remove_container(&id.0, Some(RemoveContainerOptionsBuilder::new().force(true).build()))
                .await;
            return Err(RuntimeError::Engine(format!("the container did not start: {e}")));
        }
        let mut ports = Vec::new();
        // Only a container that publishes ports is inspected for them: a job may have exited and been removed by
        // the time the answer comes, and that is its outcome, not a failure to start.
        if !spec.ports.is_empty() {
            let inspected = match self.docker.inspect_container(&id.0, None).await {
                Ok(i) => i,
                Err(e) => {
                    let _ = self.stop(&id).await;
                    return Err(RuntimeError::Engine(format!(
                        "the started container cannot be inspected and was stopped: {e}"
                    )));
                }
            };
            let map = inspected.network_settings.and_then(|n| n.ports).unwrap_or_default();
            for p in &spec.ports {
                let host = map
                    .get(&format!("{p}/tcp"))
                    .and_then(|b| b.as_ref())
                    .and_then(|b| b.iter().find_map(|pb| pb.host_port.as_deref()?.parse::<u16>().ok()));
                if let Some(host) = host {
                    ports.push(Published { container: *p, host });
                }
            }
        }
        let _ = self.tx.send(Event::Started {
            id: id.clone(),
            ports: ports.clone(),
        });
        Ok(Started { id, ports })
    }

    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError> {
        match self
            .docker
            .stop_container(&id.0, Some(StopContainerOptionsBuilder::new().t(10).build()))
            .await
        {
            Ok(()) => {}
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                return Err(RuntimeError::NoSuchContainer(id.0.clone()))
            }
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => {}
            Err(e) => return Err(RuntimeError::Engine(e.to_string())),
        }
        // The engine removes it on exit; a container that was already stopped is removed here.
        match self
            .docker
            .remove_container(&id.0, Some(RemoveContainerOptionsBuilder::new().force(true).build()))
            .await
        {
            Ok(()) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => Ok(()),
            Err(e) => Err(RuntimeError::Engine(e.to_string())),
        }
    }

    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError> {
        let filters = HashMap::from([("label", vec![LABEL])]);
        let list = self
            .docker
            .list_containers(Some(ListContainersOptionsBuilder::new().filters(&filters).build()))
            .await
            .map_err(|e| RuntimeError::Unreachable(e.to_string()))?;
        Ok(list.into_iter().filter_map(|c| c.id).map(ContainerId).collect())
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}
