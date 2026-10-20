//! [`Runtime`] over the Docker Engine API through bollard. Every container this adapter creates carries the label
//! `best-peer`, so `running` and the event feed see the peer's containers and nothing else. A device is handed over
//! by the NVIDIA container toolkit when its id is an NVML UUID (`GPU-...`); other accelerators wait for their own
//! adapter. A mount is a bind the engine refuses when its source is not there. A container is confined as its spec
//! says, in the engine's own words: capabilities dropped, no new privileges, a read-only root with a private `/tmp`,
//! ceilings on processes and on memory with swap counted in, and its network. A container that exits is removed by
//! this adapter once it has read the last lines the container wrote, which the exit then carries; one whose exit was
//! not heard (the peer was down, or the event feed broke) is removed by a sweep, every minute and after the feed
//! reconnects, once this adapter has seen it exited for a minute, so a peer that shares the engine has read its own
//! first. A container goes with its anonymous volumes, as the engine's own removal on exit took them. Thin; proven on a host by hand. Only the share of a pull, which is arithmetic over what the engine
//! reports, is unit-tested.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use best_peer_runtime::{
    ContainerId, Event, ImageRef, Isolation, Network, Progress, Published, Runtime, RuntimeError, Spec, Started,
};
use bollard::models::{
    ContainerCreateBody, DeviceRequest, EventMessageTypeEnum, HostConfig, Mount, MountType, PortBinding,
};
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
    /// When the sweep first saw each of the peer's containers exited, by this host's clock.
    exited: Arc<Mutex<Exited>>,
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
            exited: Arc::new(Mutex::new(Exited::default())),
            bind_ip: bind_ip.into(),
            tx,
        };
        sweep(&me.docker, &me.exited).await;
        me.follow();
        let (docker, exited) = (me.docker.clone(), me.exited.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                sweep(&docker, &exited).await;
            }
        });
        Ok(me)
    }

    fn follow(&self) {
        let docker = self.docker.clone();
        let exited = self.exited.clone();
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
                            let last_words = last_words(&docker, &id.0).await;
                            let _ = docker
                                .remove_container(
                                    &id.0,
                                    Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build()),
                                )
                                .await;
                            let _ = tx.send(Event::Exited { id, code, last_words });
                        }
                        _ => {}
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // The exits told while the feed was down were not heard: what they left is swept, beside the feed
                // followed again at once, so no exit is missed while the sweep runs.
                let (d, e) = (docker.clone(), exited.clone());
                tokio::spawn(async move { sweep(&d, &e).await });
            }
        });
    }
}

/// How often the containers whose exit was not heard are looked for, and how long one must have been exited before
/// it is removed: the peer that heard its exit has read its last words and removed it well before then.
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// When each of the peer's exited containers was first seen exited, by this host's clock: the engine's own times may
/// come from another host's clock.
#[derive(Default)]
struct Exited {
    since: HashMap<String, std::time::Instant>,
}

impl Exited {
    /// Takes the containers exited `now`: those seen exited for `SWEEP_EVERY` or more are due for removal; those
    /// seen for the first time are noted; those no longer exited (removed by whoever heard their exit) are forgotten.
    fn due(&mut self, exited_now: &[String], now: std::time::Instant) -> Vec<String> {
        self.since.retain(|id, _| exited_now.contains(id));
        let mut due = Vec::new();
        for id in exited_now {
            let first = *self.since.entry(id.clone()).or_insert(now);
            if now.duration_since(first) >= SWEEP_EVERY {
                due.push(id.clone());
            }
        }
        due
    }

    fn removed(&mut self, id: &str) {
        self.since.remove(id);
    }
}

/// Removes the peer's containers this adapter has seen exited for [`SWEEP_EVERY`] or more: one whose exit nobody
/// heard, or that another peer on this engine did not remove. A removal that fails is logged and tried at the next
/// sweep; one already gone is done.
async fn sweep(docker: &Docker, exited: &Mutex<Exited>) {
    let filters = HashMap::from([("label", vec![LABEL]), ("status", vec!["exited", "dead"])]);
    let Ok(list) = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new().all(true).filters(&filters).build(),
        ))
        .await
    else {
        return;
    };
    let ids: Vec<String> = list.into_iter().filter_map(|c| c.id).collect();
    let due = exited.lock().unwrap().due(&ids, std::time::Instant::now());
    for id in due {
        match docker
            .remove_container(
                &id,
                Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build()),
            )
            .await
        {
            Ok(()) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                exited.lock().unwrap().removed(&id)
            }
            Err(e) => {
                tracing::warn!(container = %id, error = %e, "an exited container could not be removed; trying again at the next sweep")
            }
        }
    }
}

/// The last lines a container wrote, out and error together, at most a screen of them: what an engine that ended
/// said about why. None where the engine kept none.
async fn last_words(docker: &Docker, id: &str) -> Option<String> {
    let options = bollard::query_parameters::LogsOptionsBuilder::new()
        .stdout(true)
        .stderr(true)
        .tail("20")
        .build();
    let mut logs = docker.logs(id, Some(options));
    let mut text = String::new();
    while let Some(Ok(chunk)) = logs.next().await {
        text.push_str(&String::from_utf8_lossy(&chunk.into_bytes()));
    }
    let text = text.trim();
    // A screen of text at most, its end kept: the last line is the one that says why.
    let start = text.len().saturating_sub(2000);
    let start = (start..=text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    (!text.is_empty()).then(|| text[start..].to_string())
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

/// The share of a pull across every layer, not per layer. The engine reports each layer twice over its own bytes:
/// downloading it, then extracting it, each from 0 to the layer's size. So a layer counts half when downloaded and
/// whole when extracted, and the start of its extraction is not read as a fall back to nothing.
#[derive(Default)]
struct Layers {
    /// Each layer's size, and the bytes it has downloaded and extracted.
    of: HashMap<String, (i64, i64, i64)>,
}

impl Layers {
    /// One line of the engine's pull stream about `layer`: its status, and the bytes it reports where it says.
    fn report(&mut self, layer: &str, status: &str, current: Option<i64>, total: Option<i64>) {
        let entry = self.of.entry(layer.to_string()).or_insert((0, 0, 0));
        if let Some(t) = total.filter(|t| *t > 0) {
            entry.0 = entry.0.max(t);
        }
        let size = entry.0;
        let at = current.unwrap_or(0).clamp(0, size);
        match status {
            "Downloading" => entry.1 = entry.1.max(at),
            "Verifying Checksum" | "Download complete" => entry.1 = size,
            "Extracting" => (entry.1, entry.2) = (size, entry.2.max(at)),
            "Pull complete" => (entry.1, entry.2) = (size, size),
            _ => {}
        }
    }

    /// The share done, in percent, once any layer has said its size.
    fn share(&self) -> Option<u8> {
        let (done, whole) = self
            .of
            .values()
            .fold((0i64, 0i64), |(d, w), (size, down, out)| (d + down + out, w + 2 * size));
        (done * 100).checked_div(whole).map(|p| p.clamp(0, 100) as u8)
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
        let mut layers = Layers::default();
        let mut last: Option<u8> = None;
        while let Some(next) = stream.next().await {
            let info = next.map_err(|e| image_error(image, &e.to_string()))?;
            if let Some(err) = info.error_detail.and_then(|d| d.message) {
                return Err(image_error(image, &err));
            }
            if let Some(layer) = info.id {
                let (current, total) = info.progress_detail.map(|p| (p.current, p.total)).unwrap_or_default();
                layers.report(&layer, info.status.as_deref().unwrap_or_default(), current, total);
            }
            let pct = layers.share();
            if pct.is_some() && pct != last {
                last = pct;
                progress(pct);
            }
        }
        Ok(())
    }

    /// A container, or a user namespace when the engine runs rootless or remaps its users, as its own `info` says.
    /// An engine that does not answer is still the one the peer confines every container in.
    async fn isolation(&self) -> Isolation {
        match self.docker.info().await {
            Ok(info) => Isolation::of_container_engine(&info.security_options.unwrap_or_default()),
            Err(e) => {
                tracing::warn!(error = %e, "the container engine did not say whether it runs rootless; told as a container");
                Isolation::Container
            }
        }
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
                // Not removed by the engine on exit: the adapter reads its last lines first, then removes it.
                auto_remove: Some(false),
                port_bindings: Some(port_bindings),
                device_requests: (!device_requests.is_empty()).then_some(device_requests),
                // A bind as a mount, not a `-v` string: the engine refuses a source that is not there instead of
                // making an empty one, and reads the path as its own host's.
                mounts: (!spec.mounts.is_empty()).then(|| {
                    spec.mounts
                        .iter()
                        .map(|m| Mount {
                            target: Some(m.container.clone()),
                            source: Some(m.host.clone()),
                            typ: Some(MountType::BIND),
                            read_only: Some(m.read_only),
                            ..Default::default()
                        })
                        .collect()
                }),
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
            other => {
                let said = other.to_string();
                match spec.mounts.iter().find(|m| said.contains(&m.host)) {
                    Some(m) => {
                        tracing::warn!(host = %m.host, container = %m.container, error = %said, "the container engine cannot mount a directory of this host");
                        RuntimeError::Engine(format!(
                            "the container engine cannot mount the operator's directory at {}: whoever runs the peer reads why in its log",
                            m.container
                        ))
                    }
                    None => RuntimeError::Engine(said),
                }
            }
        })?;
        let id = ContainerId(created.id);
        if let Err(e) = self.docker.start_container(&id.0, None).await {
            let _ = self
                .docker
                .remove_container(
                    &id.0,
                    Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build()),
                )
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
        // The adapter removes it when its exit is heard; one already stopped, or not heard, is removed here.
        match self
            .docker
            .remove_container(
                &id.0,
                Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build()),
            )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_layer_extracted_after_it_downloaded_moves_the_share_on_and_never_back() {
        let mut l = Layers::default();
        l.report("a", "Pulling fs layer", None, None);
        l.report("b", "Pulling fs layer", None, None);
        assert_eq!(l.share(), None, "no size known yet");
        l.report("a", "Downloading", Some(50), Some(100));
        l.report("b", "Downloading", Some(100), Some(100));
        l.report("b", "Download complete", None, None);
        assert_eq!(l.share(), Some(37), "a half downloaded and b downloaded: 150 of 400");
        l.report("a", "Downloading", Some(100), Some(100));
        l.report("a", "Download complete", None, None);
        assert_eq!(l.share(), Some(50), "both downloaded, nothing extracted");
        // The engine starts extracting a at 0 of its size: that is progress past the download, not a fall to 0.
        l.report("a", "Extracting", Some(0), Some(100));
        assert_eq!(l.share(), Some(50));
        l.report("a", "Extracting", Some(100), Some(100));
        l.report("a", "Pull complete", None, None);
        l.report("b", "Extracting", Some(40), Some(100));
        assert_eq!(l.share(), Some(85));
        l.report("b", "Pull complete", None, None);
        assert_eq!(l.share(), Some(100));
    }

    #[test]
    fn a_container_is_swept_once_this_adapter_has_seen_it_exited_for_a_minute_and_forgotten_once_gone() {
        let t0 = std::time::Instant::now();
        let mut e = Exited::default();
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(e.due(&ids(&["a"]), t0).is_empty(), "first seen: noted, not removed");
        assert!(e.due(&ids(&["a", "b"]), t0 + Duration::from_secs(59)).is_empty());
        assert_eq!(
            e.due(&ids(&["a", "b"]), t0 + SWEEP_EVERY),
            ids(&["a"]),
            "a minute on, a is due; b is not yet"
        );
        // a was removed; b was removed by whoever heard its exit: neither is remembered.
        e.removed("a");
        assert!(e.due(&ids(&[]), t0 + Duration::from_secs(120)).is_empty());
        assert!(e.since.is_empty());
        // Seen again later, a container is counted from then.
        assert!(e.due(&ids(&["b"]), t0 + Duration::from_secs(130)).is_empty());
    }

    #[test]
    fn a_layer_the_engine_already_holds_counts_for_nothing_and_takes_nothing_away() {
        let mut l = Layers::default();
        l.report("held", "Already exists", None, None);
        l.report("new", "Downloading", Some(10), Some(100));
        assert_eq!(l.share(), Some(5));
    }
}
