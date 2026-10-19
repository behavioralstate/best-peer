//! The container runtime abstraction best-peer owns.
//!
//! A peer runs workloads it did not write, in containers an engine it did not write manages. Everything the door
//! says about a workload (pulled, started, ready, out of memory, finished, failed) is an [`Event`] from this trait's
//! stream, so the door's lifecycle is written once against [`Runtime`] and tested against [`Fake`]. An engine
//! adapter (Docker or containerd through bollard, a microVM later) is a separate crate that implements [`Runtime`]
//! and is proven on a host by hand, never unit-tested.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use best_peer_gpu::DeviceId;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// An image reference as the engine understands it (`ollama/ollama:0.6`, `vllm/vllm-openai:v0.8`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageRef(pub String);

/// The engine's id for a running container.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContainerId(pub String);

/// What to run. Devices are handed over by [`DeviceId`]; how the engine exposes them (the NVIDIA toolkit's
/// `--gpus device=<uuid>`, `/dev/kfd` and `/dev/dri` for ROCm) is the adapter's business.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub image: ImageRef,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub devices: Vec<DeviceId>,
    /// Container ports to publish; the adapter reports the host side in [`Event::Started`].
    pub ports: Vec<u16>,
    /// What the container may not do on the host, and how much of the host it may take.
    pub confinement: Confinement,
}

/// How a container is confined: what it may not do on the host, and how much of the host it may take. A peer runs
/// code it did not write, so the default is a closed box, what a job gets; an engine serving a model gets
/// [`Confinement::serving`]. The adapter maps each to the engine's own words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confinement {
    /// No Linux capability: nothing inside may mount, trace, change ownership or bind a low port.
    pub drop_capabilities: bool,
    /// No setuid binary or file capability gains a privilege the container did not start with.
    pub no_new_privileges: bool,
    /// The image's filesystem is read-only, with a private `/tmp` of at most 1 GiB, counted in its memory.
    pub read_only_root: bool,
    /// The most tasks the container may hold, every thread counted as one; none for the engine's own default.
    pub pids: Option<u64>,
    /// The most host memory the container may hold, swap counted in; none for no ceiling. Not device memory.
    pub memory_bytes: Option<u64>,
    pub network: Network,
}

impl Confinement {
    /// What an engine serving a model gets: the same rules on capabilities and privileges, but its network, which
    /// it needs to pull models, and a writable filesystem, which it keeps them on, with a ceiling on processes alone.
    pub fn serving() -> Self {
        Self {
            drop_capabilities: true,
            no_new_privileges: true,
            read_only_root: false,
            pids: Some(4096),
            memory_bytes: None,
            network: Network::Default,
        }
    }
}

/// The closed box a job gets: no network, no capabilities, no new privileges, a read-only root, 4096 tasks and
/// 4 GiB of host memory at most.
impl Default for Confinement {
    fn default() -> Self {
        Self {
            drop_capabilities: true,
            no_new_privileges: true,
            read_only_root: true,
            pids: Some(4096),
            memory_bytes: Some(4 << 30),
            network: Network::None,
        }
    }
}

/// Where a container's network goes: nowhere, what a job gets, or the container engine's own default, what an
/// engine gets to pull its models.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    None,
    Default,
}

/// A published port: the container's and the host's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    pub container: u16,
    pub host: u16,
}

/// What `start` answers: the container's id and the ports the engine published for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    pub id: ContainerId,
    pub ports: Vec<Published>,
}

/// What a long call tells while it runs: progress in percent, where the engine says. Called in order, before the
/// call returns, so the caller tells each step as a fact before the outcome.
pub type Progress = Arc<dyn Fn(Option<u8>) + Send + Sync>;

/// Every fact the engine tells on its own, after a call returned. The door turns these into BEST events on its
/// stream, correlated to the command that started the container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    Started { id: ContainerId, ports: Vec<Published> },
    Exited { id: ContainerId, code: i64 },
    OutOfMemory { id: ContainerId },
    Failed { id: ContainerId, reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("image not found: {0}")]
    ImageNotFound(String),
    #[error("no such container: {0}")]
    NoSuchContainer(String),
    #[error("device {0} is not available to this engine")]
    DeviceUnavailable(String),
    #[error("the engine is unreachable: {0}")]
    Unreachable(String),
    #[error("the engine failed: {0}")]
    Engine(String),
}

/// What the door needs from a container engine.
#[async_trait]
pub trait Runtime: Send + Sync {
    /// Makes the image present, telling `progress` as it goes.
    async fn pull(&self, image: &ImageRef, progress: Progress) -> Result<(), RuntimeError>;
    /// Creates and starts a container, answering its id and the published ports; emits `Started` too.
    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError>;
    /// Stops and removes a container; emits `Exited`.
    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError>;
    /// The containers this engine runs for the peer.
    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError>;
    /// Every event from now on. A slow subscriber may lag; the door rebuilds from its own stream, not from this.
    fn events(&self) -> broadcast::Receiver<Event>;
    /// Whether this engine runs a job: an image run once to its exit. One that cannot (an engine already installed
    /// on the host, outside any container) says so here, and the door refuses the job at ingest with the fix rather
    /// than accepting it and failing it later.
    fn runs_jobs(&self) -> bool {
        true
    }
}

/// An in-memory [`Runtime`] for tests: images the engine already holds, images a registry would serve, containers
/// that start at once, and the events a real engine would emit, in order. Like a real engine, it starts only an image
/// it holds locally: a `pull` moves an image from the registry to the engine, and a door that skips the pull fails
/// here as it would there. A test can make a container fail or run out of memory.
pub struct Fake {
    local: Mutex<Vec<ImageRef>>,
    registry: Mutex<Vec<ImageRef>>,
    /// A registry that serves every image, for a peer run on the fakes.
    open_registry: bool,
    /// Whether this engine runs jobs; an engine that only serves deployments says no.
    jobs: bool,
    /// Host ports chosen for container ports, over the fake's own numbering: where a test listens itself.
    published: BTreeMap<u16, u16>,
    /// What a pull reports as it goes; a real engine reports every percent, often more.
    steps: Vec<Option<u8>>,
    containers: Mutex<BTreeMap<ContainerId, Spec>>,
    devices: Vec<DeviceId>,
    next: Mutex<u32>,
    tx: broadcast::Sender<Event>,
}

impl Fake {
    /// A fake whose engine can see `devices` and already holds `local` images.
    pub fn new(devices: Vec<DeviceId>, local: Vec<ImageRef>) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            local: Mutex::new(local),
            registry: Mutex::new(Vec::new()),
            open_registry: false,
            jobs: true,
            published: BTreeMap::new(),
            steps: vec![Some(50)],
            containers: Mutex::new(BTreeMap::new()),
            devices,
            next: Mutex::new(0),
            tx,
        }
    }

    /// Declares an image the registry serves, so a `pull` of it succeeds; it is not local until pulled.
    pub fn registry_has(&self, image: ImageRef) {
        self.registry.lock().unwrap().push(image);
    }

    /// A registry that serves every image: the peer's fake mode, where the whole surface works and nothing runs.
    pub fn with_open_registry(mut self) -> Self {
        self.open_registry = true;
        self
    }

    /// An engine that runs no job, as an engine installed on the host outside any container: deploys only.
    pub fn without_jobs(mut self) -> Self {
        self.jobs = false;
        self
    }

    /// A fake whose pull reports every percent from 0 to 100, as a real engine does.
    pub fn reporting_every_percent(mut self) -> Self {
        self.steps = (0..=100).map(Some).collect();
        self
    }

    /// Publishes container port `container` at host port `host` instead of the fake's own numbering, for a test
    /// that listens there itself and sees what reaches the engine.
    pub fn publishes(mut self, container: u16, host: u16) -> Self {
        self.published.insert(container, host);
        self
    }

    /// Drives a running container out of memory, as the engine would report it.
    pub fn out_of_memory(&self, id: &ContainerId) -> Result<(), RuntimeError> {
        self.containers
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        let _ = self.tx.send(Event::OutOfMemory { id: id.clone() });
        Ok(())
    }

    /// Makes a running container fail, as the engine would report it.
    pub fn fail(&self, id: &ContainerId, reason: &str) -> Result<(), RuntimeError> {
        self.containers
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        let _ = self.tx.send(Event::Failed {
            id: id.clone(),
            reason: reason.to_string(),
        });
        Ok(())
    }

    pub fn spec_of(&self, id: &ContainerId) -> Option<Spec> {
        self.containers.lock().unwrap().get(id).cloned()
    }
}

#[async_trait]
impl Runtime for Fake {
    async fn pull(&self, image: &ImageRef, progress: Progress) -> Result<(), RuntimeError> {
        if !self.open_registry && !self.registry.lock().unwrap().contains(image) {
            return Err(RuntimeError::ImageNotFound(image.0.clone()));
        }
        for &step in &self.steps {
            progress(step);
        }
        let mut local = self.local.lock().unwrap();
        if !local.contains(image) {
            local.push(image.clone());
        }
        Ok(())
    }

    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError> {
        if !self.local.lock().unwrap().contains(&spec.image) {
            return Err(RuntimeError::ImageNotFound(spec.image.0.clone()));
        }
        if let Some(d) = spec.devices.iter().find(|d| !self.devices.contains(d)) {
            return Err(RuntimeError::DeviceUnavailable(d.0.clone()));
        }
        let n = {
            let mut next = self.next.lock().unwrap();
            *next += 1;
            *next
        };
        let id = ContainerId(format!("fake-{n}"));
        let ports = spec
            .ports
            .iter()
            .map(|&p| match self.published.get(&p) {
                Some(&host) => Ok(Published { container: p, host }),
                None => p
                    .checked_add(30000)
                    .map(|host| Published { container: p, host })
                    .ok_or_else(|| RuntimeError::Engine(format!("no host port for container port {p}"))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.containers.lock().unwrap().insert(id.clone(), spec);
        let _ = self.tx.send(Event::Started {
            id: id.clone(),
            ports: ports.clone(),
        });
        Ok(Started { id, ports })
    }

    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError> {
        self.containers
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        let _ = self.tx.send(Event::Exited {
            id: id.clone(),
            code: 0,
        });
        Ok(())
    }

    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError> {
        Ok(self.containers.lock().unwrap().keys().cloned().collect())
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    fn runs_jobs(&self) -> bool {
        self.jobs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> Fake {
        Fake::new(vec!["gpu-0".into()], vec![ImageRef("ollama/ollama:0.6".into())])
    }

    fn spec(image: &str, device: &str) -> Spec {
        Spec {
            image: ImageRef(image.into()),
            args: vec![],
            env: vec![],
            devices: vec![device.into()],
            ports: vec![11434],
            confinement: Confinement::default(),
        }
    }

    #[tokio::test]
    async fn an_image_the_engine_does_not_hold_cannot_start_until_it_is_pulled() {
        let rt = Fake::new(vec!["gpu-0".into()], vec![]);
        let image = ImageRef("vllm/vllm-openai:v0.8".into());
        rt.registry_has(image.clone());
        let err = rt.start(spec("vllm/vllm-openai:v0.8", "gpu-0")).await.unwrap_err();
        assert!(matches!(err, RuntimeError::ImageNotFound(ref i) if i == "vllm/vllm-openai:v0.8"));
        rt.pull(&image, Arc::new(|_| {})).await.unwrap();
        rt.start(spec("vllm/vllm-openai:v0.8", "gpu-0")).await.unwrap();
    }

    #[tokio::test]
    async fn a_container_port_with_no_host_port_is_refused_not_wrapped() {
        let rt = fake();
        let mut s = spec("ollama/ollama:0.6", "gpu-0");
        s.ports = vec![65000];
        assert!(matches!(rt.start(s).await.unwrap_err(), RuntimeError::Engine(_)));
    }

    #[tokio::test]
    async fn the_lifecycle_is_told_as_events_in_order() {
        let rt = fake();
        let mut events = rt.events();
        let image = ImageRef("ollama/ollama:0.6".into());
        rt.registry_has(image.clone());
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        rt.pull(&image, Arc::new(move |pct| sink.lock().unwrap().push(pct)))
            .await
            .unwrap();
        assert_eq!(
            *told.lock().unwrap(),
            vec![Some(50)],
            "progress is told to the caller, in order"
        );
        let started = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap();
        let id = started.id.clone();
        assert_eq!(
            started.ports,
            vec![Published {
                container: 11434,
                host: 41434
            }],
            "the answer carries the published ports"
        );
        rt.stop(&id).await.unwrap();
        match events.recv().await.unwrap() {
            Event::Started { id: started, ports } => {
                assert_eq!(started, id);
                assert_eq!(
                    ports,
                    vec![Published {
                        container: 11434,
                        host: 41434
                    }]
                );
            }
            other => panic!("expected Started, got {other:?}"),
        }
        assert!(matches!(events.recv().await.unwrap(), Event::Exited { code: 0, .. }));
        assert!(rt.running().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_image_the_registry_lacks_is_refused_by_name() {
        let rt = fake();
        let err = rt
            .pull(&ImageRef("nobody/nothing:1".into()), Arc::new(|_| {}))
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::ImageNotFound(ref i) if i == "nobody/nothing:1"));
        rt.registry_has(ImageRef("nobody/nothing:1".into()));
        rt.pull(&ImageRef("nobody/nothing:1".into()), Arc::new(|_| {}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_device_the_engine_cannot_see_is_refused_by_id() {
        let rt = fake();
        let err = rt.start(spec("ollama/ollama:0.6", "gpu-9")).await.unwrap_err();
        assert!(matches!(err, RuntimeError::DeviceUnavailable(ref d) if d == "gpu-9"));
    }

    #[tokio::test]
    async fn out_of_memory_and_failure_are_events_and_end_the_container() {
        let rt = fake();
        let mut events = rt.events();
        let a = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        let b = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        rt.out_of_memory(&a).unwrap();
        rt.fail(&b, "exit 137").unwrap();
        let _ = events.recv().await.unwrap();
        let _ = events.recv().await.unwrap();
        assert!(matches!(events.recv().await.unwrap(), Event::OutOfMemory { id } if id == a));
        assert!(
            matches!(events.recv().await.unwrap(), Event::Failed { id, reason } if id == b && reason == "exit 137")
        );
        assert!(rt.running().await.unwrap().is_empty());
        assert!(matches!(
            rt.stop(&a).await.unwrap_err(),
            RuntimeError::NoSuchContainer(_)
        ));
    }
}
