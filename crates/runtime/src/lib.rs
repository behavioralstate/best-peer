//! The container runtime abstraction best-peer owns.
//!
//! A peer runs workloads it did not write, in containers an engine it did not write manages. Everything the door
//! says about a workload (pulled, started, ready, out of memory, finished, failed) is an [`Event`] from this trait's
//! stream, so the door's lifecycle is written once against [`Runtime`] and tested against [`Fake`]. An engine
//! adapter (Docker or containerd through bollard, a microVM later) is a separate crate that implements [`Runtime`]
//! and is proven on a host by hand, never unit-tested.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use best_peer_gpu::DeviceId;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// An image reference as the engine understands it (`ollama/ollama:0.6`, `vllm/vllm-openai:v0.8`), or one pinned by
/// digest (`nvidia/cuda@sha256:...`), which names one image whatever the registry's tags say later.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageRef(pub String);

impl ImageRef {
    /// The repository it names, without its tag or digest: a port in the registry's host is not a tag.
    pub fn repository(&self) -> &str {
        let r = self.0.split('@').next().unwrap_or_default();
        let after_slash = r.rfind('/').map_or(0, |i| i + 1);
        match r[after_slash..].rfind(':') {
            Some(i) => &r[..after_slash + i],
            None => r,
        }
    }

    /// [`ImageRef::repository`] as the engine's default registry spells it in full, so two spellings of one
    /// repository compare equal: `nvidia/cuda`, `docker.io/nvidia/cuda` and `index.docker.io/nvidia/cuda` are all
    /// `docker.io/nvidia/cuda`, and `busybox` is `docker.io/library/busybox`. A first part with a dot or a port, or
    /// `localhost`, is a registry of its own.
    pub fn canonical_repository(&self) -> String {
        let repo = self.repository();
        let (registry, path) = match repo.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => (first, rest),
            _ => ("docker.io", repo),
        };
        let registry = if registry == "index.docker.io" {
            "docker.io"
        } else {
            registry
        };
        match registry == "docker.io" && !path.contains('/') {
            true => format!("docker.io/library/{path}"),
            false => format!("{registry}/{path}"),
        }
    }

    /// Its digest, when it is pinned by one.
    pub fn digest(&self) -> Option<&str> {
        self.0.split_once('@').map(|(_, d)| d)
    }

    /// The same repository pinned by `digest`: what pulls, runs and removes that one image and never a tag.
    pub fn pinned(&self, digest: &str) -> ImageRef {
        ImageRef(format!("{}@{digest}", self.repository()))
    }
}

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
    /// Directories of the container engine's host the container sees, where the operator shares one.
    pub mounts: Vec<Mount>,
    /// What the container may not do on the host, and how much of the host it may take.
    pub confinement: Confinement,
    /// The caller's own name for the container, carried as a label by an adapter that finds containers by name
    /// ([`Runtime::named`]) and ignored by one that cannot; none means no label.
    pub name: Option<String>,
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
    /// The most of the host's cores the container may keep busy at once, in whole cores; none for no ceiling.
    #[serde(default)]
    pub cpus: Option<u32>,
    /// The most files the container may hold open at once; none for the engine's own default.
    #[serde(default)]
    pub open_files: Option<u64>,
    /// The user every process of the container runs as, whatever its image names; none for the image's own, which is
    /// root for most images.
    #[serde(default)]
    pub user: Option<User>,
}

/// A user and its group by number, never by name: a name is resolved by the image's own files, which may make it
/// root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

impl User {
    /// `nobody` and `nogroup`: unprivileged, named in the passwd file of most images, so a program that looks its user
    /// up finds one, and inside the 65536 ids a remapped or rootless engine maps.
    pub const NOBODY: User = User { uid: 65534, gid: 65534 };
}

impl Confinement {
    /// What an engine serving a model gets: the same rules on capabilities and privileges, but its network, which
    /// it needs to pull models, and a writable filesystem, which it keeps them on, with a ceiling on processes alone,
    /// run as its image's own user, which keeps its models where that user's home is.
    pub fn serving() -> Self {
        Self {
            drop_capabilities: true,
            no_new_privileges: true,
            read_only_root: false,
            pids: Some(4096),
            memory_bytes: None,
            network: Network::Default,
            cpus: None,
            open_files: None,
            user: None,
        }
    }
}

/// The closed box a job gets: no network, no capabilities, no new privileges, a read-only root, 4096 tasks, 4 GiB of
/// host memory, half the host's cores and 65536 open files at most, run as [`User::NOBODY`] whatever its image names.
impl Default for Confinement {
    fn default() -> Self {
        Self {
            drop_capabilities: true,
            no_new_privileges: true,
            read_only_root: true,
            pids: Some(4096),
            memory_bytes: Some(4 << 30),
            network: Network::None,
            cpus: Some(half_the_cores()),
            open_files: Some(65536),
            user: Some(User::NOBODY),
        }
    }
}

/// Half the cores this host lets the process use, one at least: a job never takes the whole host.
fn half_the_cores() -> u32 {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    (cores / 2).max(1)
}

/// Where a container's network goes: nowhere, what a job gets, or the container engine's own default, what an
/// engine gets to pull its models.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    None,
    Default,
}

/// A directory of the container engine's host at a path in the container. The path is the engine host's, in its
/// own form; a directory that is not there is refused by the engine, never made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub host: String,
    pub container: String,
    pub read_only: bool,
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

/// What a pull may take of the engine's disk, held from its start to its end. Both are read on the file system where
/// the engine keeps its images, the room it takes counting whatever else lands there meanwhile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PullLimits {
    /// The most the pull may put on that disk: the room it has taken there since it began, while it runs, and the
    /// image's unpacked size, every layer counted, once it is pulled; none for no bound.
    pub most_bytes: Option<u64>,
    /// The fewest bytes that disk keeps free while the pull runs; none for no floor.
    pub floor_bytes: Option<u64>,
}

impl PullLimits {
    /// Whether a pull begun with `free_at_start` bytes free on the engine's disk may go on with `free_now`:
    /// [`RuntimeError::TooLarge`] once it has taken more than the bound, [`RuntimeError::NoRoom`] once what is free is
    /// under the floor.
    pub fn hold(&self, image: &ImageRef, free_at_start: u64, free_now: u64) -> Result<(), RuntimeError> {
        let taken = free_at_start.saturating_sub(free_now);
        if let Some(most) = self.most_bytes.filter(|most| taken > *most) {
            return Err(RuntimeError::TooLarge(format!(
                "{}: the pull took {taken} bytes of the engine's disk, past its bound of {most}",
                image.0
            )));
        }
        if let Some(floor) = self.floor_bytes.filter(|floor| free_now < *floor) {
            return Err(RuntimeError::NoRoom(format!(
                "{}: the engine's disk has {free_now} bytes free, under its floor of {floor}",
                image.0
            )));
        }
        Ok(())
    }

    /// Whether an image pulled whole, `unpacked` bytes once its layers are extracted, is within the bound.
    pub fn hold_unpacked(&self, image: &ImageRef, unpacked: u64) -> Result<(), RuntimeError> {
        match self.most_bytes.filter(|most| unpacked > *most) {
            Some(most) => Err(RuntimeError::TooLarge(format!(
                "{}: the image unpacks to {unpacked} bytes, past its bound of {most}",
                image.0
            ))),
            None => Ok(()),
        }
    }
}

/// What a long call tells while it runs: progress in percent, where the engine says. Called in order, before the
/// call returns, so the caller tells each step as a fact before the outcome.
pub type Progress = Arc<dyn Fn(Option<u8>) + Send + Sync>;

/// Every fact the engine tells on its own, after a call returned. The door turns these into BEST events on its
/// stream, correlated to the command that started the container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    Started {
        id: ContainerId,
        ports: Vec<Published>,
    },
    /// It ended, with its exit code and the last lines it wrote, where the engine kept them.
    Exited {
        id: ContainerId,
        code: i64,
        last_words: Option<String>,
    },
    OutOfMemory {
        id: ContainerId,
    },
    Failed {
        id: ContainerId,
        reason: String,
    },
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
    /// A pull took, or would take, more of the engine's disk than its caller allows: the words say which image and
    /// by how much. It was given up, or the image it made removed.
    #[error("image larger than allowed: {0}")]
    TooLarge(String),
    /// The engine's disk has, or fell to, less free than a pull's floor: the pull was given up, or never begun.
    #[error("no room on the engine's disk: {0}")]
    NoRoom(String),
    /// The room on the engine's disk cannot be read where this runtime runs, so a pull's floor cannot be held: the pull
    /// was never begun.
    #[error("the room on the engine's disk is not known: {0}")]
    RoomUnknown(String),
    /// A job's disk could not be made, or this runtime makes none: the words say which.
    #[error("{0}")]
    NoDisk(String),
    /// This runtime finds no container by name at all; a name no container carries is `Ok(None)`, never this.
    #[error("{0}")]
    NoName(String),
    /// This runtime cannot follow what a container writes; a container that wrote nothing is a feed that ends.
    #[error("{0}")]
    NoFollow(String),
}

/// Which of a container's outputs some bytes came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Output {
    Out,
    Err,
}

/// Bytes a container wrote, as the engine handed them over: neither cut at lines nor read as text, which is the
/// caller's to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub output: Output,
    pub bytes: Vec<u8>,
}

/// What a follower reads: what the container wrote, in the order written, from its first byte. It closes once the
/// container has ended and all it wrote is read, or after an error, which is the last thing it tells.
pub type Following = tokio::sync::mpsc::Receiver<Result<Written, RuntimeError>>;

/// What stands between a workload and the host and the other workloads on it, weakest first, so a workload that asks
/// for one is placed only where at least that is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// A process of an engine already installed on the host: nothing of the peer's own between it and the host.
    Process,
    /// A container with no capability and no new privilege, a ceiling on tasks, and a tenant's job in a closed box.
    Container,
    /// The same, its users mapped to unprivileged ones on the host (a rootless or user-namespaced container engine):
    /// root in the container is nobody outside it.
    UserNamespace,
    /// A virtual machine with the device passed through. No adapter offers it yet.
    Vm,
}

impl Isolation {
    /// Every level, weakest first: what a workload may ask for.
    pub const ALL: [Isolation; 4] = [
        Isolation::Process,
        Isolation::Container,
        Isolation::UserNamespace,
        Isolation::Vm,
    ];

    /// The level's name, as the hardware state and a command say it.
    pub fn name(&self) -> &'static str {
        match self {
            Isolation::Process => "process",
            Isolation::Container => "container",
            Isolation::UserNamespace => "user-namespace",
            Isolation::Vm => "vm",
        }
    }

    /// What a container engine offers by the security options it reports (Docker's `SecurityOptions`, entries such
    /// as `name=seccomp,profile=builtin`): a user namespace when it runs rootless or remaps its users, a container
    /// otherwise.
    pub fn of_container_engine<S: AsRef<str>>(security_options: &[S]) -> Isolation {
        let user_namespace = security_options.iter().any(|o| {
            o.as_ref()
                .split(',')
                .any(|kv| kv.trim() == "name=rootless" || kv.trim() == "name=userns")
        });
        if user_namespace {
            Isolation::UserNamespace
        } else {
            Isolation::Container
        }
    }
}

/// What the door needs from a container engine.
#[async_trait]
pub trait Runtime: Send + Sync {
    /// Makes the image present, telling `progress` as it goes: from the registry, whether or not it is held.
    async fn pull(&self, image: &ImageRef, progress: Progress) -> Result<(), RuntimeError>;
    /// [`Runtime::pull`], held to `limits` from its start to its end. It is given up with [`RuntimeError::TooLarge`]
    /// once the room it has taken on the engine's disk, or the layers' sizes the engine says it downloads, pass the
    /// bound, and with [`RuntimeError::NoRoom`] once that disk's free room falls under the floor. An image it pulled
    /// whole and past either limit, by the room read at its end or by its unpacked size, is undone and the pull answers
    /// the limit it passed: an image the engine did not hold is removed; a reference the engine held that the pull
    /// moved to a new image names the image it named before again, the new one removed; an image the pull left as the
    /// engine held it is the owner's and stays. The unpacked size of an image the pull left as the engine held it is
    /// not held to the bound, since none of it landed on the disk: such a pull succeeds whatever that size. A layer the engine already holds takes no room while it pulls, and
    /// counts in the unpacked size. A floor where the room cannot be read is refused with [`RuntimeError::RoomUnknown`]
    /// before anything is pulled. A runtime that cannot hold a pull to limits refuses any rather than ignore them.
    async fn pull_bounded(&self, image: &ImageRef, progress: Progress, limits: PullLimits) -> Result<(), RuntimeError> {
        match limits == PullLimits::default() {
            true => self.pull(image, progress).await,
            false => Err(RuntimeError::Engine(
                "this runtime cannot hold a pull to limits on its disk, so it takes none".into(),
            )),
        }
    }
    /// The reference pinned by digest to the image the registry serves under `image` now, asked of the registry and
    /// nothing pulled: an image the registry does not serve is [`RuntimeError::ImageNotFound`] whatever the engine
    /// holds, so the answer tells a caller nothing of the host. Pulling, running and removing what it answers never
    /// touches a tag on the engine. A caller that wants the registry's answer resolves every reference first, one
    /// already pinned by digest too, and only then asks [`Runtime::holds`] of what it answers. A runtime that cannot
    /// ask a registry errs.
    async fn resolve(&self, _image: &ImageRef) -> Result<ImageRef, RuntimeError> {
        Err(RuntimeError::Engine(
            "this runtime cannot resolve a reference at its registry".into(),
        ))
    }
    /// Whether the engine holds the image now, so starting it needs no registry: a reference pinned by digest is held
    /// when the engine holds that digest under that repository, however the repository is spelled
    /// ([`ImageRef::canonical_repository`]), whatever its tags name. It is the engine's answer alone, never the
    /// registry's: a caller that must not run what the registry no longer serves, nor tell what the host holds,
    /// asks [`Runtime::resolve`] first, for a reference pinned by digest too. An error is the engine's, never
    /// "not held". An engine that cannot tell says no, and every image is pulled.
    async fn holds(&self, _image: &ImageRef) -> Result<bool, RuntimeError> {
        Ok(false)
    }
    /// Removes the image from the engine by the reference it was pulled as, so it takes no more room: one the engine
    /// no longer holds is no error, and one a container still uses is refused. A reference pinned by digest removes
    /// that reference alone: an image a tag still names stays, with its tag. A runtime that keeps no images has none to
    /// remove.
    async fn remove_image(&self, _image: &ImageRef) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// The bytes free to the engine on the file system where it keeps its images, so a caller can refuse a pull that
    /// would fill it; none when the runtime cannot tell. It may take a while on a file system that does not answer.
    async fn image_room(&self) -> Option<u64> {
        None
    }
    /// Creates and starts a container, answering its id and the published ports; emits `Started` too.
    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError>;
    /// Stops and removes a container; emits `Exited`.
    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError>;
    /// The containers this engine runs for the peer.
    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError>;
    /// The running container the caller started under `name`, the newest when several carry it; none when the engine
    /// holds no such container. A runtime that cannot look a container up by name errs, never none, so a caller never
    /// mistakes "cannot tell" for "nothing there".
    async fn named(&self, _name: &str) -> Result<Option<ContainerId>, RuntimeError> {
        Err(RuntimeError::NoName("this runtime finds no container by name".into()))
    }
    /// What the container wrote, out and error apart, from its first byte until it has ended and all of it is read,
    /// whether it is running or has just exited and is not yet removed. While one follows, the runtime does not remove
    /// the container before the follower has read it all, or a bound has passed. A runtime that cannot follow errs,
    /// never an empty feed, so a caller never mistakes "cannot tell" for "wrote nothing".
    async fn follow(&self, _id: &ContainerId) -> Result<Following, RuntimeError> {
        Err(RuntimeError::NoFollow(
            "this runtime cannot follow what a container writes".into(),
        ))
    }
    /// Every event from now on. A slow subscriber may lag; the door rebuilds from its own stream, not from this.
    fn events(&self) -> broadcast::Receiver<Event>;
    /// Whether this engine runs a job: an image run once to its exit. One that cannot (an engine already installed
    /// on the host, outside any container) says so here, and the door refuses the job at ingest with the fix rather
    /// than accepting it and failing it later.
    fn runs_jobs(&self) -> bool {
        true
    }
    /// What stands between a workload this engine runs and the host. An engine that cannot say claims the least.
    async fn isolation(&self) -> Isolation {
        Isolation::Process
    }
    /// The host's ids of the processes this engine runs for the peer, so the peer tells its own use of a device from
    /// its owner's. An engine that cannot tell says `None`.
    async fn processes(&self) -> Option<Vec<u32>> {
        None
    }
    /// A disk of `bytes` for the job `id`, capped at that size so the job cannot fill the host, and the directory on
    /// the host where it is mounted (behavioralstate/spec#66). A runtime that makes none refuses, in words.
    async fn make_disk(&self, _id: &str, _bytes: u64) -> Result<std::path::PathBuf, RuntimeError> {
        Err(RuntimeError::NoDisk(
            "this peer's container engine makes no disk for a job: a job with inputs or outputs runs where Docker does, on Linux".into(),
        ))
    }
    /// Removes the job `id`'s disk and everything on it; one already gone is no error.
    async fn remove_disk(&self, _id: &str) -> Result<(), RuntimeError> {
        Ok(())
    }
    /// Whether this runtime makes jobs' disks at all; answered at once, without asking the file system.
    fn makes_disks(&self) -> bool {
        false
    }
    /// The space free, and in all, where this runtime makes disks, the disks it made counted whole; none when it
    /// makes none, or the file system did not say. It may take a while: call it off the executor.
    fn disk_room(&self) -> Option<(u64, u64)> {
        None
    }
    /// The jobs whose disks this runtime made and has not removed, as a restart finds them.
    fn disks(&self) -> Vec<String> {
        vec![]
    }
    /// Where the job `id`'s disk is mounted on the host, when it is.
    fn disk_at(&self, _id: &str) -> Option<std::path::PathBuf> {
        None
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
    /// Every image a pull was asked for, in order: what went to the registry.
    pulled: Mutex<Vec<ImageRef>>,
    /// Every image a removal was asked for, in order.
    removed: Mutex<Vec<ImageRef>>,
    /// What a pull of an image downloads, where a test sets it; nothing for one it holds.
    sizes: Mutex<HashMap<ImageRef, u64>>,
    /// What an image takes on its disk once pulled, where a test sets it: its unpacked size.
    unpacked: Mutex<HashMap<ImageRef, u64>>,
    /// What each image a pull made took from the room for images, given back when it is removed.
    landed: Mutex<HashMap<ImageRef, u64>>,
    /// References the engine holds that the registry now names a newer image by: the next pull moves them to it.
    moved: Mutex<std::collections::HashSet<ImageRef>>,
    /// How many times a pull moved each reference the engine holds to a newer image: its id is told by it.
    generation: Mutex<HashMap<ImageRef, u32>>,
    /// Every reference pinned by digest it resolved, with the reference it was resolved from.
    resolved: Mutex<HashMap<ImageRef, ImageRef>>,
    /// The room it says it has for images, as a test sets it; `None` for an engine that cannot tell.
    image_room: Mutex<Option<u64>>,
    devices: Vec<DeviceId>,
    next: Mutex<u32>,
    tx: broadcast::Sender<Event>,
    /// When set, a pull waits for a permit: a test holds a workload between its pull and its start.
    gate: Mutex<Option<std::sync::Arc<tokio::sync::Semaphore>>>,
    /// What the engine says when it refuses to start a container, when a test says it does.
    refusal: Mutex<Option<String>>,
    /// What the engine says when it fails to stop a container, while a test says it does.
    stop_refusal: Mutex<Option<String>>,
    /// What it says stands between its containers and the host: a container, unless a test says otherwise.
    isolation: Isolation,
    /// The host's ids of the processes its containers run, as a test sets them; `None` for an engine that cannot
    /// tell.
    processes: Mutex<Option<Vec<u32>>>,
    /// Where its jobs' disks are made, a directory of its own, and the room it says it has there.
    disks: std::path::PathBuf,
    disk_free: Mutex<u64>,
    /// The disks it made, with their sizes: each takes its whole size from the room, as an allocated file does.
    disks_made: Mutex<HashMap<String, u64>>,
    /// Why the next disk fails once it is begun, as a file system that cannot be made on it fails.
    broken_disk: Mutex<Option<String>>,
    /// Whether its room can be read now: not, as a file system that does not answer.
    room_unread: Mutex<bool>,
    /// Whether it makes no disk, as an engine whose peer cannot mount one.
    no_disks: Mutex<bool>,
    /// What each container it started wrote, and who follows it while it runs.
    written: Mutex<HashMap<ContainerId, Writing>>,
    /// The user an image names, where a test sets one; root otherwise, as an image that names none runs.
    image_users: Mutex<HashMap<ImageRef, String>>,
}

/// One container's output on the fake: all it wrote, its followers while it runs, and whether it has ended.
#[derive(Default)]
struct Writing {
    chunks: Vec<Written>,
    followers: Vec<tokio::sync::mpsc::Sender<Result<Written, RuntimeError>>>,
    ended: bool,
}

/// What one follower of the fake holds unread: more than any test writes before reading.
const FAKE_FOLLOWED: usize = 1024;

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
            pulled: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
            sizes: Mutex::new(HashMap::new()),
            unpacked: Mutex::new(HashMap::new()),
            landed: Mutex::new(HashMap::new()),
            moved: Mutex::new(std::collections::HashSet::new()),
            generation: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            image_room: Mutex::new(Some(1 << 40)),
            devices,
            next: Mutex::new(0),
            tx,
            gate: Mutex::new(None),
            refusal: Mutex::new(None),
            stop_refusal: Mutex::new(None),
            isolation: Isolation::Container,
            disks: std::env::temp_dir().join("best-peer-fake-disks").join(uuid_like()),
            disk_free: Mutex::new(1 << 40),
            disks_made: Mutex::new(HashMap::new()),
            broken_disk: Mutex::new(None),
            processes: Mutex::new(Some(Vec::new())),
            room_unread: Mutex::new(false),
            no_disks: Mutex::new(false),
            written: Mutex::new(HashMap::new()),
            image_users: Mutex::new(HashMap::new()),
        }
    }

    /// The image names `user` as its own (a Dockerfile's `USER`).
    pub fn image_runs_as(&self, image: ImageRef, user: &str) {
        self.image_users.lock().unwrap().insert(image, user.to_string());
    }

    /// Who a running container's processes run as, as an engine decides it: the confinement's user, `uid:gid`, when it
    /// sets one, whatever the image names; else the image's own, root when it names none.
    pub fn user_of(&self, id: &ContainerId) -> Option<String> {
        let spec = self.spec_of(id)?;
        Some(match spec.confinement.user {
            Some(User { uid, gid }) => format!("{uid}:{gid}"),
            None => self
                .image_users
                .lock()
                .unwrap()
                .get(&self.source_of(&spec.image))
                .cloned()
                .unwrap_or_else(|| "root".into()),
        })
    }

    /// From now on its room cannot be read, or can again.
    pub fn room_unread(&self, unread: bool) {
        *self.room_unread.lock().unwrap() = unread;
    }

    /// From now on it makes no disk, as a peer that cannot mount one, or does again.
    pub fn makes_no_disks(&self, none: bool) {
        *self.no_disks.lock().unwrap() = none;
    }

    /// The next disk is begun, its directory made, and then fails with `why`.
    pub fn break_next_disk(&self, why: &str) {
        *self.broken_disk.lock().unwrap() = Some(why.to_string());
    }

    /// The room it says it has for disks from now on, before the disks it made.
    pub fn set_disk_room(&self, free: u64) {
        *self.disk_free.lock().unwrap() = free;
    }

    /// Where the job `id`'s disk is, made or not.
    pub fn disk_of(&self, id: &str) -> std::path::PathBuf {
        self.disks.join(id)
    }

    /// Sets the host's ids of the processes its containers run, or `None` for an engine that cannot tell.
    pub fn set_processes(&self, pids: Option<Vec<u32>>) {
        *self.processes.lock().unwrap() = pids;
    }

    /// An engine that offers `isolation`, as a rootless one offers a user namespace.
    pub fn with_isolation(mut self, isolation: Isolation) -> Self {
        self.isolation = isolation;
        self
    }

    /// Holds every pull from now on until the gate answered gives it a permit (`add_permits`).
    pub fn hold_pulls(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        *self.gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    /// Every image a pull was asked for, in order: what went to the registry.
    pub fn pulled(&self) -> Vec<ImageRef> {
        self.pulled.lock().unwrap().clone()
    }

    /// Every image a removal was asked for, in order.
    pub fn removed(&self) -> Vec<ImageRef> {
        self.removed.lock().unwrap().clone()
    }

    /// A pull of `image`, while the engine does not hold it, downloads `bytes`.
    pub fn sized(&self, image: ImageRef, bytes: u64) {
        self.sizes.lock().unwrap().insert(image, bytes);
    }

    /// A pull of `image`, while the engine does not hold it, unpacks to `bytes` on its disk: its room for images falls
    /// by that in step with what the pull reports, while it can be read, and the image's size once pulled is that.
    pub fn unpacks(&self, image: ImageRef, bytes: u64) {
        self.unpacked.lock().unwrap().insert(image, bytes);
    }

    /// The registry names a newer image by `image`, a reference the engine holds: the next pull of it moves the
    /// reference to that image, a new id, which downloads and unpacks as a test set for it.
    pub fn moves_on_pull(&self, image: ImageRef) {
        self.moved.lock().unwrap().insert(image);
    }

    /// The id of the image the engine holds by `image`, none when it holds none: a pull that moves the reference
    /// changes it.
    pub fn image_id(&self, image: &ImageRef) -> Option<String> {
        if !self.local.lock().unwrap().contains(image) {
            return None;
        }
        let generation = self.generation.lock().unwrap().get(image).copied().unwrap_or(0);
        Some(format!("{}#{generation}", image.0))
    }

    /// The digest of the image `image` names at `generation`: the registry's now, or the one the engine holds.
    fn digest_at(image: &ImageRef, generation: u32) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (image.repository(), &image.0, generation).hash(&mut h);
        let h = h.finish();
        format!("sha256:{h:016x}{h:016x}{h:016x}{h:016x}")
    }

    /// The reference a test set things on for `image`: the tag it was resolved from, for one pinned by digest.
    fn source_of(&self, image: &ImageRef) -> ImageRef {
        self.resolved
            .lock()
            .unwrap()
            .get(image)
            .cloned()
            .unwrap_or_else(|| image.clone())
    }

    fn serves(&self, image: &ImageRef) -> bool {
        self.open_registry || self.registry.lock().unwrap().contains(image)
    }

    /// Whether it holds `image`: by that reference, or, for one pinned by digest, under a tag of its repository that
    /// names that digest now.
    fn held(&self, image: &ImageRef) -> bool {
        let local = self.local.lock().unwrap();
        if local.contains(image) {
            return true;
        }
        image.digest().is_some()
            && local.iter().any(|tag| {
                tag.digest().is_none() && tag.canonical_repository() == image.canonical_repository() && {
                    let generation = self.generation.lock().unwrap().get(tag).copied().unwrap_or(0);
                    image.digest() == Some(Self::digest_at(tag, generation).as_str())
                }
            })
    }

    /// Sets the room it says it has for images from now on, or `None` for an engine that cannot tell.
    pub fn set_image_room(&self, free: Option<u64>) {
        *self.image_room.lock().unwrap() = free;
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

    /// Makes every start from now on refused with the engine's own words, as Docker refuses a container its NVIDIA
    /// toolkit will not hand a device to.
    pub fn refuse_starts(&self, why: &str) {
        *self.refusal.lock().unwrap() = Some(why.into());
    }

    /// Makes every stop from now on fail with `why`, as an engine that does not answer, or stops that when `None`.
    pub fn refuse_stops(&self, why: Option<&str>) {
        *self.stop_refusal.lock().unwrap() = why.map(str::to_string);
    }

    /// A fake whose pull reports every percent from 0 to 100, as a real engine does.
    pub fn reporting_every_percent(mut self) -> Self {
        self.steps = (0..=100).map(Some).collect();
        self
    }

    /// A fake whose pull reports `steps`, in order: a share that reaches 100 and falls back, as an engine that learns
    /// of more to fetch as it goes does.
    pub fn reporting(mut self, steps: &[u8]) -> Self {
        self.steps = steps.iter().copied().map(Some).collect();
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
        self.ended(id);
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
        self.ended(id);
        let _ = self.tx.send(Event::Failed {
            id: id.clone(),
            reason: reason.to_string(),
        });
        Ok(())
    }

    /// Ends a container on its own, as a process that exits does, with its exit code and the last lines it wrote.
    pub fn exit(&self, id: &ContainerId, code: i64, last_words: &str) -> Result<(), RuntimeError> {
        self.containers
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        self.ended(id);
        let _ = self.tx.send(Event::Exited {
            id: id.clone(),
            code,
            last_words: Some(last_words.to_string()),
        });
        Ok(())
    }

    /// Makes a running container write `text` to `output`, as a process does: told to every follower at once.
    pub fn write(&self, id: &ContainerId, output: Output, text: &str) -> Result<(), RuntimeError> {
        let mut written = self.written.lock().unwrap();
        let writing = written
            .get_mut(id)
            .filter(|w| !w.ended)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        let chunk = Written {
            output,
            bytes: text.as_bytes().to_vec(),
        };
        writing.chunks.push(chunk.clone());
        // A follower that was dropped is let go; one that fell behind is a test writing more than the fake holds,
        // said aloud, never a quiet end that looks like the container's.
        writing.followers.retain(|f| match f.try_send(Ok(chunk.clone())) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                panic!("a follower of the fake fell {FAKE_FOLLOWED} chunks behind")
            }
        });
        Ok(())
    }

    /// Ends what a container writes: its followers read what is left and close.
    fn ended(&self, id: &ContainerId) {
        if let Some(writing) = self.written.lock().unwrap().get_mut(id) {
            writing.ended = true;
            writing.followers.clear();
        }
    }

    pub fn spec_of(&self, id: &ContainerId) -> Option<Spec> {
        self.containers.lock().unwrap().get(id).cloned()
    }
}

/// A name no other fake in this process or another uses: the fake's disks of one test stay apart from another's.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{}-{t}-{n}", std::process::id())
}

#[async_trait]
impl Runtime for Fake {
    async fn pull(&self, image: &ImageRef, progress: Progress) -> Result<(), RuntimeError> {
        self.pull_bounded(image, progress, PullLimits::default()).await
    }

    async fn pull_bounded(&self, image: &ImageRef, progress: Progress, limits: PullLimits) -> Result<(), RuntimeError> {
        self.pulled.lock().unwrap().push(image.clone());
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            if let Ok(permit) = gate.acquire().await {
                permit.forget();
            }
        }
        let source = self.source_of(image);
        let resolved = self.resolved.lock().unwrap().contains_key(image);
        if !(resolved && self.serves(&source)) && !self.serves(image) {
            return Err(RuntimeError::ImageNotFound(image.0.clone()));
        }
        let held = self.held(image);
        let moves = held && image.digest().is_none() && self.moved.lock().unwrap().contains(image);
        let fresh = !held || moves;
        let downloads = self.sizes.lock().unwrap().get(&source).copied().filter(|_| fresh);
        if let (Some(bytes), Some(most)) = (downloads, limits.most_bytes) {
            if bytes > most {
                return Err(RuntimeError::TooLarge(image.0.clone()));
            }
        }
        let unpacked = self.unpacked.lock().unwrap().get(&source).copied().filter(|_| fresh);
        let start = *self.image_room.lock().unwrap();
        if limits.floor_bytes.is_some() && start.is_none() {
            return Err(RuntimeError::RoomUnknown(format!(
                "{}: the room on the engine's disk cannot be read, so its floor cannot be held",
                image.0
            )));
        }
        if let Some(start) = start {
            limits.hold(image, start, start)?;
        }
        // The room falls in step with what the pull reports, held to the limits at each step but the last, which is
        // the reading at its end, once the image is made.
        let steps = self.steps.len() as u64;
        for (i, &step) in self.steps.iter().enumerate() {
            progress(step);
            if let (Some(start), Some(unpacked)) = (start, unpacked) {
                let now = start.saturating_sub(unpacked * (i as u64 + 1) / steps.max(1));
                *self.image_room.lock().unwrap() = Some(now);
                if (i as u64) + 1 < steps {
                    if let Err(e) = limits.hold(image, start, now) {
                        // Given up: what it downloaded is the engine's to release, and no image is made.
                        *self.image_room.lock().unwrap() = Some(start);
                        return Err(e);
                    }
                }
            }
        }
        if let Some(start) = start.filter(|_| unpacked.is_some()) {
            let now = self.image_room.lock().unwrap().unwrap_or(start);
            self.landed
                .lock()
                .unwrap()
                .insert(image.clone(), start.saturating_sub(now));
        }
        {
            let mut local = self.local.lock().unwrap();
            if !local.contains(image) {
                local.push(image.clone());
            }
        }
        if moves {
            self.moved.lock().unwrap().remove(image);
            *self.generation.lock().unwrap().entry(image.clone()).or_default() += 1;
        }
        let end = *self.image_room.lock().unwrap();
        let size = self.unpacked.lock().unwrap().get(&source).copied().unwrap_or(0);
        let past = match (start, end) {
            (Some(start), Some(end)) => limits.hold(image, start, end).err(),
            _ => None,
        }
        .or_else(|| limits.hold_unpacked(image, size).err().filter(|_| fresh));
        let Some(e) = past else {
            return Ok(());
        };
        // Undone as an engine's adapter undoes it: an image it did not hold is removed; a reference it held and the
        // pull moved is given back to the image it named, the new one removed; one the pull left alone is the owner's.
        if !held {
            let _ = self.remove_image(image).await;
        } else if moves {
            *self.generation.lock().unwrap().entry(image.clone()).or_default() -= 1;
            if let Some(taken) = self.landed.lock().unwrap().remove(image) {
                if let Some(room) = self.image_room.lock().unwrap().as_mut() {
                    *room = room.saturating_add(taken);
                }
            }
        }
        Err(e)
    }

    async fn resolve(&self, image: &ImageRef) -> Result<ImageRef, RuntimeError> {
        if image.digest().is_some() {
            let known = self.resolved.lock().unwrap().contains_key(image);
            return match known || self.serves(image) {
                true => Ok(image.clone()),
                false => Err(RuntimeError::ImageNotFound(image.0.clone())),
            };
        }
        if !self.serves(image) {
            return Err(RuntimeError::ImageNotFound(image.0.clone()));
        }
        let generation = self.generation.lock().unwrap().get(image).copied().unwrap_or(0);
        let newer = u32::from(self.moved.lock().unwrap().contains(image));
        let pinned = image.pinned(&Self::digest_at(image, generation + newer));
        self.resolved.lock().unwrap().insert(pinned.clone(), image.clone());
        Ok(pinned)
    }

    async fn holds(&self, image: &ImageRef) -> Result<bool, RuntimeError> {
        Ok(self.held(image))
    }

    async fn remove_image(&self, image: &ImageRef) -> Result<(), RuntimeError> {
        self.removed.lock().unwrap().push(image.clone());
        if self.containers.lock().unwrap().values().any(|s| s.image == *image) {
            return Err(RuntimeError::Engine(format!(
                "the image {} is used by a running container",
                image.0
            )));
        }
        self.local.lock().unwrap().retain(|i| i != image);
        if let Some(taken) = self.landed.lock().unwrap().remove(image) {
            if let Some(room) = self.image_room.lock().unwrap().as_mut() {
                *room = room.saturating_add(taken);
            }
        }
        Ok(())
    }

    async fn image_room(&self) -> Option<u64> {
        *self.image_room.lock().unwrap()
    }

    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError> {
        if let Some(why) = self.refusal.lock().unwrap().clone() {
            return Err(RuntimeError::Engine(why));
        }
        if !self.held(&spec.image) {
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
        self.written.lock().unwrap().insert(id.clone(), Writing::default());
        let _ = self.tx.send(Event::Started {
            id: id.clone(),
            ports: ports.clone(),
        });
        Ok(Started { id, ports })
    }

    async fn stop(&self, id: &ContainerId) -> Result<(), RuntimeError> {
        if let Some(why) = self.stop_refusal.lock().unwrap().clone() {
            return Err(RuntimeError::Engine(why));
        }
        self.containers
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        self.ended(id);
        let _ = self.tx.send(Event::Exited {
            id: id.clone(),
            code: 0,
            last_words: None,
        });
        Ok(())
    }

    async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError> {
        Ok(self.containers.lock().unwrap().keys().cloned().collect())
    }

    async fn named(&self, name: &str) -> Result<Option<ContainerId>, RuntimeError> {
        Ok(self
            .containers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, spec)| spec.name.as_deref() == Some(name))
            .map(|(id, _)| id.clone())
            .max_by_key(|id| id.0.rsplit('-').next().and_then(|n| n.parse::<u64>().ok())))
    }

    async fn follow(&self, id: &ContainerId) -> Result<Following, RuntimeError> {
        let mut written = self.written.lock().unwrap();
        let writing = written
            .get_mut(id)
            .ok_or_else(|| RuntimeError::NoSuchContainer(id.0.clone()))?;
        // The fake never removes a container, so one that has ended is followed as an engine follows one exited and
        // not yet removed: all it wrote, then the end.
        assert!(
            writing.chunks.len() < FAKE_FOLLOWED,
            "the fake holds {FAKE_FOLLOWED} chunks for a follower"
        );
        let (tx, rx) = tokio::sync::mpsc::channel(FAKE_FOLLOWED);
        for chunk in &writing.chunks {
            let _ = tx.try_send(Ok(chunk.clone()));
        }
        if !writing.ended {
            writing.followers.push(tx);
        }
        Ok(rx)
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    async fn make_disk(&self, id: &str, bytes: u64) -> Result<std::path::PathBuf, RuntimeError> {
        if self.disk_room().is_some_and(|(free, _)| bytes > free) {
            return Err(RuntimeError::NoDisk(format!(
                "no room for a disk of {bytes} bytes on this host"
            )));
        }
        let dir = self.disk_of(id);
        std::fs::create_dir_all(&dir).map_err(|e| RuntimeError::NoDisk(e.to_string()))?;
        if let Some(why) = self.broken_disk.lock().unwrap().take() {
            return Err(RuntimeError::NoDisk(why));
        }
        self.disks_made.lock().unwrap().insert(id.to_string(), bytes);
        Ok(dir)
    }

    async fn remove_disk(&self, id: &str) -> Result<(), RuntimeError> {
        self.disks_made.lock().unwrap().remove(id);
        match std::fs::remove_dir_all(self.disk_of(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(RuntimeError::NoDisk(e.to_string())),
        }
    }

    fn makes_disks(&self) -> bool {
        !*self.no_disks.lock().unwrap()
    }

    fn disk_room(&self) -> Option<(u64, u64)> {
        if *self.room_unread.lock().unwrap() {
            return None;
        }
        let free = *self.disk_free.lock().unwrap();
        let made: u64 = self.disks_made.lock().unwrap().values().sum();
        Some((free.saturating_sub(made), free.max(1 << 40)))
    }

    fn disks(&self) -> Vec<String> {
        std::fs::read_dir(&self.disks)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect()
    }

    fn disk_at(&self, id: &str) -> Option<std::path::PathBuf> {
        Some(self.disk_of(id)).filter(|d| d.is_dir())
    }

    fn runs_jobs(&self) -> bool {
        self.jobs
    }

    async fn isolation(&self) -> Isolation {
        self.isolation
    }

    async fn processes(&self) -> Option<Vec<u32>> {
        self.processes.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_engine_that_runs_rootless_or_remaps_its_users_offers_a_user_namespace() {
        let plain = ["name=seccomp,profile=builtin", "name=cgroupns"];
        assert_eq!(Isolation::of_container_engine(&plain), Isolation::Container);
        let rootless = ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"];
        assert_eq!(Isolation::of_container_engine(&rootless), Isolation::UserNamespace);
        let remapped = ["name=apparmor", "name=userns"];
        assert_eq!(Isolation::of_container_engine(&remapped), Isolation::UserNamespace);
        assert_eq!(Isolation::of_container_engine::<&str>(&[]), Isolation::Container);
        assert!(Isolation::Process < Isolation::Container);
        assert!(Isolation::Container < Isolation::UserNamespace && Isolation::UserNamespace < Isolation::Vm);
        assert_eq!(
            Isolation::ALL.iter().map(|i| i.name()).collect::<Vec<_>>(),
            ["process", "container", "user-namespace", "vm"]
        );
    }

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
            mounts: vec![],
            confinement: Confinement::default(),
            name: None,
        }
    }

    #[test]
    fn the_closed_box_takes_half_the_hosts_cores_and_a_ceiling_on_open_files() {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
        let job = Confinement::default();
        assert_eq!(job.cpus, Some((cores / 2).max(1)));
        assert_eq!(job.open_files, Some(65536));
        let serving = Confinement::serving();
        assert_eq!(serving.cpus, None, "an engine serving a model keeps the host's cores");
        assert_eq!(serving.open_files, None);
    }

    #[test]
    fn the_closed_box_runs_as_nobody_and_an_engine_serving_a_model_as_its_image_says() {
        assert_eq!(Confinement::default().user, Some(User { uid: 65534, gid: 65534 }));
        assert_eq!(Confinement::serving().user, None);
    }

    #[tokio::test]
    async fn a_job_runs_as_its_boxs_user_even_from_an_image_that_names_root() {
        let rt = fake();
        let image = ImageRef("ollama/ollama:0.6".into());
        rt.image_runs_as(image.clone(), "root");
        let boxed = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap();
        assert_eq!(rt.user_of(&boxed.id).as_deref(), Some("65534:65534"));
        let mut open = spec("ollama/ollama:0.6", "gpu-0");
        open.confinement = Confinement::serving();
        let open = rt.start(open).await.unwrap();
        assert_eq!(
            rt.user_of(&open.id).as_deref(),
            Some("root"),
            "with no user of its own, the image's stands"
        );
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

    #[tokio::test]
    async fn a_removed_image_is_no_longer_held_and_one_a_running_container_uses_is_refused() {
        let rt = fake();
        let image = ImageRef("ollama/ollama:0.6".into());
        let id = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        assert!(matches!(
            rt.remove_image(&image).await.unwrap_err(),
            RuntimeError::Engine(_)
        ));
        assert!(rt.holds(&image).await.unwrap(), "an image in use stays");
        rt.stop(&id).await.unwrap();
        rt.remove_image(&image).await.unwrap();
        assert!(!rt.holds(&image).await.unwrap());
        assert!(matches!(
            rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap_err(),
            RuntimeError::ImageNotFound(_)
        ));
        rt.remove_image(&image).await.unwrap();
        assert_eq!(
            rt.removed(),
            vec![image.clone(), image.clone(), image],
            "every removal asked for"
        );
    }

    #[tokio::test]
    async fn a_pull_that_would_download_more_than_its_bound_is_refused_and_leaves_nothing_held() {
        let rt = Fake::new(vec!["gpu-0".into()], vec![ImageRef("ollama/ollama:0.6".into())]).with_open_registry();
        let big = ImageRef("vllm/vllm-openai:v0.8".into());
        rt.sized(big.clone(), 20 << 30);
        let err = rt
            .pull_bounded(&big, Arc::new(|_| {}), most(10 << 30))
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::TooLarge(ref i) if i == "vllm/vllm-openai:v0.8"));
        assert!(!rt.holds(&big).await.unwrap(), "nothing of it is kept");
        rt.pull_bounded(&big, Arc::new(|_| {}), most(20 << 30)).await.unwrap();
        assert!(rt.holds(&big).await.unwrap());
        rt.pull_bounded(&big, Arc::new(|_| {}), most(1)).await.unwrap();
        let held = ImageRef("ollama/ollama:0.6".into());
        rt.sized(held.clone(), 20 << 30);
        rt.pull_bounded(&held, Arc::new(|_| {}), most(1)).await.unwrap();
        let other = ImageRef("nobody/else:1".into());
        rt.sized(other.clone(), 20 << 30);
        rt.pull_bounded(&other, Arc::new(|_| {}), PullLimits::default())
            .await
            .unwrap();
    }

    fn most(bytes: u64) -> PullLimits {
        PullLimits {
            most_bytes: Some(bytes),
            floor_bytes: None,
        }
    }

    #[test]
    fn a_pull_is_held_to_the_room_it_took_and_the_room_left_and_an_image_to_its_unpacked_size() {
        let image = ImageRef("x".into());
        let limits = PullLimits {
            most_bytes: Some(10),
            floor_bytes: Some(100),
        };
        assert!(limits.hold(&image, 200, 190).is_ok(), "the bound itself is within it");
        assert!(
            matches!(limits.hold(&image, 200, 189), Err(RuntimeError::TooLarge(why)) if why.contains("bound of 10"))
        );
        assert!(limits.hold(&image, 110, 100).is_ok(), "the floor itself is within it");
        assert!(matches!(limits.hold(&image, 105, 99), Err(RuntimeError::NoRoom(why)) if why.contains("floor of 100")));
        assert!(
            limits.hold(&image, 100, 150).is_ok(),
            "room freed meanwhile takes nothing"
        );
        assert!(limits.hold_unpacked(&image, 10).is_ok());
        assert!(
            matches!(limits.hold_unpacked(&image, 11), Err(RuntimeError::TooLarge(why)) if why.contains("unpacks"))
        );
        assert!(PullLimits::default().hold(&image, u64::MAX, 0).is_ok());
        assert!(PullLimits::default().hold_unpacked(&image, u64::MAX).is_ok());
    }

    fn unpacking(image: &ImageRef, bytes: u64, room: Option<u64>) -> Fake {
        let rt = Fake::new(vec!["gpu-0".into()], vec![])
            .with_open_registry()
            .reporting_every_percent();
        rt.unpacks(image.clone(), bytes);
        rt.set_image_room(room);
        rt
    }

    #[tokio::test]
    async fn a_pull_whose_room_on_disk_passes_its_bound_is_given_up_midway_and_its_room_given_back() {
        let image = ImageRef("big/unpacks:1".into());
        let rt = unpacking(&image, 30 << 30, Some(100 << 30));
        rt.sized(image.clone(), 8 << 30);
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        let err = rt
            .pull_bounded(&image, Arc::new(move |p| sink.lock().unwrap().push(p)), most(25 << 30))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::TooLarge(ref why) if why.contains("took") && why.contains("bound")),
            "{err}"
        );
        assert!(!told.lock().unwrap().contains(&Some(100)), "given up before it ended");
        assert!(!rt.holds(&image).await.unwrap(), "no image is made for it");
        assert_eq!(rt.image_room().await, Some(100 << 30));
    }

    #[tokio::test]
    async fn a_pull_that_brings_the_disk_under_its_floor_is_given_up_midway() {
        let image = ImageRef("big/unpacks:1".into());
        let rt = unpacking(&image, 20 << 30, Some(100 << 30));
        let limits = PullLimits {
            most_bytes: Some(50 << 30),
            floor_bytes: Some(90 << 30),
        };
        let err = rt.pull_bounded(&image, Arc::new(|_| {}), limits).await.unwrap_err();
        assert!(
            matches!(err, RuntimeError::NoRoom(ref why) if why.contains("floor")),
            "{err}"
        );
        assert!(!rt.holds(&image).await.unwrap());
        rt.set_image_room(Some(200 << 30));
        rt.pull_bounded(&image, Arc::new(|_| {}), limits).await.unwrap();
        assert_eq!(
            rt.image_room().await,
            Some(180 << 30),
            "what it unpacked is taken from the room"
        );
        rt.remove_image(&image).await.unwrap();
        assert_eq!(rt.image_room().await, Some(200 << 30), "and given back with the image");
    }

    #[tokio::test]
    async fn a_floor_where_the_room_cannot_be_read_is_refused_before_anything_is_pulled() {
        let image = ImageRef("small/image:1".into());
        let rt = unpacking(&image, 1 << 20, None);
        let floor = PullLimits {
            most_bytes: None,
            floor_bytes: Some(1),
        };
        let err = rt.pull_bounded(&image, Arc::new(|_| {}), floor).await.unwrap_err();
        assert!(
            matches!(err, RuntimeError::RoomUnknown(ref why) if why.contains("cannot be read")),
            "{err}"
        );
        assert!(!rt.holds(&image).await.unwrap());
        rt.set_image_room(Some(0));
        let err = rt.pull_bounded(&image, Arc::new(|_| {}), floor).await.unwrap_err();
        assert!(
            matches!(err, RuntimeError::NoRoom(_)),
            "a disk under the floor at the start is refused at once"
        );
    }

    #[tokio::test]
    async fn an_image_that_unpacks_past_its_bound_is_removed_once_pulled_and_the_pull_fails() {
        let image = ImageRef("big/unpacks:1".into());
        let rt = unpacking(&image, 30 << 30, None);
        let err = rt
            .pull_bounded(&image, Arc::new(|_| {}), most(25 << 30))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::TooLarge(ref why) if why.contains("unpacks")),
            "{err}"
        );
        assert!(!rt.holds(&image).await.unwrap(), "the image it made is removed");
        assert_eq!(rt.removed(), vec![image.clone()]);
        rt.pull_bounded(&image, Arc::new(|_| {}), most(30 << 30)).await.unwrap();
        assert!(rt.holds(&image).await.unwrap(), "at the bound it stays");
    }

    #[tokio::test]
    async fn an_image_the_engine_held_before_its_pull_and_still_holds_is_pulled_whatever_it_unpacks_to() {
        let image = ImageRef("owners/own:latest".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![image.clone()]).with_open_registry();
        let owners = rt.image_id(&image);
        rt.unpacks(image.clone(), 30 << 30);
        rt.pull_bounded(&image, Arc::new(|_| {}), most(25 << 30)).await.unwrap();
        assert!(rt.holds(&image).await.unwrap());
        assert_eq!(rt.image_id(&image), owners, "the same image, nothing of it landed");
        assert!(rt.removed().is_empty());
        rt.set_image_room(Some(0));
        let floor = PullLimits {
            most_bytes: None,
            floor_bytes: Some(1),
        };
        let err = rt.pull_bounded(&image, Arc::new(|_| {}), floor).await.unwrap_err();
        assert!(matches!(err, RuntimeError::NoRoom(_)), "the floor is still held");
        assert!(rt.holds(&image).await.unwrap());
    }

    #[tokio::test]
    async fn a_reference_the_owner_held_that_a_pull_moved_past_its_bound_names_the_owners_image_again() {
        let image = ImageRef("owners/own:latest".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![image.clone()]).with_open_registry();
        let owners = rt.image_id(&image).unwrap();
        rt.moves_on_pull(image.clone());
        rt.unpacks(image.clone(), 30 << 30);
        rt.set_image_room(None);
        let err = rt
            .pull_bounded(&image, Arc::new(|_| {}), most(25 << 30))
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::TooLarge(_)), "{err}");
        assert_eq!(
            rt.image_id(&image),
            Some(owners.clone()),
            "the reference names the owner's image again"
        );
        assert!(rt.removed().is_empty(), "the owner's image is never removed");
        rt.moves_on_pull(image.clone());
        rt.pull_bounded(&image, Arc::new(|_| {}), most(30 << 30)).await.unwrap();
        assert_ne!(
            rt.image_id(&image),
            Some(owners),
            "within its bound, the pull moves it as an engine does"
        );
    }

    #[tokio::test]
    async fn a_pull_past_its_floor_by_the_reading_at_its_end_is_undone() {
        let image = ImageRef("big/unpacks:1".into());
        let rt = unpacking(&image, 20 << 30, Some(100 << 30)).reporting(&[100]);
        let limits = PullLimits {
            most_bytes: None,
            floor_bytes: Some(90 << 30),
        };
        let err = rt.pull_bounded(&image, Arc::new(|_| {}), limits).await.unwrap_err();
        assert!(
            matches!(err, RuntimeError::NoRoom(ref why) if why.contains("floor")),
            "{err}"
        );
        assert!(!rt.holds(&image).await.unwrap(), "the image it made is removed");
        assert_eq!(rt.removed(), vec![image]);
        assert_eq!(rt.image_room().await, Some(100 << 30), "and its room given back");
    }

    #[test]
    fn a_reference_is_pinned_to_its_repository_by_digest_whatever_its_tag_or_registry_port() {
        let d = "sha256:abc";
        for (r, repo) in [
            ("nvidia/cuda:12.8.0-base-ubuntu24.04", "nvidia/cuda"),
            ("registry.example:5000/team/train", "registry.example:5000/team/train"),
            ("registry.example:5000/team/train:1", "registry.example:5000/team/train"),
            ("busybox", "busybox"),
            ("busybox:1@sha256:old", "busybox"),
        ] {
            let image = ImageRef(r.into());
            assert_eq!(image.repository(), repo, "{r}");
            assert_eq!(image.pinned(d), ImageRef(format!("{repo}@{d}")), "{r}");
        }
        assert_eq!(ImageRef("busybox@sha256:abc".into()).digest(), Some("sha256:abc"));
        assert_eq!(ImageRef("busybox:1".into()).digest(), None);
    }

    #[test]
    fn a_repository_is_spelled_in_full_whatever_registry_or_library_it_leaves_out() {
        for (r, full) in [
            ("busybox", "docker.io/library/busybox"),
            ("busybox:1", "docker.io/library/busybox"),
            ("library/busybox@sha256:a", "docker.io/library/busybox"),
            ("docker.io/busybox", "docker.io/library/busybox"),
            ("index.docker.io/library/busybox", "docker.io/library/busybox"),
            ("nvidia/cuda:12", "docker.io/nvidia/cuda"),
            ("docker.io/nvidia/cuda@sha256:a", "docker.io/nvidia/cuda"),
            ("ghcr.io/example/train:1", "ghcr.io/example/train"),
            ("registry.example:5000/team/train", "registry.example:5000/team/train"),
            ("localhost/own", "localhost/own"),
            ("private/other", "docker.io/private/other"),
        ] {
            assert_eq!(ImageRef(r.into()).canonical_repository(), full, "{r}");
        }
    }

    #[tokio::test]
    async fn a_digest_is_held_under_its_repository_however_spelled_and_never_under_another() {
        let tag = ImageRef("docker.io/library/busybox:1".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![tag.clone()]).with_open_registry();
        let pinned = rt.resolve(&tag).await.unwrap();
        let digest = pinned.digest().unwrap();
        assert!(rt.holds(&ImageRef(format!("busybox@{digest}"))).await.unwrap());
        assert!(rt.holds(&ImageRef(format!("library/busybox@{digest}"))).await.unwrap());
        assert!(!rt.holds(&ImageRef(format!("private/other@{digest}"))).await.unwrap());
        assert!(!rt
            .holds(&ImageRef(format!("ghcr.io/library/busybox@{digest}")))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_reference_is_resolved_at_the_registry_and_its_digest_pulled_run_and_removed_with_no_tag_made() {
        let tag = ImageRef("ghcr.io/example/train:1".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![]);
        rt.registry_has(tag.clone());
        let pinned = rt.resolve(&tag).await.unwrap();
        assert_eq!(pinned.repository(), "ghcr.io/example/train");
        assert!(pinned.digest().unwrap().starts_with("sha256:"));
        assert!(rt.pulled().is_empty(), "resolving pulls nothing");
        assert!(!rt.holds(&pinned).await.unwrap());
        rt.pull(&pinned, Arc::new(|_| {})).await.unwrap();
        assert!(rt.holds(&pinned).await.unwrap());
        assert!(!rt.holds(&tag).await.unwrap(), "a pull by digest makes no tag");
        let mut s = spec(&pinned.0, "gpu-0");
        s.ports = vec![];
        let id = rt.start(s).await.unwrap().id;
        rt.stop(&id).await.unwrap();
        rt.remove_image(&pinned).await.unwrap();
        assert!(!rt.holds(&pinned).await.unwrap());
    }

    #[tokio::test]
    async fn a_tag_the_owner_holds_at_an_older_image_is_left_on_it_by_a_pull_of_the_registrys_digest() {
        let tag = ImageRef("pytorch/pytorch:latest".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![tag.clone()]).with_open_registry();
        let owners = rt.image_id(&tag);
        let then = rt.resolve(&tag).await.unwrap();
        assert!(
            rt.holds(&then).await.unwrap(),
            "the engine holds the digest its tag names, by that digest"
        );
        rt.moves_on_pull(tag.clone());
        let now = rt.resolve(&tag).await.unwrap();
        assert_ne!(now, then, "the registry names a newer image by the tag");
        assert!(
            !rt.holds(&now).await.unwrap(),
            "the tag the engine holds is not the registry's digest"
        );
        rt.pull(&now, Arc::new(|_| {})).await.unwrap();
        assert_eq!(
            rt.image_id(&tag),
            owners,
            "the owner's tag still names the owner's image"
        );
        rt.remove_image(&now).await.unwrap();
        assert!(rt.holds(&tag).await.unwrap() && rt.holds(&then).await.unwrap());
    }

    #[tokio::test]
    async fn removing_a_digest_leaves_a_tag_the_owner_pulled_meanwhile_on_its_image() {
        let tag = ImageRef("pytorch/pytorch:latest".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![]).with_open_registry();
        let pinned = rt.resolve(&tag).await.unwrap();
        rt.pull(&pinned, Arc::new(|_| {})).await.unwrap();
        rt.pull(&tag, Arc::new(|_| {})).await.unwrap();
        let owners = rt.image_id(&tag);
        rt.remove_image(&pinned).await.unwrap();
        assert!(rt.holds(&tag).await.unwrap());
        assert_eq!(rt.image_id(&tag), owners);
    }

    #[tokio::test]
    async fn an_image_only_the_host_holds_is_not_found_at_the_registry_as_one_nobody_holds_is() {
        let local = ImageRef("owners/own-build:1".into());
        let rt = Fake::new(vec!["gpu-0".into()], vec![local.clone()]);
        let held = rt.resolve(&local).await.unwrap_err();
        let nowhere = rt.resolve(&ImageRef("owners/no-such:1".into())).await.unwrap_err();
        assert!(matches!(held, RuntimeError::ImageNotFound(ref r) if r == "owners/own-build:1"));
        assert!(matches!(nowhere, RuntimeError::ImageNotFound(ref r) if r == "owners/no-such:1"));
        assert_eq!(
            held.to_string().replace("own-build", "X"),
            nowhere.to_string().replace("no-such", "X"),
            "the same answer, whatever the host holds"
        );
        assert!(rt.pulled().is_empty());
        let guessed = ImageRef("owners/own-build@sha256:anything".into());
        assert!(matches!(
            rt.resolve(&guessed).await,
            Err(RuntimeError::ImageNotFound(_))
        ));
        assert!(matches!(
            rt.pull(&guessed, Arc::new(|_| {})).await,
            Err(RuntimeError::ImageNotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_resolve_a_reference_says_so() {
        assert!(matches!(
            NoNames.resolve(&ImageRef("x:1".into())).await,
            Err(RuntimeError::Engine(_))
        ));
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_bound_a_pull_refuses_one_with_a_bound() {
        let err = NoNames
            .pull_bounded(&ImageRef("x".into()), Arc::new(|_| {}), most(1))
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::Engine(_)));
        let floor = PullLimits {
            most_bytes: None,
            floor_bytes: Some(1),
        };
        let err = NoNames
            .pull_bounded(&ImageRef("x".into()), Arc::new(|_| {}), floor)
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::Engine(_)), "nor one with a floor");
    }

    #[tokio::test]
    async fn the_room_for_images_is_what_a_test_sets_and_none_where_it_cannot_be_told() {
        let rt = fake();
        assert_eq!(rt.image_room().await, Some(1 << 40));
        rt.set_image_room(Some(10 << 30));
        assert_eq!(rt.image_room().await, Some(10 << 30));
        rt.set_image_room(None);
        assert_eq!(rt.image_room().await, None);
        assert_eq!(NoNames.image_room().await, None, "a runtime that cannot tell says none");
        NoNames.remove_image(&ImageRef("x".into())).await.unwrap();
    }

    fn named_spec(name: &str) -> Spec {
        Spec {
            name: Some(name.into()),
            ..spec("ollama/ollama:0.6", "gpu-0")
        }
    }

    #[tokio::test]
    async fn a_container_started_with_a_name_is_found_by_it() {
        let rt = fake();
        let id = rt.start(named_spec("deployment-1")).await.unwrap().id;
        assert_eq!(rt.named("deployment-1").await.unwrap(), Some(id));
    }

    #[tokio::test]
    async fn a_container_started_without_a_name_is_found_by_no_name() {
        let rt = fake();
        rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap();
        assert_eq!(rt.named("").await.unwrap(), None);
        assert_eq!(rt.named("deployment-1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_stopped_container_is_no_longer_found_by_its_name() {
        let rt = fake();
        let id = rt.start(named_spec("deployment-1")).await.unwrap().id;
        rt.stop(&id).await.unwrap();
        assert_eq!(rt.named("deployment-1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_name_started_twice_is_answered_by_the_newest_container() {
        let rt = fake();
        let older = rt.start(named_spec("job-7")).await.unwrap().id;
        let newer = rt.start(named_spec("job-7")).await.unwrap().id;
        assert_eq!(rt.named("job-7").await.unwrap(), Some(newer.clone()));
        rt.stop(&newer).await.unwrap();
        assert_eq!(rt.named("job-7").await.unwrap(), Some(older));
    }

    #[tokio::test]
    async fn two_containers_with_different_names_are_each_found_by_their_own() {
        let rt = fake();
        let a = rt.start(named_spec("deployment-1")).await.unwrap().id;
        let b = rt.start(named_spec("deployment-2")).await.unwrap().id;
        assert_eq!(rt.named("deployment-1").await.unwrap(), Some(a));
        assert_eq!(rt.named("deployment-2").await.unwrap(), Some(b));
    }

    struct NoNames;

    #[async_trait]
    impl Runtime for NoNames {
        async fn pull(&self, _image: &ImageRef, _progress: Progress) -> Result<(), RuntimeError> {
            unimplemented!()
        }
        async fn start(&self, _spec: Spec) -> Result<Started, RuntimeError> {
            unimplemented!()
        }
        async fn stop(&self, _id: &ContainerId) -> Result<(), RuntimeError> {
            unimplemented!()
        }
        async fn running(&self) -> Result<Vec<ContainerId>, RuntimeError> {
            unimplemented!()
        }
        fn events(&self) -> broadcast::Receiver<Event> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_look_a_container_up_by_name_says_so_and_never_answers_none() {
        let err = NoNames.named("deployment-1").await.unwrap_err();
        assert!(matches!(err, RuntimeError::NoName(_)));
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_follow_what_a_container_writes_says_so_and_never_answers_an_empty_feed() {
        let err = NoNames.follow(&ContainerId("c".into())).await.unwrap_err();
        assert!(matches!(err, RuntimeError::NoFollow(_)));
    }

    fn out(text: &str) -> Written {
        Written {
            output: Output::Out,
            bytes: text.as_bytes().to_vec(),
        }
    }

    fn err(text: &str) -> Written {
        Written {
            output: Output::Err,
            bytes: text.as_bytes().to_vec(),
        }
    }

    async fn all_of(mut following: Following) -> Vec<Written> {
        let mut read = Vec::new();
        while let Some(next) = following.recv().await {
            read.push(next.unwrap());
        }
        read
    }

    #[tokio::test]
    async fn a_follower_reads_what_a_container_wrote_from_its_first_byte_in_order_and_ends_with_its_exit() {
        let rt = fake();
        let id = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        rt.write(
            &id,
            Output::Out,
            "loading
",
        )
        .unwrap();
        let following = rt.follow(&id).await.unwrap();
        rt.write(
            &id,
            Output::Err,
            "warning
",
        )
        .unwrap();
        rt.write(
            &id,
            Output::Out,
            "done
",
        )
        .unwrap();
        rt.exit(&id, 0, "done").unwrap();
        assert_eq!(
            all_of(following).await,
            vec![
                out("loading
"),
                err("warning
"),
                out("done
")
            ]
        );
    }

    #[tokio::test]
    async fn every_way_a_container_ends_ends_its_followers() {
        let rt = fake();
        for end in ["stop", "fail", "oom"] {
            let id = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
            let following = rt.follow(&id).await.unwrap();
            rt.write(&id, Output::Out, end).unwrap();
            match end {
                "stop" => rt.stop(&id).await.unwrap(),
                "fail" => rt.fail(&id, "the engine said no").unwrap(),
                _ => rt.out_of_memory(&id).unwrap(),
            }
            assert_eq!(all_of(following).await, vec![out(end)], "{end} ends the follower");
        }
    }

    #[tokio::test]
    async fn a_container_that_has_ended_is_still_read_whole_and_one_never_started_is_refused() {
        let rt = fake();
        let id = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        rt.write(&id, Output::Out, "all of it").unwrap();
        rt.exit(&id, 3, "all of it").unwrap();
        assert_eq!(all_of(rt.follow(&id).await.unwrap()).await, vec![out("all of it")]);
        assert!(matches!(
            rt.write(&id, Output::Out, "late"),
            Err(RuntimeError::NoSuchContainer(_))
        ));
        let never = rt.follow(&ContainerId("fake-99".into())).await.unwrap_err();
        assert!(matches!(never, RuntimeError::NoSuchContainer(_)));
    }

    #[tokio::test]
    async fn two_followers_of_one_container_each_read_all_of_it() {
        let rt = fake();
        let id = rt.start(spec("ollama/ollama:0.6", "gpu-0")).await.unwrap().id;
        let first = rt.follow(&id).await.unwrap();
        rt.write(&id, Output::Out, "a").unwrap();
        let second = rt.follow(&id).await.unwrap();
        rt.write(&id, Output::Err, "b").unwrap();
        rt.stop(&id).await.unwrap();
        assert_eq!(all_of(first).await, vec![out("a"), err("b")]);
        assert_eq!(all_of(second).await, vec![out("a"), err("b")]);
    }
}
