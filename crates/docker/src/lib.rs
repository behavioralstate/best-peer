//! [`Runtime`] over the Docker Engine API through bollard. Every container this adapter creates carries the label
//! `best-peer`, so `running` and the event feed see the peer's containers and nothing else. A device is handed over
//! by the NVIDIA container toolkit when its id is an NVML UUID: a whole card (`GPU-...`) or one MIG instance of a split
//! card (`MIG-...`), which the toolkit hands over alone; other accelerators wait for their own adapter. A mount is a bind the engine refuses when its source is not there. A container is confined as its spec
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
    /// Where jobs' disks are made: each a file system of its own on a loop device, capped at the size asked for.
    disks: Option<std::path::PathBuf>,
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
            disks: None,
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

impl DockerRuntime {
    /// The same engine, making jobs' disks under `dir`.
    pub fn with_disks(mut self, dir: std::path::PathBuf) -> Self {
        self.disks = Some(dir);
        self
    }
}

/// How many `df`s killed past their time have not ended: each counted until its own reaper sees it end, so the room
/// stays unknown, and no other is started, while any is stuck.
static DF_STUCK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Runs `program` with `args`, its failure in its own words.
fn run(program: &str, args: &[&str]) -> Result<(), RuntimeError> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| RuntimeError::NoDisk(format!("{program} could not run: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(RuntimeError::NoDisk(format!(
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
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

    /// A file system of its own for the job `id`: an ext4 file of `bytes`, allocated whole so the room it takes is
    /// taken now, on a loop device mounted under the disks' directory. It has no journal, which a disk that lives as
    /// long as its job does not need, and keeps nothing for root, so the job has all of it. Linux only, and the peer
    /// needs root to mount.
    async fn make_disk(&self, id: &str, bytes: u64) -> Result<std::path::PathBuf, RuntimeError> {
        let Some(dir) = self.disks.clone() else {
            return Err(RuntimeError::NoDisk(
                "this peer makes no disk for a job: it was started without a place for them".into(),
            ));
        };
        if !cfg!(target_os = "linux") {
            return Err(RuntimeError::NoDisk(
                "a job's disk is a file system on a loop device, which this peer makes on Linux only".into(),
            ));
        }
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&dir)
                .map_err(|e| RuntimeError::NoDisk(format!("cannot make {}: {e}", dir.display())))?;
            let image = dir.join(format!("{id}.img"));
            let mount = dir.join(&id);
            std::fs::File::create(&image)
                .map_err(|e| RuntimeError::NoDisk(format!("cannot make {}: {e}", image.display())))?;
            // Allocated, not sparse: the host's free space shrinks now, so two disks are never promised one room.
            run("fallocate", &["-l", &bytes.to_string(), &image.to_string_lossy()])
                .map_err(|e| RuntimeError::NoDisk(format!("no room for a disk of {bytes} bytes: {e}")))?;
            std::fs::create_dir_all(&mount).map_err(|e| RuntimeError::NoDisk(e.to_string()))?;
            let (img, mnt) = (image.to_string_lossy().to_string(), mount.to_string_lossy().to_string());
            run("mkfs.ext4", &["-q", "-F", "-m", "0", "-O", "^has_journal", &img])?;
            run("mount", &["-o", "loop", &img, &mnt]).map_err(|e| {
                RuntimeError::NoDisk(format!("{e}; a job's disk is mounted by the peer, which needs root"))
            })?;
            // Whoever the job's image runs as writes there.
            run("chmod", &["0777", &mnt])?;
            Ok(mount)
        })
        .await
        .map_err(|e| RuntimeError::NoDisk(e.to_string()))?
    }

    async fn remove_disk(&self, id: &str) -> Result<(), RuntimeError> {
        let Some(dir) = self.disks.clone() else {
            return Ok(());
        };
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let mount = dir.join(&id);
            if mount.exists() {
                let _ = run("umount", &[&mount.to_string_lossy()]);
                let _ = std::fs::remove_dir_all(&mount);
            }
            let _ = std::fs::remove_file(dir.join(format!("{id}.img")));
            Ok(())
        })
        .await
        .map_err(|e| RuntimeError::NoDisk(e.to_string()))?
    }

    fn makes_disks(&self) -> bool {
        self.disks.is_some() && cfg!(target_os = "linux")
    }

    fn disks(&self) -> Vec<String> {
        let Some(dir) = self.disks.clone() else {
            return vec![];
        };
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().strip_suffix(".img").map(str::to_string))
            .collect()
    }

    fn disk_at(&self, id: &str) -> Option<std::path::PathBuf> {
        let mount = self.disks.clone()?.join(id);
        // Mounted: its own file system, on another device than the directory it is in. After a reboot it is not.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let (here, above) = (
                std::fs::metadata(&mount).ok()?,
                std::fs::metadata(mount.parent()?).ok()?,
            );
            (here.dev() != above.dev()).then_some(mount)
        }
        #[cfg(not(unix))]
        {
            let _ = mount;
            None
        }
    }

    fn disk_room(&self) -> Option<(u64, u64)> {
        let dir = self.disks.clone()?;
        if !cfg!(target_os = "linux") {
            return None;
        }
        // While a df is stuck in the file system, the room is not known and no other is started: the dfs left behind
        // are those that were already asking when it stopped answering, never one per question after.
        if DF_STUCK.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            return None;
        }
        let failed = |why: String| {
            tracing::warn!(dir = %dir.display(), %why, "the room for jobs' disks could not be read");
            None
        };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return failed(format!("the directory could not be made: {e}"));
        }
        // Asked for ten seconds at most: a file system that does not answer is one with no room known.
        let mut df = match std::process::Command::new("df")
            .args(["-B1", "--output=avail,size", &dir.to_string_lossy()])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(df) => df,
            Err(e) => return failed(format!("df could not run: {e}")),
        };
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match df.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                _ => {
                    // Killed, and left to a thread of its own to reap: one stuck in the file system may never end.
                    let _ = df.kill();
                    DF_STUCK.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let _ = df.wait();
                        DF_STUCK.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    });
                    return failed("df did not answer within ten seconds".into());
                }
            }
        }
        let mut text = String::new();
        let _ = df
            .stdout
            .take()
            .map(|mut out| std::io::Read::read_to_string(&mut out, &mut text));
        let mut numbers = text
            .lines()
            .nth(1)
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|n| n.parse::<u64>().ok());
        match (numbers.next(), numbers.next()) {
            (Some(free), Some(total)) => Some((free, total)),
            _ => failed(format!("df answered what does not read as room: {text:?}")),
        }
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
        let device_requests = spec
            .devices
            .iter()
            .map(|d| handed_over(&d.0))
            .collect::<Result<Vec<_>, _>>()?;
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

/// What the NVIDIA container toolkit is asked for to hand device `id` to a container: a whole card by its `GPU-`
/// UUID, or one MIG instance by its `MIG-` UUID. Any other id is not an NVIDIA device this adapter can hand over.
fn handed_over(id: &str) -> Result<DeviceRequest, RuntimeError> {
    if !(id.starts_with("GPU-") || id.starts_with("MIG-")) {
        return Err(RuntimeError::DeviceUnavailable(format!(
            "{id}: this adapter hands over NVIDIA cards (GPU-...) and MIG instances (MIG-...) only"
        )));
    }
    Ok(DeviceRequest {
        driver: Some("nvidia".into()),
        device_ids: Some(vec![id.to_string()]),
        capabilities: Some(vec![vec!["gpu".into()]]),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_whole_card_and_a_mig_instance_are_handed_over_by_their_uuid_and_nothing_else_is() {
        for id in [
            "GPU-314ff147-b152-3a61-162c-d127e3ec73e8",
            "MIG-9d534ce5-32ef-5865-bac6-a1d9e895ee4a",
        ] {
            let r = handed_over(id).unwrap();
            assert_eq!(r.device_ids, Some(vec![id.to_string()]));
            assert_eq!(r.driver.as_deref(), Some("nvidia"));
        }
        assert!(matches!(handed_over("gpu-0"), Err(RuntimeError::DeviceUnavailable(_))));
    }

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
