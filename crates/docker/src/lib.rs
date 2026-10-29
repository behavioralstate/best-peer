//! [`Runtime`] over the Docker Engine API through bollard. Every container this adapter creates carries the label
//! `best-peer`, so `running` and the event feed see the peer's containers and nothing else. A device is handed over
//! by the NVIDIA container toolkit when its id is an NVML UUID: a whole card (`GPU-...`) or one MIG instance of a split
//! card (`MIG-...`), which the toolkit hands over alone, with the driver's compute and utility capabilities and no
//! other; other accelerators wait for their own adapter. A mount is a bind the engine refuses when its source is not there. A container is confined as its spec
//! says, in the engine's own words: capabilities dropped, no new privileges, a read-only root with a private `/tmp`,
//! ceilings on processes, on memory with swap counted in, on cores and on open files, no core dump, its network, and
//! the box's user over any the image names, with `/tmp` as that user's home;
//! with a read-only root, a volume the image declares is a private tmpfs, never a volume on the host; and the seccomp
//! and AppArmor profiles the engine has, named; and the engine's own copy of what it writes rotated at two files of
//! ten megabytes. What a container writes is followed from its first byte, out and error apart. A container that exits
//! is removed by this adapter once it has read the last lines the container wrote, which the exit then carries, and
//! once whoever follows it has read the rest, ten seconds at most; one whose exit was
//! not heard (the peer was down, or the event feed broke) is removed by a sweep, every minute and after the feed
//! reconnects, once this adapter has seen it exited for a minute, so a peer that shares the engine has read its own
//! first. A container goes with its anonymous volumes, as the engine's own removal on exit took them. An image is
//! removed by the reference it was pulled as, never forced; a reference is resolved to its digest at the registry
//! through the engine's distribution endpoint, pulling nothing, and one pinned by digest is held when the image found
//! by it lists that digest, pulled with no tag made, and removed as that reference alone; and the room for images is read from the file system
//! holding the engine's root directory on this host, found in the mount table when the directory itself cannot be
//! reached, as an engine with user namespaces remapped keeps it; none when the engine is on another host. A pull may be
//! held to limits on that disk: given up, its stream dropped, once the room it took there or the sizes of the layers
//! it downloads pass a bound, or the room left falls under a floor, read every half second while it runs; and an image
//! pulled whole whose unpacked size passes the bound is removed. Thin; proven on a host by hand. What needs no engine
//! is unit-tested: the share and the bytes of a pull over what the engine reports, a pull held to its limits over a
//! stream and readings of the room, the body a container is created from, the host config a confinement becomes, a
//! container's environment, the profiles named from the engine's options, the room free at a directory, and the mount
//! holding it. A job's disk is made, released and removed by the disk helper when the peer has one
//! ([`DockerRuntime::with_disk_helper`], behavioralstate/spec#169), and mounted by the peer itself otherwise; what goes
//! to the helper is unit-tested over a socket that stands in for it, and a disk's layout on a directory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use best_peer_disk::kept_free;
use best_peer_runtime::{
    Confinement, ContainerId, Event, Following, ImageRef, Isolation, Network, Output, Progress, Published, PullLimits,
    RegistryToken, Runtime, RuntimeError, Spec, Started, Written,
};
use bollard::auth::DockerCredentials;
use bollard::container::LogOutput;
use bollard::models::{
    ContainerCreateBody, ContainerTopResponse, CreateImageInfo, DeviceRequest, EventMessageTypeEnum, HostConfig,
    HostConfigLogConfig, Mount, MountType, PortBinding, ResourcesUlimits,
};
use bollard::query_parameters::{
    CreateImageOptionsBuilder, EventsOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, RemoveImageOptionsBuilder, StopContainerOptionsBuilder, TagImageOptionsBuilder,
};
use bollard::Docker;
use futures::StreamExt;
use tokio::sync::broadcast;

const LABEL: &str = "best-peer";
const NAME_LABEL: &str = "best-peer.name";

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
    /// Whether this peer can mount a disk there; one that cannot makes none, and still clears what is left there.
    /// With a disk helper: whether the helper answered at start.
    mounts: bool,
    /// The socket of the disk helper (`best-peer-disk`) that makes, releases and removes jobs' disks for this peer,
    /// when it has one, and its bounds, as it listed them at start.
    helper: Option<std::path::PathBuf>,
    helper_limits: Option<best_peer_disk::Limits>,
    /// Whether the engine runs on this host, so the room for its images can be read here: published ports bound to
    /// loopback, as they are when the peer reaches the engines on this host.
    engine_here: bool,
    /// Who follows each container's output now: a container that ends is removed once they have read it all.
    followers: Arc<Followers>,
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
            mounts: false,
            helper: None,
            helper_limits: None,
            engine_here: engine_is_here(bind_ip),
            followers: Arc::new(Followers::default()),
        };
        sweep(&me.docker, &me.exited).await;
        me.follow_events();
        let (docker, exited) = (me.docker.clone(), me.exited.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                sweep(&docker, &exited).await;
            }
        });
        Ok(me)
    }

    fn follow_events(&self) {
        let docker = self.docker.clone();
        let exited = self.exited.clone();
        let tx = self.tx.clone();
        let followers = self.followers.clone();
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
                            // Removed once its followers have read all it wrote, each exit on its own, so a follower
                            // slow to finish never holds another container's exit.
                            let (docker, tx, followers) = (docker.clone(), tx.clone(), followers.clone());
                            tokio::spawn(async move {
                                followers.drained(&id.0, FOLLOWED_FOR).await;
                                let _ = docker
                                    .remove_container(
                                        &id.0,
                                        Some(RemoveContainerOptionsBuilder::new().force(true).v(true).build()),
                                    )
                                    .await;
                                let _ = tx.send(Event::Exited { id, code, last_words });
                            });
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

/// The longest an exited container waits for its followers to read the rest of what it wrote before it is removed.
const FOLLOWED_FOR: std::time::Duration = std::time::Duration::from_secs(10);

/// What a follower holds unread before the engine's feed waits for it.
const FOLLOWED: usize = 256;

/// What the engine keeps on the host of a container's output, as its `json-file` driver rotates it: a follower reads
/// from there, so one that keeps up reads it all, and a container that writes without end never fills the host's disk.
const KEPT_PER_FILE: &str = "10m";
const KEPT_FILES: &str = "2";

/// The followers of each container's output this adapter has open, so a container that ends is removed only once
/// they have read all it wrote.
#[derive(Default)]
struct Followers {
    open: Mutex<HashMap<String, usize>>,
    changed: tokio::sync::Notify,
}

/// One follower of a container, counted while it is held.
struct Follower {
    followers: Arc<Followers>,
    id: String,
}

impl Followers {
    fn begin(self: &Arc<Self>, id: &str) -> Follower {
        *self.open.lock().unwrap().entry(id.to_string()).or_default() += 1;
        Follower {
            followers: self.clone(),
            id: id.to_string(),
        }
    }

    /// Whether every follower of `id` has finished within `within`; false once it has passed with one still open.
    async fn drained(&self, id: &str, within: std::time::Duration) -> bool {
        let until = tokio::time::Instant::now() + within;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.open.lock().unwrap().contains_key(id) {
                return true;
            }
            if tokio::time::timeout_at(until, changed).await.is_err() {
                return false;
            }
        }
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        let mut open = self.followers.open.lock().unwrap();
        if let Some(n) = open.get_mut(&self.id) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.id);
            }
        }
        drop(open);
        self.followers.changed.notify_waiters();
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
    // Only the end is kept, so a tail of huge lines (a progress bar rewritten for megabytes) is never held whole.
    const HELD: usize = 64 * 1024;
    let mut text = String::new();
    while let Some(Ok(chunk)) = logs.next().await {
        text.push_str(&String::from_utf8_lossy(&chunk.into_bytes()));
        if text.len() > 2 * HELD {
            let cut = (text.len() - HELD..=text.len())
                .find(|i| text.is_char_boundary(*i))
                .unwrap_or(text.len());
            text.drain(..cut);
        }
    }
    let text = text.trim();
    // A screen of text at most, its end kept: the last line is the one that says why.
    let start = text.len().saturating_sub(2000);
    let start = (start..=text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    (!text.is_empty()).then(|| text[start..].to_string())
}

/// The engine's credentials for a request about `image`: none without a credential; with one, its token as a registry
/// token for its registry, refused when the image is pulled from another.
fn credentials_for(
    image: &ImageRef,
    credential: Option<&RegistryToken>,
) -> Result<Option<DockerCredentials>, RuntimeError> {
    let Some(credential) = credential else {
        return Ok(None);
    };
    credential.for_image(image)?;
    Ok(Some(DockerCredentials {
        serveraddress: Some(credential.registry().to_string()),
        registrytoken: Some(credential.token().to_string()),
        ..Default::default()
    }))
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

/// How often a pull held to limits reads the room on the engine's disk while it runs: a layer extracted at disk speed
/// passes a bound by no more than this much of its writing before the pull is given up.
const ROOM_EVERY: std::time::Duration = std::time::Duration::from_millis(500);

/// How long one reading of that room may take: a file system that does not answer has no room known.
const ROOM_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// The room free for anyone on the file system holding the engine's root directory `root`, read off the executor; none
/// when there is no root here or it cannot be read in time.
async fn room_under(root: Option<String>) -> Option<u64> {
    let root = root?;
    let read = tokio::task::spawn_blocking(move || {
        room_at(std::path::Path::new(&root), || {
            std::fs::read_to_string("/proc/self/mountinfo")
        })
        .ok()
    });
    tokio::time::timeout(ROOM_WITHIN, read).await.ok()?.ok()?
}

/// Reads the engine's pull `stream` to its end, telling `progress` the share done, and holds it to `limits`: the
/// `room` free on the engine's disk is read once before the first line and every `every` after, while the first
/// reading said one, and once more when the stream ends, and the layers' sizes the engine says are held to the bound as
/// they come. Returning an error before the end drops the stream, which gives the engine's pull up; a pull past its
/// limits by the reading at its end answers [`Pulled::Past`], since the engine has made its image by then. A floor
/// with no room read at the start is refused before a line is read; a reading that fails later is skipped, said once.
async fn watched<S, R, F>(
    image: &ImageRef,
    mut stream: S,
    progress: &Progress,
    limits: PullLimits,
    mut room: R,
    every: std::time::Duration,
) -> Result<Pulled, RuntimeError>
where
    S: futures::Stream<Item = Result<CreateImageInfo, bollard::errors::Error>> + Unpin,
    R: FnMut() -> F,
    F: std::future::Future<Output = Option<u64>>,
{
    let start = match limits != PullLimits::default() {
        true => room().await,
        false => None,
    };
    match start {
        Some(start) => limits.hold(image, start, start)?,
        None if limits.floor_bytes.is_some() => {
            return Err(RuntimeError::RoomUnknown(format!(
                "{}: the room on the engine's disk cannot be read on this host, so its floor cannot be held",
                image.0
            )))
        }
        None => {}
    }
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut unread = false;
    let mut layers = Layers::default();
    let mut last: Option<u8> = None;
    loop {
        tokio::select! {
            next = stream.next() => {
                let Some(next) = next else { break };
                let info = next.map_err(|e| image_error(image, &e.to_string()))?;
                if let Some(err) = info.error_detail.and_then(|d| d.message) {
                    return Err(image_error(image, &err));
                }
                if let Some(layer) = info.id {
                    let (current, total) = info.progress_detail.map(|p| (p.current, p.total)).unwrap_or_default();
                    layers.report(&layer, info.status.as_deref().unwrap_or_default(), current, total);
                    if let Some(most) = limits.most_bytes.filter(|most| layers.downloads() > *most) {
                        return Err(RuntimeError::TooLarge(format!(
                            "{}: its layers download {} bytes, past its bound of {most}",
                            image.0,
                            layers.downloads()
                        )));
                    }
                }
                let pct = layers.share();
                if pct.is_some() && pct != last {
                    last = pct;
                    progress(pct);
                }
            }
            _ = ticks.tick(), if start.is_some() => {
                match (start, room().await) {
                    (Some(start), Some(now)) => limits.hold(image, start, now)?,
                    _ if !unread => {
                        unread = true;
                        tracing::warn!(image = %image.0, "the room on the engine's disk could not be read during a pull; it is read again at the next tick");
                    }
                    _ => {}
                }
            }
        }
    }
    // A last layer may land between two ticks: the room is read once more now the engine has made the image.
    let Some(start) = start else {
        return Ok(Pulled::Within);
    };
    match room().await {
        Some(now) => Ok(limits
            .hold(image, start, now)
            .map_or_else(Pulled::Past, |()| Pulled::Within)),
        None => {
            tracing::warn!(image = %image.0, "the room on the engine's disk could not be read when the pull ended; it is held to what was read last");
            Ok(Pulled::Within)
        }
    }
}

/// Whether an image pulled whole is past the bound by its unpacked size, `after` its id and size as the engine holds it
/// now: never when it is the very image the engine held before the pull, `before` its id, since nothing of it landed
/// on the disk; an image the engine does not hold after the pull cannot be held to a bound, and is an error.
fn unpacked_past(
    image: &ImageRef,
    limits: PullLimits,
    before: Option<&str>,
    after: Option<(String, u64)>,
) -> Option<RuntimeError> {
    match after {
        Some((id, _)) if before == Some(id.as_str()) => None,
        Some((_, size)) => limits.hold_unpacked(image, size).err(),
        None => Some(RuntimeError::Engine(format!(
            "the engine does not hold {} after pulling it, so its size cannot be held to a bound",
            image.0
        ))),
    }
}

/// Whether an image whose repository digests are `repo_digests` is the one `image` names: always for a reference by
/// tag, which the engine found it by; for one pinned by digest, only when that digest is among them under the same
/// repository, however either spells it ([`ImageRef::canonical_repository`]).
fn lists_digest(image: &ImageRef, repo_digests: &[String]) -> bool {
    let Some(digest) = image.digest() else {
        return true;
    };
    let repository = image.canonical_repository();
    repo_digests.iter().any(|r| {
        let listed = ImageRef(r.clone());
        listed.digest() == Some(digest) && listed.canonical_repository() == repository
    })
}

/// `past` with `note` on what became of the image it made added to its words.
fn noted(past: RuntimeError, note: &str) -> RuntimeError {
    match past {
        RuntimeError::TooLarge(why) => RuntimeError::TooLarge(format!("{why}; {note}")),
        RuntimeError::NoRoom(why) => RuntimeError::NoRoom(format!("{why}; {note}")),
        other => other,
    }
}

/// How a pull held to limits ended once the engine made its image: within them, or past them by the room read at its
/// end, the image then to be undone.
#[derive(Debug)]
enum Pulled {
    Within,
    Past(RuntimeError),
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

    /// The bytes the pull downloads, as far as the engine has said: every layer's size once it is said. A layer the
    /// engine already holds says none and counts nothing.
    fn downloads(&self) -> u64 {
        self.of.values().map(|(size, _, _)| (*size).max(0) as u64).sum()
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
    /// The same engine, making jobs' disks under `dir`, when this peer can mount them: a peer that cannot makes none,
    /// so a job asking for one is refused at admission and no room is ever reserved for a disk that cannot be made.
    /// A Linux peer that cannot says so at start; elsewhere a peer never makes one, and says nothing.
    pub fn with_disks(mut self, dir: std::path::PathBuf) -> Self {
        self.mounts = match can_mount() {
            Ok(()) => true,
            Err(why) => {
                if cfg!(target_os = "linux") {
                    tracing::warn!(dir = %dir.display(), %why, "this peer makes no disk for a job");
                }
                false
            }
        };
        self.disks = Some(dir);
        self
    }
}

impl DockerRuntime {
    /// The same engine, its jobs' disks made, released and removed by the disk helper listening on `socket`
    /// (`best-peer-disk`, behavioralstate/spec#169), in the directory the helper names when it is asked for its
    /// disks now, which this peer reads for where a disk is and the room there, held to the bounds the helper lists
    /// with them: no disk past its `--most-bytes`, and none free while its `--most-disks` are there. A helper that
    /// does not answer then leaves this peer making no disk, as one that cannot mount, and says so at start.
    pub fn with_disk_helper(mut self, socket: std::path::PathBuf) -> Self {
        match ask_helper(&socket, &best_peer_disk::Request::List, HELPER_LISTS_WITHIN) {
            Ok(best_peer_disk::Answer::Listed {
                dir,
                most_bytes,
                most_disks,
                ..
            }) => {
                self.disks = Some(dir);
                self.mounts = true;
                self.helper_limits = Some(best_peer_disk::Limits { most_bytes, most_disks });
            }
            Ok(other) => {
                tracing::warn!(socket = %socket.display(), answer = ?other, "this peer makes no disk for a job: its disk helper did not list its disks");
                self.mounts = false;
            }
            Err(why) => {
                tracing::warn!(socket = %socket.display(), %why, "this peer makes no disk for a job: its disk helper did not answer");
                self.mounts = false;
            }
        }
        self.helper = Some(socket);
        self
    }

    /// Asks this peer's disk helper `request`, off the executor, waiting [`HELPER_WITHIN`] at most.
    async fn ask_disk_helper(
        &self,
        socket: &std::path::Path,
        request: best_peer_disk::Request,
    ) -> Result<best_peer_disk::Answer, RuntimeError> {
        let socket = socket.to_path_buf();
        tokio::task::spawn_blocking(move || ask_helper(&socket, &request, HELPER_WITHIN))
            .await
            .map_err(|e| RuntimeError::NoDisk(e.to_string()))?
    }
}

/// How long the disk helper may take over listing its disks, which reads one directory.
const HELPER_LISTS_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the disk helper may take over a disk: making one formats it, and releasing one walks all a job left.
const HELPER_WITHIN: std::time::Duration = std::time::Duration::from_secs(600);

/// The disk helper's answer to `request`, a refusal included; why there is none, in words that name the helper.
#[cfg(unix)]
fn ask_helper(
    socket: &std::path::Path,
    request: &best_peer_disk::Request,
    within: std::time::Duration,
) -> Result<best_peer_disk::Answer, RuntimeError> {
    best_peer_disk::ask(socket, request, within).map_err(RuntimeError::NoDisk)
}

#[cfg(not(unix))]
fn ask_helper(
    _socket: &std::path::Path,
    _request: &best_peer_disk::Request,
    _within: std::time::Duration,
) -> Result<best_peer_disk::Answer, RuntimeError> {
    Err(RuntimeError::NoDisk(
        "a job's disk is a file system on a loop device, which this peer makes on Linux only".into(),
    ))
}

/// What the disk helper answered other than `expected`: its refusal by name and in its words, or the answer itself.
fn not_answered(answer: best_peer_disk::Answer, expected: &str) -> RuntimeError {
    match answer {
        best_peer_disk::Answer::Refused { code, reason } => {
            RuntimeError::NoDisk(format!("the disk helper refused ({code}): {reason}"))
        }
        other => RuntimeError::NoDisk(format!("the disk helper answered {other:?}, not {expected}")),
    }
}

/// How many disks' images are in `dir`, each `<id>.img` with an id a disk may have.
fn images_in(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".img"))
                .is_some_and(|id| best_peer_disk::valid_id(id).is_ok())
        })
        .count()
}

/// The room for disks in `dir`, as `df` reads it there within ten seconds, less what is kept free.
fn room_for_disks(dir: std::path::PathBuf) -> Option<(u64, u64)> {
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
            Ok(None) if std::time::Instant::now() < until => std::thread::sleep(std::time::Duration::from_millis(20)),
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
    room_in(&text).or_else(|| failed(format!("df answered what does not read as room: {text:?}")))
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
        self.pull_bounded(image, progress, PullLimits::default()).await
    }

    /// Gives the pull up as soon as it passes `limits`, by dropping the engine's stream, which ends the request and,
    /// with it, the engine's pull: the room on the file system holding the engine's root directory is read when the
    /// pull begins, every [`ROOM_EVERY`] while it runs and once more at its end, where it can be read on this host, and
    /// the layers' sizes the engine says are counted as they come. What a pull given up downloaded is the engine's own
    /// to release, and no image is made for it. An image pulled whole and past the limits by the room read at the end,
    /// or by its unpacked size, is undone as [`DockerRuntime::undo_pull`] says, and the pull answers the limit it
    /// passed; the unpacked size of the very image the engine held before the pull is not held to the bound, since
    /// none of it landed on the disk.
    async fn pull_bounded(&self, image: &ImageRef, progress: Progress, limits: PullLimits) -> Result<(), RuntimeError> {
        self.pull_bounded_with(image, progress, limits, None).await
    }

    /// [`DockerRuntime::pull_bounded`], the credential in the pull's `X-Registry-Auth` as a registry token, which the
    /// engine sends the registry as a bearer token, and in nothing else of the pull.
    async fn pull_bounded_with(
        &self,
        image: &ImageRef,
        progress: Progress,
        limits: PullLimits,
        credential: Option<&RegistryToken>,
    ) -> Result<(), RuntimeError> {
        let credentials = credentials_for(image, credential)?;
        if limits == PullLimits::default() {
            return self
                .pull_whole(image, &progress, limits, None, credentials)
                .await
                .map(|_| ());
        }
        let root = match self.engine_here {
            true => self.docker.info().await.ok().and_then(|i| i.docker_root_dir),
            false => None,
        };
        let before = self.image_id_and_size(image).await?.map(|(id, _)| id);
        let past = match self.pull_whole(image, &progress, limits, root, credentials).await? {
            Pulled::Past(e) => Some(e),
            Pulled::Within => match limits.most_bytes {
                None => None,
                Some(_) => unpacked_past(image, limits, before.as_deref(), self.image_id_and_size(image).await?),
            },
        };
        match past {
            Some(e) => Err(self.undo_pull(image, before, e).await),
            None => Ok(()),
        }
    }

    /// A file system of its own for the job `id`: an ext4 file of `bytes`, allocated whole so the room it takes is
    /// taken now, on a loop device mounted under the disks' directory. It has no journal, which a disk that lives as
    /// long as its job does not need, and keeps nothing for root, so the job has all of it. Linux only, and the peer
    /// needs the capability to mount and the loop devices.
    async fn make_disk(&self, id: &str, bytes: u64) -> Result<std::path::PathBuf, RuntimeError> {
        if let Some(socket) = &self.helper {
            if !self.mounts {
                return Err(RuntimeError::NoDisk(
                    "this peer makes no disk for a job: its disk helper did not answer at start, as its log said"
                        .into(),
                ));
            }
            let request = best_peer_disk::Request::Make {
                id: id.to_string(),
                bytes,
            };
            return match self.ask_disk_helper(socket, request).await? {
                best_peer_disk::Answer::Made { path } => Ok(path),
                other => Err(not_answered(other, "made")),
            };
        }
        let Some(dir) = self.disks.clone() else {
            return Err(RuntimeError::NoDisk(
                "this peer makes no disk for a job: it was started without a place for them".into(),
            ));
        };
        if !self.mounts {
            return Err(RuntimeError::NoDisk(
                "this peer makes no disk for a job: it cannot mount one, as its log said at start".into(),
            ));
        }
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
                RuntimeError::NoDisk(format!("{e}; a job's disk is mounted by the peer, which needs the capability to mount (CAP_SYS_ADMIN) and the loop devices"))
            })?;
            lay_out(&mount)?;
            Ok(mount)
        })
        .await
        .map_err(|e| RuntimeError::NoDisk(e.to_string()))?
    }

    async fn remove_disk(&self, id: &str) -> Result<(), RuntimeError> {
        if let Some(socket) = &self.helper {
            let request = best_peer_disk::Request::Remove { id: id.to_string() };
            return match self.ask_disk_helper(socket, request).await? {
                best_peer_disk::Answer::Removed => Ok(()),
                other => Err(not_answered(other, "removed")),
            };
        }
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
        self.disks.is_some() && self.mounts && cfg!(target_os = "linux")
    }

    fn most_disk_bytes(&self) -> Option<u64> {
        self.helper_limits.map(|l| l.most_bytes)
    }

    fn most_disks(&self) -> Option<usize> {
        self.helper_limits.map(|l| l.most_disks)
    }

    /// Through the disk helper when there is one: what the job left under `out/` given to this peer's user. Without
    /// one, this peer mounted the disk itself, and reads what is on it.
    async fn release(&self, id: &str) -> Result<(), RuntimeError> {
        let Some(socket) = &self.helper else {
            return Ok(());
        };
        let request = best_peer_disk::Request::Release { id: id.to_string() };
        match self.ask_disk_helper(socket, request).await? {
            best_peer_disk::Answer::Released => Ok(()),
            other => Err(not_answered(other, "released")),
        }
    }

    fn disks(&self) -> Vec<String> {
        if let Some(socket) = &self.helper {
            return match ask_helper(socket, &best_peer_disk::Request::List, HELPER_LISTS_WITHIN) {
                Ok(best_peer_disk::Answer::Listed { ids, .. }) => ids,
                Ok(other) => {
                    tracing::warn!(error = %not_answered(other, "listed"), "the disk helper did not list its disks");
                    vec![]
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the disk helper did not list its disks");
                    vec![]
                }
            };
        }
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

    /// The images in the disks' directory, read there, so a disk helper is not asked for a count.
    fn disks_made(&self) -> usize {
        self.disks.as_deref().map(images_in).unwrap_or(0)
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

    /// With a disk helper, held to its bounds: no disk past its `--most-bytes`, and none free while its `--most-disks`
    /// are there, counted in its directory.
    fn disk_room(&self) -> Option<(u64, u64)> {
        let dir = self.disks.clone().filter(|_| self.mounts)?;
        let (free, total) = room_for_disks(dir.clone())?;
        let Some(limits) = self.helper_limits else {
            return Some((free, total));
        };
        let free = match images_in(&dir) >= limits.most_disks {
            true => 0,
            false => free.min(limits.most_bytes),
        };
        Some((free, total.min(limits.most_bytes)))
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

    /// The processes of the peer's containers, as the engine's `top` lists them: ids in the engine's own view of
    /// the host, which is the host's for an engine that does not put its containers in a process namespace of its
    /// own. A container gone between the listing and its `top` runs nothing; any other failure is an engine that
    /// cannot tell.
    async fn processes(&self) -> Option<Vec<u32>> {
        let mut pids = Vec::new();
        for id in self.running().await.ok()? {
            match self.docker.top_processes(&id.0, None).await {
                Ok(top) => pids.extend(pids_of(&top)),
                Err(bollard::errors::Error::DockerResponseServerError {
                    status_code: 404 | 409, ..
                }) => {}
                Err(e) => {
                    tracing::warn!(container = %id.0, error = %e, "the container engine did not list a container's processes");
                    return None;
                }
            }
        }
        Some(pids)
    }

    /// Asks the engine's distribution endpoint, which asks the registry for the manifest and pulls nothing. The
    /// request carries no credentials, and neither does a pull's, so a registry that needs them refuses both:
    /// [`DockerRuntime::resolve_with`] and [`DockerRuntime::pull_bounded_with`] carry one. A registry
    /// that refuses or does not know the reference is [`RuntimeError::ImageNotFound`], one that cannot be reached the
    /// engine's words, as a pull's are: neither depends on what the engine holds.
    async fn resolve(&self, image: &ImageRef) -> Result<ImageRef, RuntimeError> {
        self.resolve_with(image, None).await
    }

    /// [`DockerRuntime::resolve`], the credential carried as a pull's is: a registry that refuses it refuses the
    /// reference, [`RuntimeError::ImageNotFound`].
    async fn resolve_with(
        &self,
        image: &ImageRef,
        credential: Option<&RegistryToken>,
    ) -> Result<ImageRef, RuntimeError> {
        let credentials = credentials_for(image, credential)?;
        match self.docker.inspect_registry_image(&image.0, credentials).await {
            Ok(inspected) => match inspected.descriptor.digest {
                Some(digest) => Ok(image.pinned(&digest)),
                None => Err(RuntimeError::Engine(format!(
                    "the registry gave no digest for {}",
                    image.0
                ))),
            },
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 401 | 403 | 404,
                ..
            }) => Err(RuntimeError::ImageNotFound(image.0.clone())),
            Err(e) => Err(image_error(image, &e.to_string())),
        }
    }

    /// By the reference; one pinned by digest is held only when the image the engine finds by it lists that digest
    /// under that repository among its repository digests, whatever its tags. The engine's answer alone: see
    /// [`Runtime::holds`] on resolving first.
    async fn holds(&self, image: &ImageRef) -> Result<bool, RuntimeError> {
        match self.docker.inspect_image(&image.0).await {
            Ok(inspected) => Ok(lists_digest(
                image,
                inspected.repo_digests.as_deref().unwrap_or_default(),
            )),
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(false),
            Err(e) => Err(RuntimeError::Engine(format!(
                "the container engine cannot say whether it holds {}: {e}",
                image.0
            ))),
        }
    }

    async fn remove_image(&self, image: &ImageRef) -> Result<(), RuntimeError> {
        match self
            .docker
            .remove_image(&image.0, Some(RemoveImageOptionsBuilder::new().build()), None)
            .await
        {
            Ok(_) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
            Err(e) => Err(RuntimeError::Engine(format!(
                "the container engine did not remove {}: {e}",
                image.0
            ))),
        }
    }

    /// What the file system holding the engine's root directory, as its `info` names it, has free for anyone, read
    /// on this host: none when the engine does not say, is on another host, its root is not on this host, or neither
    /// the directory nor the mount holding it can be read.
    async fn image_room(&self) -> Option<u64> {
        if !self.engine_here {
            return None;
        }
        let root = self.docker.info().await.ok()?.docker_root_dir?;
        tokio::task::spawn_blocking(move || {
            room_at(std::path::Path::new(&root), || {
                std::fs::read_to_string("/proc/self/mountinfo")
            })
            .inspect_err(|why| tracing::warn!(root = %root, "the room for images is not known: {why}"))
            .ok()
        })
        .await
        .ok()?
    }

    async fn start(&self, spec: Spec) -> Result<Started, RuntimeError> {
        let offered = self.security_options().await;
        let volumes = match spec.confinement.read_only_root {
            true => unmounted(self.volumes_of(&spec.image).await?, &spec.mounts),
            false => Vec::new(),
        };
        let body = create_body(&spec, &self.bind_ip, &volumes, &offered)?;
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
        // The adapter removes it when its exit is heard; one already stopped, or not heard, is removed here, once its
        // followers have read all it wrote.
        self.followers.drained(&id.0, FOLLOWED_FOR).await;
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

    async fn follow(&self, id: &ContainerId) -> Result<Following, RuntimeError> {
        // Counted before the engine is asked, so an exit heard meanwhile already waits for this follower.
        let follower = self.followers.begin(&id.0);
        match self.docker.inspect_container(&id.0, None).await {
            Ok(_) => {}
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                return Err(RuntimeError::NoSuchContainer(id.0.clone()))
            }
            Err(e) => return Err(RuntimeError::Unreachable(e.to_string())),
        }
        let options = LogsOptionsBuilder::new().follow(true).stdout(true).stderr(true).build();
        let mut logs = self.docker.logs(&id.0, Some(options));
        let (tx, rx) = tokio::sync::mpsc::channel(FOLLOWED);
        let gone = id.0.clone();
        tokio::spawn(async move {
            let _follower = follower;
            loop {
                // A caller that drops what it follows ends this at once, even while the container writes nothing,
                // so no abandoned follower holds the engine's feed or the container's removal.
                let next = tokio::select! {
                    next = logs.next() => next,
                    _ = tx.closed() => break,
                };
                let Some(next) = next else { break };
                let read = match next {
                    Ok(LogOutput::StdOut { message }) | Ok(LogOutput::Console { message }) => Ok(Written {
                        output: Output::Out,
                        bytes: message.to_vec(),
                    }),
                    Ok(LogOutput::StdErr { message }) => Ok(Written {
                        output: Output::Err,
                        bytes: message.to_vec(),
                    }),
                    Ok(LogOutput::StdIn { .. }) => continue,
                    // Removed between the look and the feed: gone, as the look itself would have said.
                    Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                        Err(RuntimeError::NoSuchContainer(gone.clone()))
                    }
                    Err(e) => Err(RuntimeError::Engine(format!(
                        "the engine stopped telling what the container writes: {e}"
                    ))),
                };
                let last = read.is_err();
                if tx.send(read).await.is_err() || last {
                    break;
                }
            }
        });
        Ok(rx)
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

    async fn named(&self, name: &str) -> Result<Option<ContainerId>, RuntimeError> {
        let named = format!("{NAME_LABEL}={name}");
        let filters = HashMap::from([("label", vec![LABEL, named.as_str()])]);
        let list = self
            .docker
            .list_containers(Some(ListContainersOptionsBuilder::new().filters(&filters).build()))
            .await
            .map_err(|e| RuntimeError::Unreachable(e.to_string()))?;
        if list.len() > 1 {
            tracing::warn!("more than one running container carries one name; answering the newest");
        }
        Ok(newest(list.into_iter().filter_map(|c| Some((c.id?, c.created)))).map(ContainerId))
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

/// What the engine is asked to create for `spec`: its image, arguments, environment and user, its labels, its devices
/// and published ports bound to `bind_ip`, its mounts, and its box, with the image's declared `volumes` and the
/// engine's `offered` security options as [`confined`] takes them.
fn create_body(
    spec: &Spec,
    bind_ip: &str,
    volumes: &[String],
    offered: &[String],
) -> Result<ContainerCreateBody, RuntimeError> {
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
                    host_ip: Some(bind_ip.to_string()),
                    host_port: Some(String::new()),
                }]),
            )
        })
        .collect();
    Ok(ContainerCreateBody {
        image: Some(spec.image.0.clone()),
        cmd: (!spec.args.is_empty()).then(|| spec.args.clone()),
        env: Some(env_of(spec)),
        // Over the image's own `USER`, which the engine takes only when the body names none.
        user: spec.confinement.user.map(|u| format!("{}:{}", u.uid, u.gid)),
        exposed_ports: Some(spec.ports.iter().map(|p| format!("{p}/tcp")).collect()),
        labels: Some({
            let mut labels = HashMap::from([(LABEL.to_string(), "1".to_string())]);
            if let Some(name) = &spec.name {
                labels.insert(NAME_LABEL.to_string(), name.clone());
            }
            labels
        }),
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
            ..confined(&spec.confinement, volumes, offered)
        }),
        ..Default::default()
    })
}

/// A container's environment: the spec's and, for one handed a device, the NVIDIA driver's compute and utility
/// capabilities alone, in place of any the spec names, which the engine sets over the image's entry of that name: no
/// video codec, display or graphics library of the host's driver is mounted in. A container run as a user of its box
/// has `/tmp` as its home unless the spec names one, since that user's own home in the image is not there or not its
/// to write, and `/tmp` is.
fn env_of(spec: &Spec) -> Vec<String> {
    let mut env: Vec<String> = spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    if spec.confinement.user.is_some() && !spec.env.iter().any(|(k, _)| k == "HOME") {
        env.push("HOME=/tmp".into());
    }
    if !spec.devices.is_empty() {
        env.retain(|e| !e.starts_with("NVIDIA_DRIVER_CAPABILITIES="));
        env.push("NVIDIA_DRIVER_CAPABILITIES=compute,utility".into());
    }
    env
}

/// The image's declared volumes less those the spec mounts a directory over, since the engine refuses a tmpfs and a
/// mount at one path, and the mount covers the volume as it did.
fn unmounted(volumes: Vec<String>, mounts: &[best_peer_runtime::Mount]) -> Vec<String> {
    let same = |a: &str, b: &str| a.trim_end_matches('/') == b.trim_end_matches('/');
    volumes
        .into_iter()
        .filter(|v| !mounts.iter().any(|m| same(&m.container, v)))
        .collect()
}

/// The engine's words for a container's confinement: what it may not do on the host, and how much of the host it may
/// take. No container dumps its memory as a core, which the host's own core handler would write outside it. With a
/// read-only root, each of the image's declared `volumes` is a private tmpfs the size of `/tmp`, counted in its
/// memory as `/tmp` is, so the engine makes no volume on the host for it. The seccomp and AppArmor profiles are
/// named where the engine's `offered` security options say it has them, so no default of the engine's can leave a
/// container without them, and a host without AppArmor still runs.
fn confined(confinement: &Confinement, volumes: &[String], offered: &[String]) -> HostConfig {
    let mut ulimits = Vec::new();
    if let Some(n) = confinement.open_files {
        ulimits.push(ResourcesUlimits {
            name: Some("nofile".into()),
            soft: Some(n as i64),
            hard: Some(n as i64),
        });
    }
    ulimits.push(ResourcesUlimits {
        name: Some("core".into()),
        soft: Some(0),
        hard: Some(0),
    });
    HostConfig {
        cap_drop: confinement.drop_capabilities.then(|| vec!["ALL".into()]),
        security_opt: {
            let mut opts = Vec::new();
            if confinement.no_new_privileges {
                opts.push("no-new-privileges".to_string());
            }
            opts.extend(profiles(offered));
            (!opts.is_empty()).then_some(opts)
        },
        readonly_rootfs: Some(confinement.read_only_root),
        tmpfs: confinement.read_only_root.then(|| {
            std::iter::once("/tmp")
                .chain(volumes.iter().map(String::as_str))
                .map(|path| (path.to_string(), "rw,nosuid,nodev,size=1g".to_string()))
                .collect()
        }),
        pids_limit: confinement.pids.map(|p| p as i64),
        // One ceiling for memory and swap together: a ceiling that swap can exceed is none.
        memory: confinement.memory_bytes.map(|m| m as i64),
        memory_swap: confinement.memory_bytes.map(|m| m as i64),
        nano_cpus: confinement.cpus.map(|c| i64::from(c) * 1_000_000_000),
        ulimits: Some(ulimits),
        network_mode: match &confinement.network {
            Network::None => Some("none".into()),
            Network::Default => None,
        },
        // An init as PID 1 reaps and forwards signals, so a stop reaches an image that did not expect to be it.
        init: Some(true),
        log_config: Some(HostConfigLogConfig {
            typ: Some("json-file".into()),
            config: Some(HashMap::from([
                ("max-size".to_string(), KEPT_PER_FILE.to_string()),
                ("max-file".to_string(), KEPT_FILES.to_string()),
            ])),
        }),
        ..Default::default()
    }
}

/// The profiles a container is given by name among the engine's security options (`name=seccomp,profile=builtin`,
/// `name=apparmor`): its built-in seccomp profile where its info says `builtin`, or `unconfined`, so that an engine
/// set to run its containers unconfined still confines these (an engine too old to know the name and set so refuses
/// the container, which is right: none runs here without the profile); an older engine's default or an engine's own
/// profile file left as it is; and AppArmor's `docker-default` where AppArmor is there.
fn profiles(offered: &[String]) -> Vec<String> {
    let mut named = Vec::new();
    let option = |name: &str| {
        offered.iter().find_map(|o| {
            let mut fields = o.split(',').map(str::trim);
            (fields.next() == Some(name)).then(|| fields.find_map(|f| f.strip_prefix("profile=")))
        })
    };
    if let Some(profile) = option("name=seccomp") {
        if matches!(profile, Some("builtin" | "unconfined")) {
            named.push("seccomp=builtin".to_string());
        }
    }
    if option("name=apparmor").is_some() {
        named.push("apparmor=docker-default".to_string());
    }
    named
}

impl DockerRuntime {
    /// The engine's pull of `image`, read to its end through [`watched`] with the room under the engine's `root`.
    async fn pull_whole(
        &self,
        image: &ImageRef,
        progress: &Progress,
        limits: PullLimits,
        root: Option<String>,
        credentials: Option<DockerCredentials>,
    ) -> Result<Pulled, RuntimeError> {
        let (name, tag) = name_and_tag(image);
        let mut options = CreateImageOptionsBuilder::new().from_image(&name);
        if let Some(tag) = &tag {
            options = options.tag(tag);
        }
        let stream = self.docker.create_image(Some(options.build()), None, credentials);
        watched(image, stream, progress, limits, || room_under(root.clone()), ROOM_EVERY).await
    }

    /// Undoes a pull that made an image past its limits, answering `past` with what became of it. An image the engine
    /// held under `image` before, `before` its id, is the owner's: when the pull left the reference naming that very
    /// image, nothing is touched; when it moved the reference to a new one, the reference is given back to the old
    /// image first and the new one then removed by its id, so the owner's image keeps its name. A reference pinned by
    /// digest, or one the engine will not give back, is left on the new image, which is kept, and the answer says so.
    /// An image the engine did not hold before is removed by the reference.
    async fn undo_pull(&self, image: &ImageRef, before: Option<String>, past: RuntimeError) -> RuntimeError {
        let now = match self.image_id_and_size(image).await {
            Ok(Some((id, _))) => id,
            Ok(None) => return past,
            Err(e) => return noted(past, &format!("it could not be looked up to be removed: {e}")),
        };
        let Some(before) = before else {
            return match self.remove_image(image).await {
                Ok(()) => past,
                Err(e) => noted(past, &format!("it could not be removed and is left on the engine: {e}")),
            };
        };
        if before == now {
            return past;
        }
        let (repo, tag) = name_and_tag(image);
        let Some(tag) = tag else {
            return noted(
                past,
                "the reference is pinned by digest and cannot be given back, so the image is left on the engine",
            );
        };
        let options = TagImageOptionsBuilder::new().repo(&repo).tag(&tag).build();
        if let Err(e) = self.docker.tag_image(&before, Some(options)).await {
            return noted(
                past,
                &format!("the reference could not be given back to the image the engine held before ({e}), so the new image is left on the engine under it"),
            );
        }
        match self.remove_image(&ImageRef(now)).await {
            Ok(()) => past,
            Err(e) => noted(
                past,
                &format!("the reference names the image the engine held before again, and the new image could not be removed: {e}"),
            ),
        }
    }

    /// The id and unpacked size, every layer counted, of the image the engine holds by `image`; none when it holds none.
    async fn image_id_and_size(&self, image: &ImageRef) -> Result<Option<(String, u64)>, RuntimeError> {
        match self.docker.inspect_image(&image.0).await {
            Ok(inspected) => match (inspected.id, inspected.size) {
                (Some(id), Some(size)) => Ok(Some((id, size.max(0) as u64))),
                _ => Err(RuntimeError::Engine(format!(
                    "the engine does not say the id and size of {}, so its size cannot be held to a bound",
                    image.0
                ))),
            },
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
            Err(e) => Err(RuntimeError::Engine(format!(
                "the engine cannot say the size of {}: {e}",
                image.0
            ))),
        }
    }

    /// The engine's security options as its `info` says them; none when it does not answer, so no profile is named
    /// and the engine's own defaults stand.
    async fn security_options(&self) -> Vec<String> {
        match self.docker.info().await {
            Ok(info) => info.security_options.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, "the container engine did not say its security options; its defaults stand for this container");
                Vec::new()
            }
        }
    }

    /// The paths the image declares as volumes, which the engine would otherwise make on the host for each container.
    async fn volumes_of(&self, image: &ImageRef) -> Result<Vec<String>, RuntimeError> {
        match self.docker.inspect_image(&image.0).await {
            Ok(inspected) => Ok(inspected.config.and_then(|c| c.volumes).unwrap_or_default()),
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => {
                Err(RuntimeError::ImageNotFound(image.0.clone()))
            }
            Err(e) => Err(RuntimeError::Engine(format!(
                "the container engine cannot say what volumes {} declares: {e}",
                image.0
            ))),
        }
    }
}

fn newest(listed: impl Iterator<Item = (String, Option<i64>)>) -> Option<String> {
    listed
        .fold(None::<(String, i64)>, |best, (id, created)| {
            let created = created.unwrap_or(0);
            match best {
                Some((_, at)) if at >= created => best,
                _ => Some((id, created)),
            }
        })
        .map(|(id, _)| id)
}

/// The process ids in a container's `top`: the column titled PID, whatever else the engine lists beside it.
fn pids_of(top: &ContainerTopResponse) -> Vec<u32> {
    let Some(column) = top.titles.iter().flatten().position(|t| t == "PID") else {
        return Vec::new();
    };
    top.processes
        .iter()
        .flatten()
        .filter_map(|row| row.get(column)?.parse().ok())
        .collect()
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

/// The bytes free to an unprivileged writer on the file system holding `dir`, or why they cannot be read. Unix only.
fn free_or_why(dir: &std::path::Path) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        let fs = rustix::fs::statvfs(dir)?;
        Ok(fs.f_bavail.saturating_mul(fs.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Whether the engine runs on this host: its published ports are bound to loopback, which the peer chooses only when
/// it reaches the engines here, the socket the client connects through saying nothing of where the engine is.
fn engine_is_here(bind_ip: &str) -> bool {
    bind_ip.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The room free on the file system holding `dir`: read at `dir`, or, when a directory above it is closed to this
/// process, at the mount that holds it in the mount table `mounts` reads, the text of `/proc/self/mountinfo`; why not
/// when `dir` is not there, as an engine's root in a virtual machine is not, or neither it, the table nor that mount
/// can be read.
fn room_at(dir: &std::path::Path, mounts: impl FnOnce() -> std::io::Result<String>) -> Result<u64, String> {
    match free_or_why(dir) {
        Ok(free) => Ok(free),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let mountinfo = mounts().map_err(|e| {
                format!("the engine's root directory is closed to this peer and the mount table cannot be read: {e}")
            })?;
            let mount = mount_holding(&real_as_far_as_reached(dir), &mountinfo)
                .ok_or("the engine's root directory is closed to this peer and no mount in the table holds it")?;
            free_or_why(&mount).map_err(|e| {
                format!(
                    "the engine's root directory is closed to this peer and the mount holding it, {}, cannot be read: {e}",
                    mount.display()
                )
            })
        }
        Err(e) => Err(format!("the engine's root directory cannot be read on this host: {e}")),
    }
}

/// `path` with its links resolved as far down as this process can reach, the rest as written: the mount table names
/// real paths, and a link above a closed directory would otherwise be matched as the path it is not.
fn real_as_far_as_reached(path: &std::path::Path) -> std::path::PathBuf {
    path.ancestors()
        .find_map(|above| {
            let real = std::fs::canonicalize(above).ok()?;
            Some(real.join(path.strip_prefix(above).ok()?))
        })
        .unwrap_or_else(|| path.to_path_buf())
}

/// The mount point in `mountinfo` that holds `path`: the longest one `path` lies under, whole names compared; none
/// when no mount holds it. Where two mounts share a point, the file system read there is the one mounted last.
fn mount_holding(path: &std::path::Path, mountinfo: &str) -> Option<std::path::PathBuf> {
    mountinfo
        .lines()
        .filter_map(|line| line.split(' ').nth(4).map(unescaped))
        .filter(|mount| path.starts_with(mount))
        .fold(None, |held: Option<std::path::PathBuf>, mount| match held {
            Some(h) if h.components().count() > mount.components().count() => Some(h),
            _ => Some(mount),
        })
}

/// A path as the mount table writes it, with a space, a tab, a newline or a backslash as an octal escape (`\040`).
fn unescaped(field: &str) -> std::path::PathBuf {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match octal.and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok()) {
            Some(b) => {
                out.push(b);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    path_of(out)
}

#[cfg(unix)]
fn path_of(bytes: Vec<u8>) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(bytes).into()
}

#[cfg(not(unix))]
fn path_of(bytes: Vec<u8>) -> std::path::PathBuf {
    String::from_utf8_lossy(&bytes).into_owned().into()
}

/// The room for disks in what `df --output=avail,size` answered: what is free and the size, each less what is kept
/// free, so the size is the largest disk that could ever be made there.
fn room_in(df: &str) -> Option<(u64, u64)> {
    let mut numbers = df
        .lines()
        .nth(1)
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|n| n.parse::<u64>().ok());
    let (free, total) = (numbers.next()?, numbers.next()?);
    let kept = kept_free(total);
    Some((free.saturating_sub(kept), total.saturating_sub(kept)))
}

/// Lays a disk this peer mounted out as the helper does: `peer/` and `in/` this peer's, `out/` open to the job.
#[cfg(target_os = "linux")]
fn lay_out(mount: &std::path::Path) -> Result<(), RuntimeError> {
    use rustix::fs::{Mode, OFlags};
    let root = rustix::fs::open(
        mount,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| RuntimeError::NoDisk(format!("{}: {e}", mount.display())))?;
    let me = best_peer_disk::Peer {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
    };
    best_peer_disk::helper::lay_out(std::os::fd::AsFd::as_fd(&root), me)
        .map_err(|e| RuntimeError::NoDisk(format!("the disk at {} cannot be laid out: {e}", mount.display())))
}

#[cfg(not(target_os = "linux"))]
fn lay_out(_mount: &std::path::Path) -> Result<(), RuntimeError> {
    Err(RuntimeError::NoDisk(
        "a job's disk is a file system on a loop device, which this peer makes on Linux only".into(),
    ))
}

/// Whether this process can mount a disk: the capability to mount, and the loop devices to mount one on. Linux only.
fn can_mount() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("a job's disk is a file system on a loop device, which this peer makes on Linux only".into());
    }
    let status =
        std::fs::read_to_string("/proc/self/status").map_err(|e| format!("cannot read its own status: {e}"))?;
    if !may_mount(&status) {
        return Err(
            "it lacks the capability to mount (CAP_SYS_ADMIN), which a peer that is not run as root has not".into(),
        );
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .map(|_| ())
        .map_err(|e| format!("it cannot reach the loop devices (/dev/loop-control: {e})"))
}

/// Whether the effective capabilities in a `/proc/<pid>/status` text hold CAP_SYS_ADMIN.
fn may_mount(status: &str) -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_SYS_ADMIN) != 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_containers_processes_are_read_from_its_pid_column_wherever_it_stands() {
        let top = ContainerTopResponse {
            titles: Some(vec!["UID".into(), "PID".into(), "CMD".into()]),
            processes: Some(vec![
                vec!["root".into(), "4120".into(), "ollama serve".into()],
                vec!["root".into(), "not-a-pid".into(), "sh".into()],
                vec!["root".into(), "4188".into(), "ollama runner".into()],
            ]),
        };
        assert_eq!(pids_of(&top), vec![4120, 4188]);
        let untitled = ContainerTopResponse {
            titles: Some(vec!["UID".into(), "CMD".into()]),
            processes: Some(vec![vec!["root".into(), "sh".into()]]),
        };
        assert!(pids_of(&untitled).is_empty());
    }

    use super::*;
    use std::time::Duration;

    #[test]
    fn a_credential_reaches_the_engine_as_a_registry_token_for_its_registry_alone() {
        let image = ImageRef("registry.example.org/acct/train:1".into());
        let token = RegistryToken::new("registry.example.org", "t0ken");
        assert_eq!(credentials_for(&image, None).unwrap(), None);
        assert_eq!(
            credentials_for(&image, Some(&token)).unwrap(),
            Some(DockerCredentials {
                serveraddress: Some("registry.example.org".into()),
                registrytoken: Some("t0ken".into()),
                ..Default::default()
            })
        );
        let elsewhere = ImageRef("nvidia/cuda:13.0-base".into());
        assert!(matches!(
            credentials_for(&elsewhere, Some(&token)),
            Err(RuntimeError::Engine(_))
        ));
    }

    /// A disk helper on a socket in a temporary directory: each connection's line is kept, and answered as `answers`
    /// says for it. Answers the socket's path, its directory, and the lines it was sent.
    #[cfg(unix)]
    fn helper(
        answers: impl Fn(&str) -> String + Send + 'static,
    ) -> (std::path::PathBuf, std::path::PathBuf, Arc<Mutex<Vec<String>>>) {
        use std::io::{BufRead, Write};
        let dir = std::env::temp_dir().join(format!(
            "best-peer-helper-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("disk.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let asked = Arc::new(Mutex::new(vec![]));
        let kept = asked.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                let mut line = String::new();
                std::io::BufReader::new(&conn).read_line(&mut line).unwrap();
                let line = line.trim_end().to_string();
                let answer = answers(&line);
                kept.lock().unwrap().push(line);
                conn.write_all(format!("{answer}\n").as_bytes()).unwrap();
            }
        });
        (socket, dir, asked)
    }

    /// A runtime that never reaches an engine: enough for what goes to the disk helper alone.
    #[cfg(unix)]
    fn unconnected(socket: &std::path::Path) -> DockerRuntime {
        let (tx, _) = broadcast::channel(1);
        DockerRuntime {
            docker: Docker::connect_with_unix(&socket.to_string_lossy(), 1, bollard::API_DEFAULT_VERSION).unwrap(),
            exited: Arc::new(Mutex::new(Exited::default())),
            bind_ip: "127.0.0.1".into(),
            tx,
            disks: None,
            mounts: false,
            helper: None,
            helper_limits: None,
            engine_here: true,
            followers: Arc::new(Followers::default()),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn with_a_disk_helper_a_jobs_disk_is_made_released_listed_and_removed_by_it_in_the_directory_it_names() {
        let (socket, dir, asked) = helper(|line| {
            let request: serde_json::Value = serde_json::from_str(line).unwrap();
            match request["request"].as_str().unwrap() {
                "list" => r#"{"answer":"listed","dir":"/var/lib/best-peer-disk","ids":["job-0123456789ab"],"most_bytes":1099511627776,"most_disks":16}"#.into(),
                "make" if request["bytes"] == 1u64 << 40 => {
                    r#"{"answer":"refused","code":"too_large","reason":"past --most-bytes"}"#.into()
                }
                "make" => format!(
                    r#"{{"answer":"made","path":"/var/lib/best-peer-disk/{}"}}"#,
                    request["id"].as_str().unwrap()
                ),
                "release" => r#"{"answer":"released"}"#.into(),
                "remove" => r#"{"answer":"removed"}"#.into(),
                _ => unreachable!(),
            }
        });
        let rt = unconnected(&socket)
            .with_disks(dir.join("unused"))
            .with_disk_helper(socket.clone());
        assert!(rt.makes_disks());
        assert_eq!(
            rt.disks,
            Some("/var/lib/best-peer-disk".into()),
            "the helper's directory"
        );
        assert_eq!((rt.most_disk_bytes(), rt.most_disks()), (Some(1 << 40), Some(16)));
        assert_eq!(
            rt.make_disk("job-0123456789ab", 1 << 30).await.unwrap(),
            std::path::PathBuf::from("/var/lib/best-peer-disk/job-0123456789ab")
        );
        let refused = rt.make_disk("job-ffffffffffff", 1 << 40).await.unwrap_err();
        assert!(
            matches!(&refused, RuntimeError::NoDisk(why) if why.contains("too_large") && why.contains("past --most-bytes")),
            "{refused:?}"
        );
        rt.release("job-0123456789ab").await.unwrap();
        assert_eq!(rt.disks(), ["job-0123456789ab"]);
        rt.remove_disk("job-0123456789ab").await.unwrap();
        assert_eq!(
            *asked.lock().unwrap(),
            [
                r#"{"request":"list"}"#,
                r#"{"request":"make","id":"job-0123456789ab","bytes":1073741824}"#,
                r#"{"request":"make","id":"job-ffffffffffff","bytes":1099511627776}"#,
                r#"{"request":"release","id":"job-0123456789ab"}"#,
                r#"{"request":"list"}"#,
                r#"{"request":"remove","id":"job-0123456789ab"}"#,
            ]
        );
        assert!(
            !dir.join("unused").exists(),
            "nothing is made where the peer would mount"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_disk_helper_that_does_not_answer_at_start_leaves_the_peer_making_no_disk() {
        let (socket, dir, _) = helper(|_| "not an answer".into());
        let rt = unconnected(&socket).with_disk_helper(socket.clone());
        assert!(!rt.makes_disks());
        let refused = rt.make_disk("job-0123456789ab", 1 << 30).await.unwrap_err();
        assert!(
            matches!(&refused, RuntimeError::NoDisk(why) if why.contains("disk helper")),
            "{refused:?}"
        );
        let gone = unconnected(&socket).with_disk_helper(dir.join("none.sock"));
        assert!(!gone.makes_disks());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn with_a_disk_helper_the_room_for_disks_is_held_to_its_most_bytes_and_none_is_free_at_its_most_disks() {
        let disks = std::env::temp_dir().join(format!("best-peer-helper-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&disks);
        std::fs::create_dir_all(&disks).unwrap();
        let listed = disks.clone();
        let (socket, dir, _) = helper(move |_| {
            format!(
                r#"{{"answer":"listed","dir":"{}","ids":[],"most_bytes":16777216,"most_disks":2}}"#,
                listed.display()
            )
        });
        let rt = unconnected(&socket).with_disk_helper(socket.clone());
        let (free, total) = rt.disk_room().expect("the room is read in the helper's directory");
        assert_eq!(
            (free, total),
            (16 << 20, 16 << 20),
            "no disk past --most-bytes is promised"
        );
        std::fs::write(disks.join("job-0123456789ab.img"), "").unwrap();
        assert_eq!(rt.disk_room().unwrap().0, 16 << 20);
        std::fs::write(disks.join("job-ffffffffffff.img"), "").unwrap();
        std::fs::write(disks.join("Notes.img"), "").unwrap();
        assert_eq!(
            rt.disk_room().unwrap(),
            (0, 16 << 20),
            "none is free while --most-disks are there"
        );
        assert_eq!(rt.disks_made(), 2, "counted in the directory, the helper not asked");
        assert_eq!(
            unconnected(&socket).most_disk_bytes(),
            None,
            "without a helper, no bound but the room"
        );
        std::fs::remove_dir_all(&disks).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn without_a_disk_helper_there_is_nothing_to_release() {
        let socket = std::env::temp_dir();
        unconnected(&socket).release("job-0123456789ab").await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_disk_this_peer_mounted_is_laid_out_as_the_helper_lays_one_out() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("best-peer-lay-out-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        lay_out(&root).unwrap();
        let mode = |p: &str| std::fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(""), mode("peer"), mode("in"), mode("out")),
            (0o755, 0o700, 0o755, 0o777)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_disk_is_never_promised_the_last_of_its_file_system() {
        assert_eq!(kept_free(10 << 30), 1 << 30, "a small one keeps 1 GiB");
        assert_eq!(
            kept_free(60 << 30),
            3 << 30,
            "the host's 60 GiB volume keeps a twentieth"
        );
        assert_eq!(kept_free(0), 1 << 30);
        let df = |free: u64, total: u64| format!("    Avail     1B-blocks\n{free:>9} {total:>13}\n");
        assert_eq!(room_in(&df(50 << 30, 60 << 30)), Some((47 << 30, 57 << 30)));
        assert_eq!(
            room_in(&df(2 << 30, 60 << 30)),
            Some((0, 57 << 30)),
            "nothing past the kept room"
        );
        assert_eq!(room_in(&df(0, 0)), Some((0, 0)));
        assert_eq!(room_in("Avail 1B-blocks\n"), None);
    }

    #[test]
    fn the_room_free_is_read_from_the_file_system_holding_a_directory_and_none_where_there_is_none() {
        #[cfg(unix)]
        assert!(free_or_why(&std::env::temp_dir()).ok().is_some_and(|free| free > 0));
        #[cfg(not(unix))]
        assert_eq!(
            free_or_why(&std::env::temp_dir()).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::Unsupported),
            "read on unix alone: elsewhere the room is not known, never guessed"
        );
        assert_eq!(
            free_or_why(std::path::Path::new("/no/such/directory/anywhere")).ok(),
            None
        );
    }

    fn mountinfo(points: &[&str]) -> String {
        points
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{} 1 8:2 / {p} rw,relatime shared:1 - ext4 /dev/sda2 rw\n", 20 + i))
            .collect()
    }

    #[test]
    fn the_mount_holding_a_path_is_the_longest_it_lies_under_by_whole_names() {
        let p = std::path::Path::new;
        let table = mountinfo(&["/", "/var", "/var/lib/docker", "/home"]);
        assert_eq!(
            mount_holding(p("/var/lib/docker/100000.100000"), &table),
            Some(p("/var/lib/docker").into())
        );
        assert_eq!(
            mount_holding(p("/var/lib/docker"), &table),
            Some(p("/var/lib/docker").into())
        );
        assert_eq!(mount_holding(p("/var/lib/docker2/x"), &table), Some(p("/var").into()));
        assert_eq!(mount_holding(p("/srv/x"), &table), Some(p("/").into()));
        assert_eq!(mount_holding(p("relative/x"), &table), None);
        assert_eq!(mount_holding(p("/var/x"), ""), None);
    }

    #[test]
    fn a_mount_point_with_an_escaped_space_tab_newline_or_backslash_is_read_as_its_name() {
        let p = std::path::Path::new;
        assert_eq!(unescaped(r"/mnt/my\040disk"), p("/mnt/my disk"));
        assert_eq!(unescaped(r"/a\011b\012c\134d"), p("/a\tb\nc\\d"));
        assert_eq!(unescaped(r"/plain\0"), p(r"/plain\0"));
        assert_eq!(unescaped(r"/not\089"), p(r"/not\089"));
        let table = mountinfo(&["/", r"/mnt/my\040disk"]);
        assert_eq!(
            mount_holding(p("/mnt/my disk/images"), &table),
            Some(p("/mnt/my disk").into())
        );
    }

    #[test]
    fn only_an_engine_whose_ports_are_bound_to_loopback_is_on_this_host() {
        assert!(engine_is_here("127.0.0.1"));
        assert!(engine_is_here("::1"));
        assert!(!engine_is_here("0.0.0.0"));
        assert!(!engine_is_here("10.0.0.5"));
        assert!(!engine_is_here("not an address"));
    }

    #[cfg(unix)]
    #[test]
    fn the_room_under_a_directory_closed_to_this_process_is_read_at_the_mount_holding_it_and_none_when_that_is_closed_too(
    ) {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("best-peer-room-{}", std::process::id()));
        let inner = base.join("closed").join("root");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::set_permissions(base.join("closed"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let closed_to_us = free_or_why(&inner).ok().is_none();
        let table = mountinfo(&["/", base.to_str().unwrap()]);
        let room = room_at(&inner, || Ok(table)).ok();
        let open = free_or_why(&base).ok();
        let unreachable = room_at(&inner.join("deeper"), || Ok(mountinfo(&["/", inner.to_str().unwrap()])));
        let unmounted = room_at(&inner, || Ok(String::new()));
        let untold = room_at(&inner, || Err(std::io::ErrorKind::NotFound.into()));
        std::fs::set_permissions(base.join("closed"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
        let (room, open) = (room.unwrap(), open.unwrap());
        assert!(
            room.abs_diff(open) < 1 << 30,
            "{room} read under the closed directory, {open} at its mount"
        );
        if closed_to_us {
            assert!(unreachable.unwrap_err().contains("the mount holding it"));
            assert!(unmounted.unwrap_err().contains("no mount in the table holds it"));
            assert!(untold.unwrap_err().contains("the mount table cannot be read"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_above_a_closed_directory_is_resolved_before_the_mount_table_is_read() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("best-peer-link-{}", std::process::id()));
        let real = base.join("real");
        std::fs::create_dir_all(real.join("closed").join("root")).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        std::fs::set_permissions(real.join("closed"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let through_link = base.join("link").join("closed").join("root");
        let resolved = real_as_far_as_reached(&through_link);
        let real_mount = std::fs::canonicalize(&real).unwrap();
        let room = room_at(&through_link, || Ok(mountinfo(&[real_mount.to_str().unwrap()]))).ok();
        let closed_to_us = free_or_why(&through_link).ok().is_none();
        std::fs::set_permissions(real.join("closed"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(resolved, real_mount.join("closed").join("root"));
        if closed_to_us {
            assert!(room.is_some_and(|free| free > 0));
        }
    }

    #[test]
    fn a_root_directory_not_on_this_host_has_no_room_here_whatever_the_mount_table_holds() {
        let missing = std::path::Path::new("/no/such/directory/anywhere");
        assert!(room_at(missing, || Ok(mountinfo(&["/"])))
            .unwrap_err()
            .contains("cannot be read on this host"));
    }

    #[test]
    fn a_peer_mounts_only_with_the_capability_to() {
        let status = |caps: &str| {
            format!("Name:\tbest-peer\nCapInh:\t0000000000000000\nCapEff:\t{caps}\nCapBnd:\t000001ffffffffff\n")
        };
        assert!(may_mount(&status("000001ffffffffff")), "root");
        assert!(may_mount(&status("0000000000200000")), "CAP_SYS_ADMIN alone");
        assert!(
            !may_mount(&status("0000000000000000")),
            "a user, or a unit with no capabilities"
        );
        assert!(!may_mount(&status("00000000001fffff")), "every capability below it");
        assert!(!may_mount("Name:\tbest-peer\n"), "no line, no capability");
        assert!(!may_mount(&status("not hex")));
    }

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

    /// An engine's pull stream: `lines`, one a second, then nothing more, as a pull still extracting says nothing for a
    /// while. It says whether it was read, and whether it was dropped, which is how the engine's pull is given up.
    struct Pulling {
        lines: std::pin::Pin<Box<dyn futures::Stream<Item = Result<CreateImageInfo, bollard::errors::Error>> + Send>>,
        read: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl futures::Stream for Pulling {
        type Item = Result<CreateImageInfo, bollard::errors::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.read.store(true, std::sync::atomic::Ordering::SeqCst);
            self.lines.as_mut().poll_next(cx)
        }
    }

    impl Drop for Pulling {
        fn drop(&mut self) {
            self.dropped.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn pulling(lines: Vec<CreateImageInfo>, ends: bool) -> Pulling {
        let lines = futures::stream::iter(lines).then(|line| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(line)
        });
        let rest = match ends {
            true => futures::stream::empty().boxed(),
            false => futures::stream::pending().boxed(),
        };
        Pulling {
            lines: lines.chain(rest).boxed(),
            read: Arc::default(),
            dropped: Arc::default(),
        }
    }

    fn line(layer: &str, status: &str, current: i64, total: i64) -> CreateImageInfo {
        CreateImageInfo {
            id: Some(layer.into()),
            status: Some(status.into()),
            progress_detail: Some(bollard::models::ProgressDetail {
                current: Some(current),
                total: Some(total),
            }),
            ..Default::default()
        }
    }

    /// A small layer extracting a little more each second, its compressed size far under any bound.
    fn extracting() -> Vec<CreateImageInfo> {
        (1..=30).map(|n| line("a", "Extracting", n, 100)).collect()
    }

    /// The room free on the engine's disk, one reading per call, in order, the last for ever after.
    fn readings(free: &[Option<u64>]) -> (impl FnMut() -> std::future::Ready<Option<u64>>, Arc<Mutex<usize>>) {
        let (free, asked) = (free.to_vec(), Arc::new(Mutex::new(0)));
        let count = asked.clone();
        let room = move || {
            let mut n = count.lock().unwrap();
            *n += 1;
            std::future::ready(free[(*n - 1).min(free.len() - 1)])
        };
        (room, asked)
    }

    const GIB: u64 = 1 << 30;

    fn limits(most: Option<u64>, floor: Option<u64>) -> PullLimits {
        PullLimits {
            most_bytes: most,
            floor_bytes: floor,
        }
    }

    fn told() -> (Progress, Arc<Mutex<Vec<Option<u8>>>>) {
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = told.clone();
        (Arc::new(move |p| sink.lock().unwrap().push(p)), told)
    }

    #[tokio::test(start_paused = true)]
    async fn a_pull_whose_room_taken_on_disk_passes_its_bound_is_given_up_by_dropping_the_engines_stream() {
        let image = ImageRef("big/unpacks:1".into());
        let stream = pulling(extracting(), false);
        let dropped = stream.dropped.clone();
        let (room, _) = readings(&[Some(100 * GIB), Some(90 * GIB), Some(80 * GIB), Some(70 * GIB)]);
        let (progress, said) = told();
        let err = watched(
            &image,
            stream,
            &progress,
            limits(Some(25 * GIB), None),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RuntimeError::TooLarge(ref why) if why.contains("took") && why.contains("bound")),
            "{err}"
        );
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the engine's stream is let go"
        );
        assert!(!said.lock().unwrap().is_empty(), "its share was told while it ran");
    }

    #[tokio::test(start_paused = true)]
    async fn a_pull_that_brings_the_engines_disk_under_its_floor_is_given_up() {
        let image = ImageRef("big/unpacks:1".into());
        let stream = pulling(extracting(), false);
        let dropped = stream.dropped.clone();
        let (room, _) = readings(&[Some(100 * GIB), Some(95 * GIB), Some(89 * GIB)]);
        let (progress, _) = told();
        let err = watched(
            &image,
            stream,
            &progress,
            limits(Some(50 * GIB), Some(90 * GIB)),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RuntimeError::NoRoom(ref why) if why.contains("floor")),
            "{err}"
        );
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reading_of_the_room_that_fails_midway_is_skipped_and_the_next_still_gives_the_pull_up() {
        let image = ImageRef("big/unpacks:1".into());
        let (room, _) = readings(&[Some(100 * GIB), None, Some(70 * GIB)]);
        let (progress, _) = told();
        let err = watched(
            &image,
            pulling(extracting(), false),
            &progress,
            limits(Some(25 * GIB), None),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RuntimeError::TooLarge(_)), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_floor_with_no_room_read_at_the_start_is_refused_before_the_engine_is_read() {
        let image = ImageRef("any/image:1".into());
        let stream = pulling(extracting(), true);
        let read = stream.read.clone();
        let (room, _) = readings(&[None]);
        let (progress, _) = told();
        let err = watched(
            &image,
            stream,
            &progress,
            limits(None, Some(GIB)),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RuntimeError::RoomUnknown(ref why) if why.contains("cannot be read")),
            "{err}"
        );
        assert!(
            !read.load(std::sync::atomic::Ordering::SeqCst),
            "nothing of the pull is read"
        );
        let (room, _) = readings(&[Some(GIB - 1)]);
        let err = watched(
            &image,
            pulling(extracting(), true),
            &progress,
            limits(None, Some(GIB)),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RuntimeError::NoRoom(_)),
            "a disk under the floor at the start"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_bound_with_no_room_read_still_holds_the_layers_sizes_and_the_pull_ends_when_the_engine_does() {
        let image = ImageRef("any/image:1".into());
        let (room, asked) = readings(&[None]);
        let (progress, said) = told();
        watched(
            &image,
            pulling(extracting(), true),
            &progress,
            limits(Some(GIB), None),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(*asked.lock().unwrap(), 1, "no room at the start, none read after");
        assert_eq!(said.lock().unwrap().last(), Some(&Some(65)));
        let (room, _) = readings(&[None]);
        let big = vec![line("a", "Downloading", 1, 2 * GIB as i64)];
        let err = watched(
            &image,
            pulling(big, false),
            &progress,
            limits(Some(GIB), None),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, RuntimeError::TooLarge(ref why) if why.contains("download")),
            "{err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_last_layer_landing_between_two_readings_is_held_to_one_more_when_the_pull_ends() {
        let image = ImageRef("big/unpacks:1".into());
        let short = || vec![line("a", "Extracting", 50, 100), line("a", "Pull complete", 100, 100)];
        let every = Duration::from_secs(60);
        let (progress, _) = told();
        let (room, asked) = readings(&[Some(100 * GIB), Some(85 * GIB)]);
        let ended = watched(
            &image,
            pulling(short(), true),
            &progress,
            limits(Some(50 * GIB), Some(90 * GIB)),
            room,
            every,
        )
        .await
        .unwrap();
        assert!(
            matches!(ended, Pulled::Past(RuntimeError::NoRoom(ref why)) if why.contains("floor")),
            "{ended:?}"
        );
        assert_eq!(
            *asked.lock().unwrap(),
            2,
            "read at the start and at the end, no tick between"
        );
        let (room, _) = readings(&[Some(100 * GIB), Some(70 * GIB)]);
        let ended = watched(
            &image,
            pulling(short(), true),
            &progress,
            limits(Some(25 * GIB), None),
            room,
            every,
        )
        .await
        .unwrap();
        assert!(
            matches!(ended, Pulled::Past(RuntimeError::TooLarge(ref why)) if why.contains("took")),
            "{ended:?}"
        );
        let (room, _) = readings(&[Some(100 * GIB), Some(95 * GIB)]);
        let ended = watched(
            &image,
            pulling(short(), true),
            &progress,
            limits(Some(25 * GIB), Some(90 * GIB)),
            room,
            every,
        )
        .await
        .unwrap();
        assert!(matches!(ended, Pulled::Within), "{ended:?}");
    }

    #[test]
    fn the_image_the_engine_held_before_its_pull_is_not_held_to_the_bound_by_its_unpacked_size() {
        let image = ImageRef("nvidia/cuda:12.8.0-base-ubuntu24.04".into());
        let bound = limits(Some(25 * GIB), None);
        assert!(
            unpacked_past(&image, bound, Some("sha256:a"), Some(("sha256:a".into(), 30 * GIB))).is_none(),
            "the owner's own image, unmoved, lands nothing"
        );
        assert!(matches!(
            unpacked_past(&image, bound, Some("sha256:a"), Some(("sha256:b".into(), 30 * GIB))),
            Some(RuntimeError::TooLarge(_))
        ));
        assert!(matches!(
            unpacked_past(&image, bound, None, Some(("sha256:b".into(), 30 * GIB))),
            Some(RuntimeError::TooLarge(_))
        ));
        assert!(unpacked_past(&image, bound, None, Some(("sha256:b".into(), 25 * GIB))).is_none());
        assert!(matches!(
            unpacked_past(&image, bound, Some("sha256:a"), None),
            Some(RuntimeError::Engine(_))
        ));
    }

    #[test]
    fn an_image_is_held_by_a_digest_only_when_its_repository_digests_list_it() {
        let pinned = ImageRef("nvidia/cuda@sha256:aaa".into());
        assert!(lists_digest(&pinned, &["nvidia/cuda@sha256:aaa".into()]));
        assert!(lists_digest(&pinned, &["docker.io/nvidia/cuda@sha256:aaa".into()]));
        assert!(!lists_digest(&pinned, &["nvidia/cuda@sha256:bbb".into()]));
        assert!(!lists_digest(&pinned, &[]), "a local build lists no digest");
        assert!(lists_digest(
            &ImageRef("busybox@sha256:aaa".into()),
            &["docker.io/library/busybox@sha256:aaa".into()]
        ));
        assert!(
            !lists_digest(
                &ImageRef("owners/own-build@sha256:aaa".into()),
                &["private/other@sha256:aaa".into()]
            ),
            "the digest under another repository is not this one"
        );
        assert!(!lists_digest(&pinned, &["ghcr.io/nvidia/cuda@sha256:aaa".into()]));
        assert!(lists_digest(&ImageRef("nvidia/cuda:12".into()), &[]));
    }

    #[test]
    fn a_reference_pinned_by_digest_is_pulled_whole_and_with_no_tag() {
        assert_eq!(
            name_and_tag(&ImageRef("nvidia/cuda@sha256:aaa".into())),
            ("nvidia/cuda@sha256:aaa".to_string(), None)
        );
    }

    #[test]
    fn what_became_of_an_image_past_its_limits_is_added_to_the_limits_words() {
        let noted = noted(
            RuntimeError::TooLarge("x: past its bound".into()),
            "it is left on the engine",
        );
        assert!(
            matches!(noted, RuntimeError::TooLarge(ref why) if why == "x: past its bound; it is left on the engine")
        );
        assert!(matches!(
            super::noted(RuntimeError::NoRoom("x".into()), "kept"),
            RuntimeError::NoRoom(ref why) if why == "x; kept"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pull_with_no_limits_never_reads_the_room() {
        let (room, asked) = readings(&[Some(0)]);
        let (progress, _) = told();
        watched(
            &ImageRef("any/image:1".into()),
            pulling(extracting(), true),
            &progress,
            PullLimits::default(),
            room,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(*asked.lock().unwrap(), 0);
    }

    #[test]
    fn what_a_pull_downloads_is_its_layers_sizes_as_they_appear_and_nothing_for_a_layer_held() {
        let mut l = Layers::default();
        l.report("held", "Already exists", None, None);
        assert_eq!(l.downloads(), 0);
        l.report("a", "Downloading", Some(10), Some(300));
        assert_eq!(l.downloads(), 300, "a layer's whole size as soon as it is said");
        l.report("b", "Downloading", Some(0), Some(700));
        l.report("a", "Extracting", Some(300), Some(300));
        assert_eq!(l.downloads(), 1000, "extraction counts nothing more");
    }

    #[test]
    fn a_layer_the_engine_already_holds_counts_for_nothing_and_takes_nothing_away() {
        let mut l = Layers::default();
        l.report("held", "Already exists", None, None);
        l.report("new", "Downloading", Some(10), Some(100));
        assert_eq!(l.share(), Some(5));
    }

    #[test]
    fn what_the_engine_keeps_of_a_containers_output_on_the_host_is_bounded_whatever_its_box() {
        for confinement in [Confinement::default(), Confinement::serving()] {
            let kept = confined(&confinement, &[], &[]).log_config.unwrap();
            assert_eq!(kept.typ.as_deref(), Some("json-file"));
            let config = kept.config.unwrap();
            assert_eq!(config.get("max-size").map(String::as_str), Some("10m"));
            assert_eq!(config.get("max-file").map(String::as_str), Some("2"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_container_with_no_follower_is_removed_at_once() {
        let followers = Arc::new(Followers::default());
        assert!(followers.drained("c-1", Duration::from_secs(10)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_container_is_removed_once_its_last_follower_has_read_it_all() {
        let followers = Arc::new(Followers::default());
        let first = followers.begin("c-1");
        let second = followers.begin("c-1");
        let other = followers.begin("c-2");
        let waiting = tokio::spawn({
            let followers = followers.clone();
            async move { followers.drained("c-1", Duration::from_secs(10)).await }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(first);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!waiting.is_finished(), "one follower still reads");
        drop(second);
        assert!(
            waiting.await.unwrap(),
            "drained once the last follower of c-1 is done, whatever c-2's does"
        );
        drop(other);
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_that_never_finishes_holds_a_container_only_for_the_bound() {
        let followers = Arc::new(Followers::default());
        let _stuck = followers.begin("c-1");
        let started = tokio::time::Instant::now();
        assert!(!followers.drained("c-1", Duration::from_secs(10)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    #[test]
    fn a_containers_cores_and_open_files_are_held_to_its_box_and_it_dumps_no_core() {
        let boxed = Confinement {
            cpus: Some(8),
            open_files: Some(65536),
            ..Confinement::default()
        };
        let h = confined(&boxed, &[], &[]);
        assert_eq!(h.nano_cpus, Some(8_000_000_000));
        let limit = |name: &str| {
            h.ulimits
                .iter()
                .flatten()
                .find(|u| u.name.as_deref() == Some(name))
                .map(|u| (u.soft, u.hard))
        };
        assert_eq!(limit("nofile"), Some((Some(65536), Some(65536))));
        assert_eq!(limit("core"), Some((Some(0), Some(0))));
        let open = confined(&Confinement::serving(), &[], &[]);
        assert_eq!(open.nano_cpus, None, "no ceiling on an engine's cores");
        assert_eq!(
            open.ulimits
                .iter()
                .flatten()
                .map(|u| u.name.clone())
                .collect::<Vec<_>>(),
            vec![Some("core".to_string())],
            "no core dump from any container"
        );
    }

    #[test]
    fn a_volume_the_image_declares_is_a_small_private_tmpfs_in_the_box_and_no_volume_of_the_host() {
        let volumes = ["/data".to_string(), "/root/.cache".to_string()];
        let tmpfs = confined(&Confinement::default(), &volumes, &[]).tmpfs.unwrap();
        for path in ["/tmp", "/data", "/root/.cache"] {
            assert_eq!(
                tmpfs.get(path).map(String::as_str),
                Some("rw,nosuid,nodev,size=1g"),
                "{path}"
            );
        }
        assert_eq!(tmpfs.len(), 3);
        assert_eq!(
            confined(&Confinement::serving(), &volumes, &[]).tmpfs,
            None,
            "an engine with a writable root keeps its volumes"
        );
    }

    #[test]
    fn a_volume_the_spec_mounts_a_directory_over_is_that_mount_and_no_tmpfs() {
        let mount = |container: &str| best_peer_runtime::Mount {
            host: format!("/disks/x{container}"),
            container: container.into(),
            read_only: false,
        };
        let volumes = vec!["/in".to_string(), "/out/".to_string(), "/data".to_string()];
        assert_eq!(
            unmounted(volumes, &[mount("/in"), mount("/out")]),
            vec!["/data".to_string()],
            "a mount covers the volume as it did, and the engine refuses both at one path"
        );
        assert_eq!(unmounted(vec!["/data".to_string()], &[]), vec!["/data".to_string()]);
    }

    fn with_devices(devices: &[&str], env: &[(&str, &str)]) -> Spec {
        Spec {
            image: ImageRef("ghcr.io/example/train:1".into()),
            args: vec![],
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            devices: devices.iter().map(|d| (*d).into()).collect(),
            ports: vec![],
            mounts: vec![],
            confinement: Confinement::default(),
            name: None,
        }
    }

    #[test]
    fn a_container_handed_a_card_is_given_compute_and_utility_alone_whatever_its_image_or_spec_asks() {
        let card = "GPU-00000000-0000-0000-0000-000000000001";
        assert_eq!(
            env_of(&with_devices(
                &[card],
                &[("NVIDIA_DRIVER_CAPABILITIES", "all"), ("A", "1")]
            )),
            vec![
                "A=1".to_string(),
                "HOME=/tmp".to_string(),
                "NVIDIA_DRIVER_CAPABILITIES=compute,utility".to_string(),
            ],
            "the adapter's word, once"
        );
        assert_eq!(
            env_of(&with_devices(&[], &[("A", "1")])),
            vec!["A=1".to_string(), "HOME=/tmp".to_string()]
        );
    }

    #[test]
    fn a_boxed_container_is_created_as_nobody_whatever_its_image_names_and_an_engine_as_its_image_says() {
        let job = with_devices(&[], &[]);
        let body = create_body(&job, "127.0.0.1", &[], &[]).unwrap();
        assert_eq!(
            body.user.as_deref(),
            Some("65534:65534"),
            "named in the body, the engine never takes the image's USER, root or any other"
        );
        let mut engine = with_devices(&[], &[]);
        engine.confinement = Confinement::serving();
        assert_eq!(create_body(&engine, "127.0.0.1", &[], &[]).unwrap().user, None);
        let mut other = with_devices(&[], &[]);
        other.confinement.user = Some(best_peer_runtime::User { uid: 1234, gid: 5678 });
        assert_eq!(
            create_body(&other, "127.0.0.1", &[], &[]).unwrap().user.as_deref(),
            Some("1234:5678")
        );
    }

    #[test]
    fn a_container_run_as_its_boxs_user_has_tmp_for_its_home_unless_the_spec_names_one() {
        assert!(env_of(&with_devices(&[], &[])).contains(&"HOME=/tmp".to_string()));
        assert_eq!(
            env_of(&with_devices(&[], &[("HOME", "/work")])),
            vec!["HOME=/work".to_string()],
            "the spec's own home stands"
        );
        let mut engine = with_devices(&[], &[]);
        engine.confinement = Confinement::serving();
        assert!(
            env_of(&engine).is_empty(),
            "an image run as its own user keeps its own home"
        );
    }

    fn offered(options: &[&str]) -> Vec<String> {
        options.iter().map(|o| o.to_string()).collect()
    }

    #[test]
    fn seccomp_and_apparmor_are_named_on_every_container_where_the_engine_offers_them_and_only_there() {
        let both = offered(&["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"]);
        assert_eq!(
            confined(&Confinement::default(), &[], &both).security_opt,
            Some(offered(&[
                "no-new-privileges",
                "seccomp=builtin",
                "apparmor=docker-default"
            ]))
        );
        assert_eq!(
            confined(
                &Confinement::serving(),
                &[],
                &offered(&["name=seccomp,profile=default"])
            )
            .security_opt,
            Some(offered(&["no-new-privileges"])),
            "an older engine, which does not know the name, keeps its default"
        );
        assert_eq!(
            confined(
                &Confinement::default(),
                &[],
                &offered(&["name=seccomp,profile=unconfined"])
            )
            .security_opt,
            Some(offered(&["no-new-privileges", "seccomp=builtin"])),
            "an engine that runs its containers unconfined still confines these"
        );
        assert_eq!(
            confined(
                &Confinement::default(),
                &[],
                &offered(&["name=seccomp,profile=/etc/docker/strict.json"])
            )
            .security_opt,
            Some(offered(&["no-new-privileges"])),
            "an engine's own profile is left to it"
        );
        assert_eq!(
            confined(&Confinement::default(), &[], &offered(&["name=cgroupns"])).security_opt,
            Some(offered(&["no-new-privileges"])),
            "a host without AppArmor or seccomp still runs"
        );
    }

    fn listed(items: &[(&str, Option<i64>)]) -> Option<String> {
        super::newest(items.iter().map(|(id, at)| (id.to_string(), *at)))
    }

    #[test]
    fn the_newest_of_several_same_named_containers_is_the_latest_created() {
        assert_eq!(
            listed(&[("older", Some(100)), ("newer", Some(200))]).as_deref(),
            Some("newer")
        );
        assert_eq!(
            listed(&[("newer", Some(200)), ("older", Some(100))]).as_deref(),
            Some("newer")
        );
    }

    #[test]
    fn containers_created_in_the_same_second_keep_the_engines_order_newest_first() {
        assert_eq!(
            listed(&[("listed-first", Some(300)), ("listed-second", Some(300))]).as_deref(),
            Some("listed-first")
        );
    }

    #[test]
    fn a_container_with_no_creation_time_loses_to_one_with_it_and_none_is_none() {
        assert_eq!(
            listed(&[("unknown", None), ("known", Some(1))]).as_deref(),
            Some("known")
        );
        assert_eq!(listed(&[("only", None)]).as_deref(), Some("only"));
        assert_eq!(listed(&[]), None);
    }
}
