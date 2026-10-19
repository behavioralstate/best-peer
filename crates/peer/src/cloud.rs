//! A cloud: a named pool of machines inside a workspace, fronting the peers it is configured with. The same lifecycle
//! as a peer, where the devices are every member's, named `cloud/peer/device`; a deploy or a job is placed on the
//! member with the room (the peer's own rule, applied across members) and sent there as the cloud's own command, and
//! what the member tells about it comes back on the workspace's stream under the caller's correlation id, with the
//! cloud and the member named. The cloud holds no model and runs no job: it holds the fold of what it placed, follows
//! the members' streams, and squares its state with theirs on a timer, so a member that is gone is told as such for
//! every workload it held. Members are what `configure-cloud` listed; each admits the cloud by its own sign-in, the
//! device flow, with the code shown in the door's log for the person at that member's machine.
//!
//! A job is an order the cloud takes and places when it can. `JobQueued` holds the order whole, `JobPlaced` names
//! the member it was sent to, and the member's `JobStarted`, relayed, names the order; the state folds orders from
//! these facts, so the queue and every placement survive a restart. One placement step at a time takes the orders
//! that wait, oldest first, and sends each that a member has the room for; an order that does not fit yet holds back
//! none that does. The step runs when room may have come free (a workload ended, a member joined), on the reconcile
//! tick, and when an order is taken; it also ends an order waiting past its `queue_seconds` and stops a job running
//! past its `deadline_seconds`, both counted from the facts' own times.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use best_peer_door::auth::{hash_key, holder_of_hash, Credential};
use best_peer_door::envelope::now_rfc3339;
use best_peer_door::{BestError, Emitter, Envelope, EventLog};
use best_peer_engine::Kind;
use best_peer_gpu::{Device, DeviceId, Host};
use best_peer_runtime::Isolation;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::domain::Service;
use crate::holdings::Holdings;
use crate::lifecycle::{
    accelerators, accelerators_only, any_compute, has_share, isolation_refused, mine, new_id, not_yours, parse, place,
    ready_deployment, require, shown_to, usable_by, within_count, within_share, workloads_view,
};
use crate::member::{Heard, Member, Refusal};
use crate::state::{JobPhase, Order, Phase, Reservation, State};
use crate::transport::Transport;

/// How often the cloud squares its state with its members', and the most a member may be silent before its
/// workloads are told as ended: the same thirty seconds a peer gives a lost engine.
pub const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// How long a member's stream may be silent before it is reconnected: the member keeps it alive every fifteen
/// seconds, so a minute of nothing is a dead socket.
const STREAM_SILENCE: Duration = Duration::from_secs(60);

/// The events after which nothing more is said about a workload or a command.
const TERMINAL: &[&str] = &[
    "Undeployed",
    "DeploymentFailed",
    "DeploymentEnded",
    "OutOfMemory",
    "JobFinished",
    "JobFailed",
    "JobStopped",
    "PromptAnswered",
    "PromptFailed",
    "CommandFailed",
];

/// Why a member's stream is no longer read: the member closed it, or nothing at all came on it for the silence
/// allowed.
#[derive(Debug, PartialEq, Eq)]
enum Stopped {
    Ended,
    Silent,
}

/// Reads a member's stream until it ends or falls silent, handing every event to `relay`. A keep-alive, or any bytes
/// of an event still on its way, is the member saying it is there: a quiet member whose socket is alive is read on,
/// however long nothing happens on it; only a socket with nothing on it for `silence` is dead.
async fn read_until_stopped(
    stream: impl Stream<Item = Heard>,
    silence: Duration,
    mut relay: impl FnMut(String, Envelope),
) -> Stopped {
    let mut stream = std::pin::pin!(stream);
    loop {
        match tokio::time::timeout(silence, stream.next()).await {
            Ok(Some(Heard::Event(id, e))) => relay(id, *e),
            Ok(Some(Heard::Alive)) => {}
            Ok(None) => return Stopped::Ended,
            Err(_) => return Stopped::Silent,
        }
    }
}

/// What each device of the cloud offers between a workload and its host, by `cloud/peer/device`.
type Isolations = HashMap<String, Isolation>;

/// A member's credential and the cloud's place on its stream, kept across restarts in the cloud's `members.json`.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Saved {
    pub name: String,
    pub endpoint: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub last_event: Option<String>,
}

/// Writes a cloud's members file, for a test that stands in for the members' approvals.
#[cfg(test)]
pub fn save_members(file: &Path, saved: &[Saved]) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::tls::write_private(file, &serde_json::to_vec_pretty(saved).unwrap_or_default())
}

fn read_saved(file: &Path) -> Vec<Saved> {
    std::fs::read_to_string(file)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// What the cloud sent a member and still listens for, by the member and the correlation the member was given:
/// the emitter of the cloud command it came from, and what the command is.
#[derive(Clone)]
struct Issued {
    em: Emitter,
    /// The command's type, for the fact told when the member is lost before it answered.
    r#type: String,
    /// The cloud command's key when this is one part of a pull fanned out to every member.
    pull: Option<String>,
    /// The workload this command ends, for an undeploy or a stop.
    ends: Option<String>,
    /// The order this command runs, for a run-job the queue sent.
    order: Option<String>,
    /// What the door adds to the fact that answers it: why the door, not a caller, asked.
    note: Option<Value>,
}

/// A pull fanned out to every member: who is still to hear from, and who failed.
struct Pull {
    image: String,
    pending: HashSet<String>,
    failed: Vec<String>,
}

/// What a member's answer at a reconcile tick meant for it.
#[derive(PartialEq, Eq)]
enum Contact {
    Same,
    Joined,
    Lost,
}

pub struct Cloud {
    /// The cloud's name: the first part of its device ids, and what every fact it tells carries as `cloud`.
    pub name: String,
    /// The workspace the cloud is in, for the log lines and the connection name it signs in under.
    workspace: String,
    pub log: Arc<EventLog>,
    service: String,
    /// The workspace's door, what `DeploymentReady` names an endpoint under.
    endpoint: String,
    dataschemas: Arc<HashMap<String, String>>,
    completions: Arc<HashMap<String, HashSet<String>>>,
    members: Mutex<Vec<Arc<Member>>>,
    transport: Arc<dyn Transport>,
    holdings: Arc<Holdings>,
    pub state: Mutex<State>,
    issued: Mutex<HashMap<(String, String), Issued>>,
    pulls: Mutex<HashMap<String, Pull>>,
    /// Each member's last event the cloud relayed.
    cursors: Mutex<HashMap<String, String>>,
    /// Whether each member answered at the last reconcile tick; a member never asked is taken as answering.
    reachable: Mutex<HashMap<String, bool>>,
    /// Workloads a member did not list at the last tick: listed at two ticks running, they are told as ended, so
    /// a fact still on its way on the stream is not outrun.
    missing: Mutex<HashSet<String>>,
    file: Option<PathBuf>,
    /// The task following each member, by the member's name, and the reconcile tick.
    tasks: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    ticking: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Whether `follow` was called: a member added after it is followed at once.
    following: std::sync::atomic::AtomicBool,
    /// This cloud, for a placement step started from where only a reference is at hand.
    me: Weak<Cloud>,
    /// The command behind each order, by the order's id: what completes the command and names its holder.
    keys: Mutex<HashMap<String, String>>,
    /// The commands admitted from a credential held to the accelerators, until the order is told.
    held_to_accelerators: Mutex<HashSet<String>>,
    /// A placement step runs, and whether another was asked for meanwhile.
    stepping: AtomicBool,
    again: AtomicBool,
    /// One step at a time, however it was started: an order is placed once.
    steps: tokio::sync::Mutex<()>,
    /// Orders stopped after they were sent and before the member started them: their listener stays, so the job
    /// the member starts all the same is stopped there.
    stopped_unstarted: Mutex<HashSet<String>>,
}

/// How long an order may wait for room when it names no `queue_seconds`: a day, as RunPod's default time-to-live.
pub const DEFAULT_QUEUE_SECONDS: u64 = 24 * 60 * 60;

/// An order's id: the command's key hashed, so the command run again after a restart finds its order.
fn order_id(key: &str) -> String {
    format!("job-{}", &hash_key(key)[..12])
}

/// The id and correlation a member is given for an order: the order and its attempt, so an order queued again is a
/// new command there, even on the member that had it.
fn order_correlation(o: &Order) -> String {
    format!("{}-{}", o.id, o.attempt)
}

/// Whether `seconds` from `since` have passed at `now`; a bound not set, or a time that does not read, never has.
fn past(since: Option<&str>, seconds: Option<u64>, now: OffsetDateTime) -> bool {
    match (since.and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok()), seconds) {
        (Some(t), Some(s)) => now >= t + time::Duration::seconds(s as i64),
        _ => false,
    }
}

/// Whether a device of `host` that runs a job could hold `needed` once nothing else held it there: an order that
/// fits nowhere now waits only when room can come free.
fn could_ever_hold(host: &Host, needed: u64, pinned: Option<&str>) -> bool {
    let empty = Host {
        devices: host
            .devices
            .iter()
            .cloned()
            .map(|mut d| {
                d.memory.free_bytes = d.memory.total_bytes;
                d
            })
            .collect(),
        ..host.clone()
    };
    place(&empty, &State::default(), &any_compute(), needed, pinned, "", None).is_ok()
}

/// `JobQueued`'s body for `o`, at `attempt`.
fn queued_fact(o: &Order, attempt: u32, waiting: bool, reason: Option<String>, instead_of: Option<&str>) -> Value {
    let mut v = json!({
        "job": o.id, "image": o.image, "args": o.args, "memory_bytes": o.memory_bytes, "device": o.device,
        "queue_seconds": o.queue_seconds, "deadline_seconds": o.deadline_seconds, "holder": o.holder,
        "accelerators_only": o.accelerators_only, "isolation": o.isolation, "attempt": attempt, "waiting": waiting,
    });
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    if let Some(i) = instead_of {
        v["instead_of"] = json!(i);
    }
    v
}

/// A member's `get-hardware-state`, as the abstraction's types.
#[derive(Deserialize)]
struct Seen {
    #[serde(default)]
    driver: Option<String>,
    devices: Vec<Device>,
}

#[derive(Deserialize)]
struct DeployData {
    model: String,
    engine: Kind,
    memory_bytes: u64,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    isolation: Option<Isolation>,
}

#[derive(Deserialize)]
struct RunJobData {
    image: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    memory_bytes: Option<u64>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    queue_seconds: Option<u64>,
    #[serde(default)]
    deadline_seconds: Option<u64>,
    #[serde(default)]
    isolation: Option<Isolation>,
}

impl Cloud {
    /// A cloud `name` of workspace `workspace`, over `members` (name and endpoint), its workspace's log, and the
    /// file its members' credentials and cursors are kept in (none for a cloud that forgets them at exit). A member
    /// already in the file keeps the credential it was issued.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        workspace: &str,
        endpoint: &str,
        service: &str,
        log: Arc<EventLog>,
        dataschemas: Arc<HashMap<String, String>>,
        completions: Arc<HashMap<String, HashSet<String>>>,
        members: &[(String, String)],
        file: Option<PathBuf>,
        transport: Arc<dyn Transport>,
        holdings: Arc<Holdings>,
    ) -> Arc<Self> {
        let saved = file.as_deref().map(read_saved).unwrap_or_default();
        let mut cursors = HashMap::new();
        let list: Vec<Arc<Member>> = members
            .iter()
            .map(|(n, e)| {
                let kept = saved.iter().find(|s| s.endpoint == e.trim_end_matches('/'));
                if let Some(id) = kept.and_then(|s| s.last_event.clone()) {
                    cursors.insert(n.clone(), id);
                }
                Arc::new(Member::new(n, e, kept.and_then(|s| s.key.clone()), transport.clone()))
            })
            .collect();
        let cloud = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            keys: Mutex::new(HashMap::new()),
            held_to_accelerators: Mutex::new(HashSet::new()),
            stepping: AtomicBool::new(false),
            again: AtomicBool::new(false),
            steps: tokio::sync::Mutex::new(()),
            stopped_unstarted: Mutex::new(HashSet::new()),
            name: name.into(),
            workspace: workspace.into(),
            log,
            service: service.into(),
            endpoint: endpoint.trim_end_matches('/').into(),
            dataschemas,
            completions,
            members: Mutex::new(list),
            transport,
            holdings: holdings.clone(),
            state: Mutex::new(State::default()),
            issued: Mutex::new(HashMap::new()),
            pulls: Mutex::new(HashMap::new()),
            cursors: Mutex::new(cursors),
            reachable: Mutex::new(HashMap::new()),
            missing: Mutex::new(HashSet::new()),
            file,
            tasks: Mutex::new(HashMap::new()),
            ticking: Mutex::new(None),
            following: std::sync::atomic::AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&cloud);
        holdings.add(move |holder| {
            weak.upgrade()
                .map(|c| c.state.lock().unwrap().holdings_of(holder))
                .unwrap_or_default()
        });
        cloud
    }

    /// Folds every fact the log holds about this cloud into the state, then listens again for what the members will
    /// still tell: every order sent and every workload running, so a fact told after a restart reaches the caller
    /// under its correlation, and an order that waits keeps what it was promised. Run once, before the cloud is used.
    pub fn rebuild(&self) {
        {
            let mut state = self.state.lock().unwrap();
            self.log.replay(|e| {
                if e.data["cloud"].as_str() == Some(&self.name) {
                    state.apply(e)
                }
            });
        }
        self.relink();
    }

    fn relink(&self) {
        let (orders, jobs, deployments) = {
            let s = self.state.lock().unwrap();
            let orders: Vec<Order> = s.orders.values().cloned().collect();
            let jobs: Vec<(String, String, Option<String>)> = s
                .jobs
                .values()
                .map(|j| (j.id.clone(), j.correlation.clone(), j.peer.clone()))
                .collect();
            let deployments: Vec<(String, String, Option<String>)> = s
                .deployments
                .values()
                .map(|d| (d.id.clone(), d.correlation.clone(), d.peer.clone()))
                .collect();
            (orders, jobs, deployments)
        };
        for o in &orders {
            if let Some(key) = self
                .log
                .command_where(|sender, id, _| order_id(&format!("{sender}:{id}")) == o.id)
            {
                self.keys.lock().unwrap().insert(o.id.clone(), key);
            }
            if o.job.is_none() {
                // Not started: what it was promised counts, on the device it was placed on when it was.
                let device = o
                    .placed
                    .as_ref()
                    .map(|(peer, d)| DeviceId(d.clone().unwrap_or_else(|| format!("{}/{peer}/", self.name))));
                self.promise(o, device);
            }
            let peer = match (&o.job, &o.placed) {
                (Some(j), _) => jobs.iter().find(|(id, ..)| id == j).and_then(|(.., p)| p.clone()),
                (None, Some((p, _))) => Some(p.clone()),
                (None, None) => None,
            };
            if let Some(peer) = peer {
                self.listen_order(&peer, &order_correlation(o), &self.order_emitter(o), &o.id);
            }
        }
        // Workloads placed before orders were told: the member was given the command's own correlation.
        let ordered = |id: &str| orders.iter().any(|o| o.job.as_deref() == Some(id));
        for (id, correlation, peer, r#type) in jobs
            .iter()
            .map(|(i, c, p)| (i, c, p, "RunJob"))
            .chain(deployments.iter().map(|(i, c, p)| (i, c, p, "DeployModel")))
        {
            let Some(peer) = peer.as_deref().filter(|_| !ordered(id)) else {
                continue;
            };
            let Some(key) = self.log.command_where(|_, _, w| w == Some(id.as_str())) else {
                continue;
            };
            let mc = member_correlation(&key, &json!({}), None);
            let em = self.emitter(correlation).with_key(&key);
            self.listen_for(peer, &mc, &em, r#type, None, None);
        }
    }

    /// The order `o` holds what it asked for, on `device` once it is placed: a share and the count of jobs count it
    /// while it waits, and the placement step sees it promised there.
    fn promise(&self, o: &Order, device: Option<DeviceId>) {
        let key = self
            .keys
            .lock()
            .unwrap()
            .get(&o.id)
            .cloned()
            .unwrap_or_else(|| o.id.clone());
        let mut s = self.state.lock().unwrap();
        s.reserved.retain(|k, r| r.id != o.id || *k == key);
        let r = s.reserved.entry(key).or_insert_with(|| Reservation {
            id: o.id.clone(),
            device: None,
            compute: None,
            memory_bytes: o.memory_bytes.unwrap_or(0),
            holder: o.holder.clone(),
            boxed: false,
        });
        r.device = device;
    }

    /// The emitter of the command behind order `o`: its correlation, its key when known, and what completes it.
    fn order_emitter(&self, o: &Order) -> Emitter {
        let key = self.keys.lock().unwrap().get(&o.id).cloned().unwrap_or_default();
        let completes: Vec<String> = self
            .completions
            .get("RunJob")
            .map(|c| c.iter().cloned().collect())
            .unwrap_or_default();
        self.emitter(&o.correlation).with_key(&key).with_completes(&completes)
    }

    pub fn members(&self) -> Vec<Arc<Member>> {
        self.members.lock().unwrap().clone()
    }

    /// Writes the members' credentials and cursors, whole or not at all.
    fn save(&self) {
        let Some(file) = &self.file else { return };
        let cursors = self.cursors.lock().unwrap();
        let saved: Vec<Saved> = self
            .members()
            .iter()
            .map(|m| Saved {
                name: m.name.clone(),
                endpoint: m.endpoint.clone(),
                key: m.key(),
                last_event: cursors.get(&m.name).cloned(),
            })
            .collect();
        let tmp = file.with_extension("json.tmp");
        let written = file
            .parent()
            .map(std::fs::create_dir_all)
            .unwrap_or(Ok(()))
            .and_then(|()| crate::tls::write_private(&tmp, &serde_json::to_vec_pretty(&saved).unwrap_or_default()))
            .and_then(|()| std::fs::rename(&tmp, file));
        if let Err(e) = written {
            tracing::warn!(file = %file.display(), error = %e, "the members' credentials could not be saved");
        }
    }

    pub fn emitter(&self, correlation: &str) -> Emitter {
        Emitter::new(self.log.clone(), &self.service, correlation, self.dataschemas.clone())
            .with_completions(self.completions.clone())
    }

    /// Tells a fact of the cloud's own, with the cloud named: appended, then folded.
    fn tell(&self, em: &Emitter, r#type: &str, mut data: Value) -> Envelope {
        data["cloud"] = json!(self.name);
        let workload = data["deployment"].as_str().or(data["job"].as_str()).map(str::to_string);
        let e = em.emit(r#type, data);
        if let Some(w) = workload {
            em.completes_workload(&w, r#type);
        }
        self.state.lock().unwrap().apply(&e);
        e
    }

    fn member(&self, name: &str) -> Option<Arc<Member>> {
        self.members.lock().unwrap().iter().find(|m| m.name == name).cloned()
    }

    /// The name this cloud signs in to its members under: the cloud's and the workspace's, one word, so a machine
    /// serving two clouds, of one workspace or two, holds two credentials.
    fn connection_name(&self) -> String {
        let word: String = format!("{}-{}", self.name, self.workspace)
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
            .take(64)
            .collect();
        word.trim_matches('-').to_string()
    }

    /// What the member names as `holder` for the workloads this cloud placed there.
    fn holder_on(&self, member: &Member) -> Option<String> {
        member.key().map(|k| holder_of_hash(&hash_key(&k)))
    }

    /// The members admitted and answering at the last tick: where anything can be placed.
    fn up(&self) -> Vec<Arc<Member>> {
        let reachable = self.reachable.lock().unwrap();
        self.members()
            .into_iter()
            .filter(|m| m.admitted() && reachable.get(&m.name).copied().unwrap_or(true))
            .collect()
    }

    /// Each member with how it stands: `up`, `joining` (it has not admitted this cloud yet) or `unreachable`, as
    /// of the last tick.
    pub fn peers(&self) -> Vec<Value> {
        let reachable = self.reachable.lock().unwrap();
        self.members()
            .iter()
            .map(|m| {
                let state = if !m.admitted() {
                    "joining"
                } else if reachable.get(&m.name).copied().unwrap_or(true) {
                    "up"
                } else {
                    "unreachable"
                };
                json!({ "peer": m.name, "endpoint": m.endpoint, "state": state })
            })
            .collect()
    }

    /// The workloads this cloud holds, admitted ones included, by name; on `peer` alone when one is given.
    pub fn holds(&self, peer: Option<&str>) -> Vec<Value> {
        let s = self.state.lock().unwrap();
        let on = |p: &Option<String>| peer.is_none_or(|w| p.as_deref() == Some(w));
        let prefix = |p: &str| format!("{}/{p}/", self.name);
        let reserved_on =
            |d: &Option<DeviceId>| peer.is_none_or(|w| d.as_ref().is_some_and(|d| d.0.starts_with(&prefix(w))));
        let mut out: Vec<Value> = s
            .deployments
            .values()
            .filter(|d| on(&d.peer))
            .map(|d| json!({ "deployment": d.id, "model": d.model, "peer": d.peer }))
            .collect();
        out.extend(
            s.jobs
                .values()
                .filter(|j| on(&j.peer))
                .map(|j| json!({ "job": j.id, "image": j.image.0, "peer": j.peer })),
        );
        out.extend(
            s.reserved
                .values()
                .filter(|r| reserved_on(&r.device))
                .map(|r| json!({ "admitted": r.id, "device": r.device.as_ref().map(|d| d.0.clone()) })),
        );
        out
    }

    /// Records whether a member answered, and tells the membership fact when that changed.
    fn contact(&self, member: &Member, now: bool, why: &str) -> Contact {
        let before = self.reachable.lock().unwrap().insert(member.name.clone(), now);
        let em = self.emitter(&format!("{}/{}", self.name, member.name));
        match (before, now) {
            (Some(true), false) | (None, false) => {
                tracing::warn!(cloud = %self.name, peer = %member.name, %why, "a member peer is unreachable");
                self.tell(
                    &em,
                    "PeerLost",
                    json!({ "peer": member.name, "endpoint": member.endpoint, "reason": why }),
                );
                Contact::Lost
            }
            (Some(false), true) | (None, true) => {
                tracing::info!(cloud = %self.name, peer = %member.name, "a member peer answers");
                self.tell(
                    &em,
                    "PeerJoined",
                    json!({ "peer": member.name, "endpoint": member.endpoint }),
                );
                self.kick();
                Contact::Joined
            }
            _ => Contact::Same,
        }
    }

    /// Every admitted member's devices as one host, each device named `cloud/peer/id`, with the members as they
    /// answered this time. A device's free memory is what the member's own placement would allow: the free memory
    /// it reports, less what the member has promised to workloads there that have not taken it yet. Whether a
    /// member is lost is the reconcile tick's to say, not a read's.
    async fn combined(&self) -> (Host, Vec<Value>, Isolations) {
        let mut devices = Vec::new();
        let mut peers = Vec::new();
        let mut isolations = Isolations::new();
        for m in self.members() {
            let row =
                |state: &str| json!({ "cloud": self.name, "peer": m.name, "endpoint": m.endpoint, "state": state });
            if !m.admitted() {
                peers.push(row("joining"));
                continue;
            }
            let answered = async {
                let promised = promised_by_device(&m.query("get-workloads").await?);
                let hs = m.query("get-hardware-state").await?;
                Ok::<_, Refusal>((promised, hs))
            }
            .await;
            match answered {
                Ok((promised, hs)) => {
                    let mut up = row("up");
                    let seen: Seen = match serde_json::from_value(hs.clone()) {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!(cloud = %self.name, peer = %m.name, error = %e, "the member's hardware state could not be read");
                            up["driver"] = hs["driver"].clone();
                            peers.push(up);
                            continue;
                        }
                    };
                    up["driver"] = json!(seen.driver);
                    peers.push(up);
                    // What each device offers, as the member says; a member that says nothing offers nothing more
                    // than a process.
                    let offered: HashMap<String, Isolation> = hs["devices"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|d| {
                            let id = d["id"].as_str()?.to_string();
                            let i = serde_json::from_value(d["isolation"].clone()).unwrap_or(Isolation::Process);
                            Some((id, i))
                        })
                        .collect();
                    for mut d in seen.devices {
                        let isolation = offered.get(&d.id.0).copied().unwrap_or(Isolation::Process);
                        isolations.insert(format!("{}/{}/{}", self.name, m.name, d.id.0), isolation);
                        let held = promised.get(&d.id.0).copied().unwrap_or(0);
                        d.memory.free_bytes = d.memory.free_bytes.min(d.memory.total_bytes.saturating_sub(held));
                        devices.push(Device {
                            id: DeviceId(format!("{}/{}/{}", self.name, m.name, d.id.0)),
                            ..d
                        });
                    }
                }
                Err(e) => {
                    let mut down = row("unreachable");
                    down["reason"] = json!(e.text());
                    peers.push(down);
                }
            }
        }
        (
            Host {
                driver: None,
                devices,
                observed_at: std::time::SystemTime::now(),
            },
            peers,
            isolations,
        )
    }

    /// The devices of `host` that offer at least `asked`; all of them when nothing is asked. The member that runs a
    /// job with no device is one with a device that offers it.
    fn offering(host: &Host, isolations: &Isolations, asked: Option<Isolation>) -> Host {
        let Some(asked) = asked else { return host.clone() };
        Host {
            devices: host
                .devices
                .iter()
                .filter(|d| isolations.get(&d.id.0).is_some_and(|i| *i >= asked))
                .cloned()
                .collect(),
            ..host.clone()
        }
    }

    /// The first member that answers, for a job with no device: with nothing asked, as before; with an isolation
    /// asked, the first with a device in `host`, which holds only the devices that offer it.
    fn first_up(&self, host: &Host, asked: Option<Isolation>) -> Option<String> {
        self.up()
            .into_iter()
            .find(|m| {
                asked.is_none()
                    || host
                        .devices
                        .iter()
                        .any(|d| d.id.0.starts_with(&format!("{}/{}/", self.name, m.name)))
            })
            .map(|m| m.name.clone())
    }

    /// `host`, the devices a credential may use, held to `asked`: those that offer it, or the refusal naming what
    /// those devices offer. With no device to judge (no member answers) nothing is refused here: what follows says
    /// why nothing can be placed.
    fn held_to(&self, host: Host, isolations: &Isolations, asked: Option<Isolation>) -> Result<Host, BestError> {
        let held = Self::offering(&host, isolations, asked);
        match asked {
            Some(a) if held.devices.is_empty() && !host.devices.is_empty() => {
                let offered: Vec<Isolation> = host
                    .devices
                    .iter()
                    .map(|d| isolations.get(&d.id.0).copied().unwrap_or(Isolation::Process))
                    .collect();
                Err(isolation_refused(
                    a,
                    &offered,
                    &format!("cloud {}'s members offer", self.name),
                ))
            }
            _ => Ok(held),
        }
    }

    /// The member a device id of this cloud names, and the device's id on it: `cloud/peer/device`.
    fn split_device<'a>(&self, id: &'a str) -> Option<(&'a str, &'a str)> {
        id.strip_prefix(&format!("{}/", self.name))?.split_once('/')
    }

    /// The command as the member receives it: the cloud's own, with an id and a correlation unique to the cloud
    /// command it stands for, so a retry is the same command there too, and the facts the member tells come back
    /// to the right emitter. A command of the cloud's own, for no caller, is named by the workload it ends.
    fn to_member(
        &self,
        member: &Member,
        schema_base: &str,
        key: &str,
        r#type: &str,
        schema: &str,
        data: Value,
    ) -> (Envelope, String) {
        let mc = member_correlation(key, &data, self.holder_on(member).as_deref());
        (self.to_member_as(schema_base, &mc, r#type, schema, data), mc)
    }

    /// The command as the member receives it, under the id and correlation `mc`.
    fn to_member_as(&self, schema_base: &str, mc: &str, r#type: &str, schema: &str, data: Value) -> Envelope {
        Envelope {
            specversion: "1.0".into(),
            id: mc.into(),
            correlationid: Some(mc.into()),
            source: self.endpoint.clone(),
            r#type: r#type.into(),
            datacontenttype: "application/json".into(),
            dataschema: Some(format!("{schema_base}/commands/{schema}/1.0")),
            time: now_rfc3339(),
            data,
            extensions: Default::default(),
        }
    }

    fn listen_for(
        &self,
        member: &str,
        mc: &str,
        em: &Emitter,
        r#type: &str,
        pull: Option<String>,
        ends: Option<String>,
    ) {
        self.issued.lock().unwrap().insert(
            (member.into(), mc.into()),
            Issued {
                em: em.clone(),
                r#type: r#type.into(),
                pull,
                ends,
                order: None,
                note: None,
            },
        );
    }

    /// Listens for what a member tells about the order `order` it was sent.
    fn listen_order(&self, member: &str, mc: &str, em: &Emitter, order: &str) {
        self.issued.lock().unwrap().insert(
            (member.into(), mc.into()),
            Issued {
                em: em.clone(),
                r#type: "RunJob".into(),
                pull: None,
                ends: None,
                order: Some(order.into()),
                note: None,
            },
        );
    }

    /// Sends a command to a member and listens for its facts; a refusal comes back as the cloud's error.
    async fn place_on(
        &self,
        member: &Member,
        em: &Emitter,
        r#type: &str,
        schema: &str,
        data: Value,
    ) -> Result<(), BestError> {
        self.place_on_noting(member, em, r#type, schema, data, None).await
    }

    /// The same, `note` added to the fact that answers it.
    async fn place_on_noting(
        &self,
        member: &Member,
        em: &Emitter,
        r#type: &str,
        schema: &str,
        data: Value,
        note: Option<Value>,
    ) -> Result<(), BestError> {
        // An undeploy or a stop ends the workload it names; a prompt names one and ends nothing.
        let ends = matches!(r#type, "UndeployModel" | "StopJob")
            .then(|| data["deployment"].as_str().or(data["job"].as_str()).map(str::to_string))
            .flatten();
        let base = member.schema_base().await;
        let (envelope, mc) = self.to_member(member, &base, em.command_key(), r#type, schema, data);
        self.listen_for(&member.name, &mc, em, r#type, None, ends);
        if note.is_some() {
            if let Some(i) = self.issued.lock().unwrap().get_mut(&(member.name.clone(), mc.clone())) {
                i.note = note;
            }
        }
        member.send(&envelope).await.map(|_| ()).map_err(|e| {
            self.issued.lock().unwrap().remove(&(member.name.clone(), mc));
            e.relayed(&member.name)
        })
    }

    /// The sender and the id of a cloud command, from its key.
    fn sender_of(key: &str) -> (&str, &str) {
        key.split_once(':').unwrap_or(("", key))
    }

    /// Whether the command with this key already made a workload this cloud knows: a command run again after a
    /// restart is already placed, and the member runs it.
    fn already_placed(&self, key: &str) -> Option<String> {
        let (sender, id) = Self::sender_of(key);
        let workload = self.log.workload_of(sender, id)?;
        let s = self.state.lock().unwrap();
        let peer = s
            .deployments
            .get(&workload)
            .and_then(|d| d.peer.clone())
            .or_else(|| s.jobs.get(&workload).and_then(|j| j.peer.clone()))?;
        Some(peer)
    }

    /// What `holder` holds in this cloud, by name: deployments, jobs and admitted commands.
    pub fn holds_of(&self, holder: &str) -> Vec<Value> {
        let s = self.state.lock().unwrap();
        let mut out: Vec<Value> = s
            .deployments
            .values()
            .filter(|d| d.holder == holder)
            .map(|d| json!({ "deployment": d.id, "model": d.model, "cloud": self.name, "peer": d.peer }))
            .collect();
        out.extend(
            s.jobs
                .values()
                .filter(|j| j.holder == holder)
                .map(|j| json!({ "job": j.id, "image": j.image.0, "cloud": self.name, "peer": j.peer })),
        );
        out.extend(
            s.reserved
                .values()
                .filter(|r| r.holder == holder)
                .map(|r| json!({ "admitted": r.id, "cloud": self.name })),
        );
        out
    }

    /// Whether this cloud holds the workload `id`, as a deployment, a job or an order.
    pub fn holds_workload(&self, id: &str) -> bool {
        let s = self.state.lock().unwrap();
        s.deployments.contains_key(id) || s.jobs.contains_key(id) || s.orders.contains_key(id)
    }

    // ----- what the members tell ----------------------------------------------------------------------------------

    /// A fact a member told, relayed when it answers something the cloud sent there: told again on the workspace's
    /// log under the caller's correlation, with the cloud and the member named and the caller as the holder, and
    /// folded into the state.
    fn relay(&self, member: &Member, id: &str, e: &Envelope) {
        let issued = e.correlationid.as_deref().and_then(|mc| {
            self.issued
                .lock()
                .unwrap()
                .get(&(member.name.clone(), mc.to_string()))
                .cloned()
        });
        if let Some(Issued {
            em, pull, order, note, ..
        }) = issued
        {
            let mut data = e.data.clone();
            data["peer"] = json!(member.name);
            if let Some(device) = data["device"].as_str().filter(|d| !d.is_empty() && !d.contains('/')) {
                data["device"] = json!(format!("{}/{}/{device}", self.name, member.name));
            }
            // The holder of the order and whether it started, while it is one; an order no longer there was stopped
            // before it started.
            let ordered = order.as_ref().map(|o| {
                let s = self.state.lock().unwrap();
                (o.clone(), s.orders.get(o).map(|x| (x.holder.clone(), x.job.is_some())))
            });
            let mut r#type = e.r#type.clone();
            if let Some((o, Some((_, false)))) = &ordered {
                // The member ended the order before it started: under the member's own id for its job, which the
                // caller never saw. It is the order that ended, told by the order's id, and a refusal is its failure.
                if TERMINAL.contains(&r#type.as_str()) {
                    data["job"] = json!(o);
                    if r#type == "CommandFailed" {
                        r#type = "JobFailed".into();
                        data["fix"] = json!("read the peer's refusal in the reason, then order it again");
                    }
                }
            }
            if let Some(key) = pull {
                self.on_pull_fact(member, &key, &em, &e.r#type, data);
            } else if let Some((o, None)) = &ordered {
                // Stopped before it started: the member's facts about it are not told. When the member starts it all
                // the same, it is stopped there; when the member ends it first, nothing is left to do.
                let started = r#type == "JobStarted";
                if started || TERMINAL.contains(&r#type.as_str()) {
                    if let Some(mc) = e.correlationid.as_deref() {
                        self.issued
                            .lock()
                            .unwrap()
                            .remove(&(member.name.clone(), mc.to_string()));
                    }
                    self.stopped_unstarted.lock().unwrap().remove(o);
                }
                if let (true, Some(job)) = (started, data["job"].as_str()) {
                    tracing::info!(cloud = %self.name, peer = %member.name, %job, "a job stopped before it started was started on the member; stopping it there");
                    self.stop_stray(&member.name, job);
                }
            } else {
                let key = em.command_key().to_string();
                let (sender, _) = Self::sender_of(&key);
                // The promise made at admission is kept until the member starts the workload, or fails to.
                if !matches!(r#type.as_str(), "ImagePulling" | "ImagePulled") && !key.is_empty() {
                    self.state.lock().unwrap().reserved.remove(&key);
                }
                match r#type.as_str() {
                    "DeploymentStarted" | "JobStarted" => {
                        match &ordered {
                            Some((o, Some((holder, _)))) => {
                                data["order"] = json!(o);
                                data["holder"] = json!(holder);
                            }
                            _ if !sender.is_empty() => data["holder"] = json!(holder_of_hash(sender)),
                            _ => {}
                        }
                        if let Some(w) = data["deployment"].as_str().or(data["job"].as_str()) {
                            em.bind_workload(w);
                        }
                    }
                    _ => {}
                }
                if let Some(n) = note.as_ref().and_then(|n| n.as_object()) {
                    for (k, v) in n {
                        data[k] = v.clone();
                    }
                }
                self.tell(&em, &r#type, data);
                if TERMINAL.contains(&r#type.as_str()) {
                    if let Some(mc) = e.correlationid.as_deref() {
                        self.issued
                            .lock()
                            .unwrap()
                            .remove(&(member.name.clone(), mc.to_string()));
                    }
                    self.forget_ended_orders();
                    self.kick();
                }
            }
        }
        self.cursors.lock().unwrap().insert(member.name.clone(), id.to_string());
        self.save();
    }

    /// Stops what listens for orders that ended: a job stopped by a stop-job ends under the stop's correlation, and
    /// its order's own listener would otherwise wait for nothing.
    fn forget_ended_orders(&self) {
        let mut live: HashSet<String> = self.state.lock().unwrap().orders.keys().cloned().collect();
        live.extend(self.stopped_unstarted.lock().unwrap().iter().cloned());
        self.issued
            .lock()
            .unwrap()
            .retain(|_, i| i.order.as_ref().is_none_or(|o| live.contains(o)));
    }

    /// Stops `job` on `member` as the cloud's own command, telling nothing under any caller's correlation.
    fn stop_stray(&self, member: &str, job: &str) {
        let (Some(me), Some(m)) = (self.me.upgrade(), self.member(member)) else {
            return;
        };
        let job = job.to_string();
        tokio::spawn(async move {
            let em = me.emitter(&format!("{}/{}", me.name, m.name));
            if let Err(e) = me.place_on(&m, &em, "StopJob", "stop-job", json!({ "job": job })).await {
                tracing::warn!(cloud = %me.name, peer = %m.name, %job, why = %e.message, "a job stopped before it started could not be stopped on the member");
            }
        });
    }

    /// A pull is on every member at once: progress is relayed as it comes, the outcome is told once all answered,
    /// a member that fails or is lost counted as failed. A member that has its image is not the cloud's pull ended,
    /// so a member's share is relayed as 99 at most, and 100 is the cloud's own, told with ImagePulled.
    fn on_pull_fact(&self, member: &Member, key: &str, em: &Emitter, r#type: &str, mut data: Value) {
        if r#type == "ImagePulling" {
            if let Some(pct) = data["progress_pct"].as_u64() {
                data["progress_pct"] = json!(pct.min(99));
            }
            self.tell(em, r#type, data);
            return;
        }
        let done = {
            let mut pulls = self.pulls.lock().unwrap();
            let Some(p) = pulls.get_mut(key) else { return };
            match r#type {
                "ImagePulled" => {
                    p.pending.remove(&member.name);
                }
                "ImagePullFailed" | "CommandFailed" => {
                    p.pending.remove(&member.name);
                    p.failed.push(format!(
                        "{}: {}",
                        member.name,
                        data["reason"].as_str().unwrap_or("failed")
                    ));
                }
                _ => return,
            }
            p.pending.is_empty().then(|| pulls.remove(key)).flatten()
        };
        if let Some(p) = done {
            self.issued
                .lock()
                .unwrap()
                .retain(|_, i| i.pull.as_deref() != Some(key));
            if p.failed.is_empty() {
                self.tell(em, "ImagePulling", json!({ "image": p.image, "progress_pct": 100 }));
                self.tell(em, "ImagePulled", json!({ "image": p.image }));
            } else {
                self.tell(
                    em,
                    "ImagePullFailed",
                    json!({ "image": p.image, "reason": p.failed.join("; "), "fix": "check the image name and the tag, and that every member reaches the registry" }),
                );
            }
        }
    }

    /// Follows every member for as long as the cloud runs: signs in where it is not admitted yet, or no longer is,
    /// then relays the member's stream, reconnecting from the last event it relayed; and squares the state with the
    /// members on a timer. A member added later is followed from the moment it is added. Following is begun once:
    /// a second call changes nothing.
    pub fn follow(self: &Arc<Self>) {
        if self.following.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        for m in self.members() {
            self.follow_member(&m);
        }
        // Orders that waited across a restart are placed as soon as the members answer.
        self.kick();
        let me = self.clone();
        *self.ticking.lock().unwrap() = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(RECONCILE_EVERY).await;
                me.reconcile().await;
            }
        }));
    }

    fn follow_member(self: &Arc<Self>, member: &Arc<Member>) {
        let (me, member) = (self.clone(), member.clone());
        let name = member.name.clone();
        let task = tokio::spawn(async move {
            loop {
                if !member.admitted() {
                    me.sign_in(&member).await;
                }
                let last = me.cursors.lock().unwrap().get(&member.name).cloned();
                match member.stream(last.as_deref()).await {
                    Ok(stream) => {
                        match read_until_stopped(stream, STREAM_SILENCE, |id, e| me.relay(&member, &id, &e)).await {
                            Stopped::Ended => {
                                tracing::info!(cloud = %me.name, peer = %member.name, "the member's stream ended; reconnecting")
                            }
                            Stopped::Silent => {
                                tracing::info!(cloud = %me.name, peer = %member.name, "the member's stream went silent; reconnecting")
                            }
                        }
                    }
                    Err(e) if e.is_unauthorized() => {
                        tracing::warn!(cloud = %me.name, peer = %member.name, "the member no longer honours this cloud's credential; signing in again");
                        member.clear_key();
                        me.save();
                        continue;
                    }
                    Err(e) => {
                        tracing::debug!(cloud = %me.name, peer = %member.name, why = %e.text(), "the member's stream is not open");
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        if let Some(old) = self.tasks.lock().unwrap().insert(name, task) {
            old.abort();
        }
    }

    /// Stops following the members: nothing more is relayed or squared. What the cloud placed stays in its state.
    pub fn halt(&self) {
        for (_, t) in self.tasks.lock().unwrap().drain() {
            t.abort();
        }
        if let Some(t) = self.ticking.lock().unwrap().take() {
            t.abort();
        }
    }

    /// Changes the members to `members`: one kept (same endpoint) keeps its credential, its cursor and its stream;
    /// one removed is no longer followed; one added is signed in to and followed, when the cloud is following.
    pub fn reconfigure(self: &Arc<Self>, members: &[(String, String)]) {
        let before = self.members();
        let saved = self.file.as_deref().map(read_saved).unwrap_or_default();
        let mut after: Vec<Arc<Member>> = Vec::new();
        let mut added: Vec<Arc<Member>> = Vec::new();
        for (name, endpoint) in members {
            let endpoint = endpoint.trim_end_matches('/');
            match before.iter().find(|m| m.endpoint == endpoint) {
                Some(kept) if kept.name == *name => after.push(kept.clone()),
                kept => {
                    // A new machine, or one renamed: the credential is the machine's to keep, the name is ours. A
                    // machine that admitted this cloud before (its credential in the file) is admitted still.
                    let key = kept.and_then(|k| k.key()).or_else(|| {
                        saved
                            .iter()
                            .find(|s| s.endpoint == endpoint)
                            .and_then(|s| s.key.clone())
                    });
                    let m = Arc::new(Member::new(name, endpoint, key, self.transport.clone()));
                    if let Some(k) = kept {
                        let mut cursors = self.cursors.lock().unwrap();
                        if let Some(c) = cursors.remove(&k.name) {
                            cursors.insert(name.clone(), c);
                        }
                    }
                    added.push(m.clone());
                    after.push(m);
                }
            }
        }
        let gone: Vec<Arc<Member>> = before
            .iter()
            .filter(|b| !after.iter().any(|a| Arc::ptr_eq(a, b)))
            .cloned()
            .collect();
        *self.members.lock().unwrap() = after;
        {
            let mut tasks = self.tasks.lock().unwrap();
            for g in &gone {
                if let Some(t) = tasks.remove(&g.name) {
                    t.abort();
                }
                self.reachable.lock().unwrap().remove(&g.name);
                self.cursors.lock().unwrap().remove(&g.name);
            }
        }
        if self.following.load(std::sync::atomic::Ordering::SeqCst) {
            for m in &added {
                self.follow_member(m);
            }
        }
        self.save();
    }

    /// The device-flow sign-in with a member, until it admits this cloud: the code goes to the log for the person
    /// at that member's machine, a code that expires is asked again.
    async fn sign_in(&self, member: &Member) {
        let label = format!(
            "cloud {} of workspace {} at {}",
            self.name, self.workspace, self.endpoint
        );
        let connection = self.connection_name();
        loop {
            let asked = match member
                .sign_in_form(
                    "/auth/device",
                    &[
                        ("client_id", "best-peer"),
                        ("connection", &connection),
                        ("agent_label", &label),
                    ],
                )
                .await
            {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(cloud = %self.name, peer = %member.name, why = %e.text(), "the member did not start the sign-in; trying again in five seconds");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let (Some(user_code), Some(device_code)) = (asked["user_code"].as_str(), asked["device_code"].as_str())
            else {
                tracing::warn!(cloud = %self.name, peer = %member.name, "the member's sign-in answer has no code; trying again in five seconds");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            let interval = asked["interval"].as_u64().unwrap_or(5).max(1);
            tracing::info!(cloud = %self.name, workspace = %self.workspace, peer = %member.name, code = %user_code, "to admit cloud {} of workspace {} on {}, run on that machine: best-peer approve {user_code}", self.name, self.workspace, member.name);
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                match member
                    .sign_in_form(
                        "/auth/token",
                        &[
                            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                            ("device_code", device_code),
                            ("client_id", "best-peer"),
                        ],
                    )
                    .await
                {
                    Ok(token) => {
                        if let Some(key) = token["access_token"].as_str() {
                            member.set_key(key.to_string());
                            self.save();
                            tracing::info!(cloud = %self.name, peer = %member.name, "admitted by the member");
                            self.contact(member, true, "");
                            return;
                        }
                    }
                    Err(Refusal::Refused { body, .. }) => match body["error"].as_str() {
                        Some("authorization_pending") | Some("slow_down") => continue,
                        Some(other) => {
                            tracing::info!(cloud = %self.name, peer = %member.name, %other, "the sign-in code is no longer good; a new one follows");
                            break;
                        }
                        None => continue,
                    },
                    Err(Refusal::Unreachable(why)) => {
                        tracing::debug!(cloud = %self.name, peer = %member.name, %why, "the member did not answer the token poll");
                    }
                }
            }
        }
    }

    /// Squares the state with every member, all at once: a member that does not answer is told as lost, with every
    /// workload it held told as ended and every command in flight there failed; a workload a member no longer lists
    /// at two ticks running ended while nobody watched, and is told so; a member back after being lost that still
    /// runs a workload of this cloud's, told as ended meanwhile, is asked to end it, so the two say the same.
    pub async fn reconcile(&self) {
        futures::future::join_all(
            self.members()
                .into_iter()
                .filter(|m| m.admitted())
                .map(|m| async move { self.reconcile_member(&m).await }),
        )
        .await;
        // The tick is also when bounds are checked and what waits is tried again.
        self.kick();
    }

    async fn reconcile_member(&self, m: &Arc<Member>) {
        let held: Vec<(String, bool)> = {
            let s = self.state.lock().unwrap();
            s.deployments
                .values()
                .filter(|d| d.peer.as_deref() == Some(&m.name))
                .map(|d| (d.id.clone(), true))
                .chain(
                    s.jobs
                        .values()
                        .filter(|j| j.peer.as_deref() == Some(&m.name))
                        .map(|j| (j.id.clone(), false)),
                )
                .collect()
        };
        match m.query("get-workloads").await {
            Ok(w) => {
                let contact = self.contact(m, true, "");
                let runs = |id: &str, deployment: bool| {
                    let list = if deployment { &w["deployments"] } else { &w["jobs"] };
                    let field = if deployment { "deployment" } else { "job" };
                    list.as_array()
                        .is_some_and(|l| l.iter().any(|x| x[field].as_str() == Some(id)))
                };
                for (id, deployment) in &held {
                    if runs(id, *deployment) {
                        self.missing.lock().unwrap().remove(id);
                    } else if self.missing.lock().unwrap().insert(id.clone()) {
                        // Not listed for the first time: its end may still be on its way on the stream.
                    } else {
                        self.end(
                            id,
                            *deployment,
                            &format!("peer {} no longer runs it; its end was not observed", m.name),
                        );
                    }
                }
                if contact == Contact::Joined {
                    self.reclaim(m, &w, &held).await;
                }
            }
            Err(e) if e.is_unauthorized() => {
                tracing::warn!(cloud = %self.name, peer = %m.name, "the member no longer honours this cloud's credential; signing in again");
                m.clear_key();
                self.save();
            }
            Err(e) => {
                if self.contact(m, false, &e.text()) == Contact::Lost {
                    self.lost(m, &held);
                }
            }
        }
    }

    /// A member is lost: every workload it held ends now, whatever its phase, and every command in flight there
    /// that no fact can complete any more is failed. An order it held, running or sent and not started, is queued
    /// again, once; the second time it fails.
    fn lost(&self, m: &Member, held: &[(String, bool)]) {
        let why = format!("peer {} is unreachable", m.name);
        for (id, deployment) in held {
            if !deployment {
                let order = self.state.lock().unwrap().order_of_job(id);
                if let Some(o) = order {
                    self.missing.lock().unwrap().remove(id);
                    self.queue_again(&o, Some(id), &m.name, &why);
                    continue;
                }
            }
            self.end(id, *deployment, &why);
        }
        let sent: Vec<Order> = self
            .state
            .lock()
            .unwrap()
            .orders
            .values()
            .filter(|o| o.job.is_none() && o.placed.as_ref().is_some_and(|(p, _)| *p == m.name))
            .cloned()
            .collect();
        for o in sent {
            self.queue_again(&o, None, &m.name, &why);
        }
        let in_flight: Vec<((String, String), Issued)> = {
            let mut issued = self.issued.lock().unwrap();
            let keys: Vec<(String, String)> = issued.keys().filter(|(p, _)| *p == m.name).cloned().collect();
            keys.into_iter()
                .filter_map(|k| issued.remove(&k).map(|i| (k, i)))
                .collect()
        };
        for ((_, mc), i) in in_flight {
            let key = i.em.command_key().to_string();
            if i.order.is_some() {
                // Queued again or failed above.
                continue;
            }
            if let Some(pull) = &i.pull {
                self.on_pull_fact(m, pull, &i.em, "ImagePullFailed", json!({ "reason": why }));
            } else if i.r#type == "Prompt" {
                // The answer is not coming: the prompt is told as failed, to be sent again when the peer is back.
                self.tell(
                    &i.em,
                    "PromptFailed",
                    json!({ "reason": why, "fix": "prompt again once the peer answers: PeerJoined on this stream says so", "peer": m.name }),
                );
            } else if i.ends.is_some() || key.is_empty() {
                self.tell(
                    &i.em,
                    "CommandFailed",
                    json!({ "type": mc, "reason": format!("{why}; what it was to end is told as ended") }),
                );
            } else {
                let (sender, id) = Self::sender_of(&key);
                if self.log.workload_of(sender, id).is_none() {
                    // Never started there: nothing of it exists to be told as ended.
                    self.state.lock().unwrap().reserved.remove(&key);
                    self.tell(
                        &i.em,
                        "CommandFailed",
                        json!({ "type": mc, "reason": format!("{why} before the workload started; send it again when it answers") }),
                    );
                }
            }
        }
    }

    /// A member back after being lost still runs what this cloud told as ended meanwhile: the cloud ends it there.
    async fn reclaim(&self, m: &Arc<Member>, w: &Value, held: &[(String, bool)]) {
        let mine = self.holder_on(m);
        let known = |id: &str| held.iter().any(|(h, _)| h == id);
        let stray = |list: &Value, field: &str| -> Vec<String> {
            list.as_array()
                .map(|l| {
                    l.iter()
                        .filter(|x| x["holder"].as_str() == mine.as_deref())
                        .filter_map(|x| x[field].as_str().map(str::to_string))
                        .filter(|id| !known(id))
                        .collect()
                })
                .unwrap_or_default()
        };
        let correlation = format!("{}/{}", self.name, m.name);
        for id in stray(&w["deployments"], "deployment") {
            tracing::info!(cloud = %self.name, peer = %m.name, deployment = %id, "the member still runs a deployment this cloud told as ended; ending it there");
            let em = self.emitter(&correlation);
            let _ = self
                .place_on(m, &em, "UndeployModel", "undeploy-model", json!({ "deployment": id }))
                .await;
        }
        for id in stray(&w["jobs"], "job") {
            tracing::info!(cloud = %self.name, peer = %m.name, job = %id, "the member still runs a job this cloud told as ended; stopping it there");
            let em = self.emitter(&correlation);
            let _ = self.place_on(m, &em, "StopJob", "stop-job", json!({ "job": id })).await;
        }
    }

    /// Tells the end of a workload the cloud can no longer see, once; one already ending is ended too, since
    /// whatever was ending it cannot say so any more.
    fn end(&self, id: &str, deployment: bool, reason: &str) {
        let (correlation, model_or_image, peer) = {
            let mut s = self.state.lock().unwrap();
            if deployment {
                match s.deployments.get_mut(id) {
                    Some(d) => {
                        d.phase = Phase::Ending;
                        (d.correlation.clone(), d.model.clone(), d.peer.clone())
                    }
                    None => return,
                }
            } else {
                match s.jobs.get_mut(id) {
                    Some(j) => {
                        j.phase = JobPhase::Stopping;
                        (j.correlation.clone(), j.image.0.clone(), j.peer.clone())
                    }
                    None => return,
                }
            }
        };
        self.missing.lock().unwrap().remove(id);
        let em = self.emitter(&correlation);
        if deployment {
            self.tell(
                &em,
                "DeploymentEnded",
                json!({ "deployment": id, "model": model_or_image, "exit_code": null, "reason": reason, "peer": peer }),
            );
        } else {
            self.tell(
                &em,
                "JobFailed",
                json!({ "job": id, "image": model_or_image, "reason": reason, "fix": "run it again once the peer is back", "peer": peer }),
            );
        }
    }

    // ----- the queue ----------------------------------------------------------------------------------------------

    /// An order a lost member held, running or sent and not started, waits again, once, keeping its place: the job
    /// it had become, `instead_of`, is gone with the member. The second time it fails.
    fn queue_again(&self, o: &Order, instead_of: Option<&str>, peer: &str, why: &str) {
        let em = self.order_emitter(o);
        if o.attempt >= 2 {
            self.tell(
                &em,
                "JobFailed",
                json!({ "job": instead_of.unwrap_or(&o.id), "image": o.image, "reason": format!("{why}, and the order was queued again once already"), "fix": "order it again once the cloud's peers answer: PeerJoined on this stream says so", "peer": peer }),
            );
            return;
        }
        self.promise(o, None);
        self.tell(
            &em,
            "JobQueued",
            queued_fact(
                o,
                o.attempt + 1,
                true,
                Some(format!("{why}; queued again, once")),
                instead_of,
            ),
        );
        self.kick();
    }

    /// Starts a placement step, unless one runs, which then runs once more when it ends.
    fn kick(&self) {
        if self.stepping.swap(true, Ordering::SeqCst) {
            self.again.store(true, Ordering::SeqCst);
            return;
        }
        let Some(me) = self.me.upgrade() else {
            self.stepping.store(false, Ordering::SeqCst);
            return;
        };
        tokio::spawn(async move {
            loop {
                me.again.store(false, Ordering::SeqCst);
                me.step(OffsetDateTime::now_utc()).await;
                if me.again.load(Ordering::SeqCst) {
                    continue;
                }
                me.stepping.store(false, Ordering::SeqCst);
                // Asked for between the last look and now: this task takes it, unless another already has.
                if me.again.load(Ordering::SeqCst) && !me.stepping.swap(true, Ordering::SeqCst) {
                    continue;
                }
                break;
            }
        });
    }

    /// One placement step at `now`: an order waiting past its `queue_seconds` ends unplaced; a job running past its
    /// `deadline_seconds` is stopped; then every order that waits, oldest first, is placed where a member has the
    /// room, an order that does not fit holding back none after it.
    pub async fn step(&self, now: OffsetDateTime) {
        let _one = self.steps.lock().await;
        let (expired, overdue) = {
            let s = self.state.lock().unwrap();
            let expired: Vec<Order> = s
                .waiting()
                .into_iter()
                .filter(|o| past(Some(&o.queued_at), o.queue_seconds, now))
                .collect();
            let overdue: Vec<(Order, String, Option<String>)> = s
                .orders
                .values()
                .filter(|o| past(o.started_at.as_deref(), o.deadline_seconds, now))
                .filter_map(|o| {
                    let j = s.jobs.get(o.job.as_deref()?)?;
                    (j.phase == JobPhase::Running).then(|| (o.clone(), j.id.clone(), j.peer.clone()))
                })
                .collect();
            (expired, overdue)
        };
        for o in expired {
            self.tell(
                &self.order_emitter(&o),
                "JobFailed",
                json!({ "job": o.id, "image": o.image, "reason": format!("no member peer had the room for it within its queue_seconds ({} s): it was never placed", o.queue_seconds.unwrap_or(0)), "fix": "order it again with a longer queue_seconds or less memory_bytes, or when get-workloads shows room" }),
            );
        }
        for (o, job, peer) in overdue {
            let Some(m) = peer.as_deref().and_then(|p| self.member(p)) else {
                continue;
            };
            if let Some(j) = self.state.lock().unwrap().jobs.get_mut(&job) {
                j.phase = JobPhase::Stopping;
            }
            let note = json!({ "reason": format!("it ran past its deadline_seconds ({} s), so the door stopped it", o.deadline_seconds.unwrap_or(0)) });
            let stopped = self
                .place_on_noting(
                    &m,
                    &self.emitter(&o.correlation),
                    "StopJob",
                    "stop-job",
                    json!({ "job": job }),
                    Some(note),
                )
                .await;
            if let Err(e) = stopped {
                tracing::warn!(cloud = %self.name, peer = %m.name, %job, why = %e.message, "a job past its deadline could not be stopped; trying again at the next tick");
                if let Some(j) = self.state.lock().unwrap().jobs.get_mut(&job) {
                    j.phase = JobPhase::Running;
                }
            }
        }
        let waiting = self.state.lock().unwrap().waiting();
        if waiting.is_empty() {
            return;
        }
        let (host, _, isolations) = self.combined().await;
        for o in waiting {
            let device = {
                let mut s = self.state.lock().unwrap();
                // Stopped while the members were read.
                if !s.orders.get(&o.id).is_some_and(|x| x.waiting()) {
                    continue;
                }
                let isolated = Self::offering(&host, &isolations, o.isolation);
                let pick = match o.memory_bytes {
                    Some(needed) => {
                        let on = if o.accelerators_only {
                            accelerators(&isolated)
                        } else {
                            isolated
                        };
                        place(&on, &s, &any_compute(), needed, o.device.as_deref(), "", None)
                            .ok()
                            .map(|(d, _)| d)
                    }
                    None => self
                        .first_up(&isolated, o.isolation)
                        .map(|m| DeviceId(format!("{}/{}/", self.name, m))),
                };
                let Some(device) = pick else {
                    continue;
                };
                // Promised there now, so the next order in this step sees the room taken.
                if let Some(r) = s.reserved.values_mut().find(|r| r.id == o.id) {
                    r.device = Some(device.clone());
                }
                device
            };
            self.dispatch(&o, device).await;
        }
    }

    /// Sends order `o` to the member `device` names, after telling `JobPlaced`. A member that turns out to have no
    /// room, or does not answer, leaves the order waiting where it was; any other refusal fails it, with the
    /// member's reason.
    async fn dispatch(&self, o: &Order, device: DeviceId) {
        let em = self.order_emitter(o);
        let fail = |reason: String, fix: &str, peer: Option<&str>| {
            self.tell(
                &em,
                "JobFailed",
                json!({ "job": o.id, "image": o.image, "reason": reason, "fix": fix, "peer": peer }),
            );
        };
        let Some((member, member_device)) = self
            .split_device(&device.0)
            .and_then(|(peer, d)| self.member(peer).map(|m| (m, d.to_string())))
        else {
            fail(
                format!("device {} names no member of this cloud", device.0),
                "get-hardware-state lists the devices; order it again on one of them",
                None,
            );
            return;
        };
        let with_device = o.memory_bytes.is_some();
        self.tell(
            &em,
            "JobPlaced",
            json!({ "job": o.id, "peer": member.name, "device": with_device.then(|| device.0.clone()) }),
        );
        let mut body = json!({ "image": o.image, "args": o.args });
        if let Some(m) = o.memory_bytes {
            body["memory_bytes"] = json!(m);
            body["device"] = json!(member_device);
        }
        // The member checks the ask against its own engine as it is now, which may have changed since it was read.
        // Only above process: a member older than isolation takes nothing more, and refuses a field it does not know.
        if let Some(i) = o.isolation.filter(|i| *i > Isolation::Process) {
            body["isolation"] = json!(i);
        }
        let mc = order_correlation(o);
        let base = member.schema_base().await;
        let envelope = self.to_member_as(&base, &mc, "RunJob", "run-job", body);
        self.listen_order(&member.name, &mc, &em, &o.id);
        let Err(e) = member.send(&envelope).await else {
            return;
        };
        self.issued.lock().unwrap().remove(&(member.name.clone(), mc));
        let room = match &e {
            Refusal::Unreachable(_) => true,
            Refusal::Refused { body, .. } => body["error"]["code"] == "INSUFFICIENT_MEMORY",
        };
        let refused = e.relayed(&member.name);
        if room {
            // Waiting again, in its place: the next step tries it on whatever has the room then.
            self.promise(o, None);
            self.tell(
                &em,
                "JobQueued",
                queued_fact(o, o.attempt, true, Some(refused.message), None),
            );
        } else {
            fail(
                refused.message,
                "read the peer's refusal in the reason, then order it again",
                Some(&member.name),
            );
        }
    }

    /// A placement refused with every member's room says which members were not asked, and why.
    fn with_peers(mut e: BestError, peers: Vec<Value>) -> BestError {
        if let Some(o) = e.details.as_object_mut() {
            o.insert("peers".into(), json!(peers));
        }
        e
    }
}

#[async_trait]
impl Service for Cloud {
    async fn hardware_state(&self, who: &Credential) -> Result<Value, BestError> {
        let (host, peers, isolations) = self.combined().await;
        let host = shown_to(host, who);
        let mut v = crate::domain::host_state(&host);
        if let Some(devices) = v["devices"].as_array_mut() {
            for d in devices {
                let id = d["id"].as_str().unwrap_or_default().to_string();
                d["isolation"] = json!(isolations.get(&id).copied().unwrap_or(Isolation::Process));
                let peer = self.split_device(&id).map(|(peer, _)| peer.to_string());
                if let Some(peer) = peer {
                    d["cloud"] = json!(self.name);
                    d["peer"] = json!(peer);
                }
            }
        }
        v["peers"] = json!(peers);
        Ok(v)
    }

    fn workloads(&self, who: &Credential) -> Result<Value, BestError> {
        let held = self.holdings.held_by(&who.holder());
        let s = self.state.lock().unwrap();
        let mut v = workloads_view(&s, who, Some(&self.name));
        v["held_bytes"] = json!(held);
        // The orders not started yet, oldest first: each waits, or was sent to the peer named.
        let mut orders: Vec<&Order> = s
            .orders
            .values()
            .filter(|o| o.job.is_none() && (who.grant.is_all() || o.holder == who.holder()))
            .collect();
        orders.sort_by_key(|o| o.arrival);
        v["queued"] = json!(orders
            .iter()
            .map(|o| json!({
                "job": o.id, "cloud": self.name, "image": o.image, "memory_bytes": o.memory_bytes, "device": o.device,
                "holder": o.holder, "attempt": o.attempt, "queued_at": o.queued_at,
                "queue_seconds": o.queue_seconds, "waiting": o.waiting(), "peer": o.placed.as_ref().map(|(p, _)| p)
            }))
            .collect::<Vec<_>>());
        Ok(v)
    }

    fn admit_pull(&self, _cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")
    }

    async fn pull_image(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let image = cmd.data["image"].as_str().unwrap_or_default().to_string();
        let members = self.up();
        if members.is_empty() {
            self.tell(
                &em,
                "ImagePullFailed",
                json!({ "image": image, "reason": "no member peer answers", "fix": "get-hardware-state lists the members and their state" }),
            );
            return;
        }
        let key = em.command_key().to_string();
        self.pulls.lock().unwrap().insert(
            key.clone(),
            Pull {
                image: image.clone(),
                pending: members.iter().map(|m| m.name.clone()).collect(),
                failed: Vec::new(),
            },
        );
        for m in members {
            let base = m.schema_base().await;
            let (envelope, mc) = self.to_member(&m, &base, &key, "PullImage", "pull-image", json!({ "image": image }));
            self.listen_for(&m.name, &mc, &em, "PullImage", Some(key.clone()), None);
            if let Err(e) = m.send(&envelope).await {
                self.issued.lock().unwrap().remove(&(m.name.clone(), mc));
                self.on_pull_fact(
                    &m,
                    &key,
                    &em,
                    "ImagePullFailed",
                    json!({ "image": image, "reason": e.relayed(&m.name).message }),
                );
            }
        }
    }

    async fn admit_deploy(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "deploy")?;
        let data: DeployData = parse(&cmd.data)?;
        if self.already_placed(&key).is_some() {
            return Ok(());
        }
        let (host, peers, isolations) = self.combined().await;
        let host = usable_by(host, &who, data.device.as_deref()).map_err(|e| Self::with_peers(e, peers.clone()))?;
        let host = self
            .held_to(host, &isolations, data.isolation)
            .map_err(|e| Self::with_peers(e, peers.clone()))?;
        // One admission at a time across the door, and what the credential holds is read before the state is
        // locked, since the door's holdings read this state too.
        let _admitting = self.holdings.admitting();
        let held = self.holdings.of(&who.holder());
        let mut state = self.state.lock().unwrap();
        within_share(held.memory_bytes, &who, data.memory_bytes)?;
        within_count("deployment", held.deployments, who.grant.deployments)?;
        let (device, compute) = place(
            &host,
            &state,
            &data.engine.runs_on(),
            data.memory_bytes,
            data.device.as_deref(),
            &format!("{} on {}", data.model, data.engine),
            mine(&who).as_deref(),
        )
        .map_err(|e| Self::with_peers(e, peers))?;
        state.reserved.insert(
            key,
            Reservation {
                id: new_id("dep"),
                device: Some(device),
                compute: Some(compute),
                memory_bytes: data.memory_bytes,
                holder: who.holder(),
                boxed: false,
            },
        );
        Ok(())
    }

    async fn deploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = parse::<DeployData>(&cmd.data) else {
            return;
        };
        // Run again after a restart: the member runs it; listen for the rest of its facts and say nothing twice.
        if let Some(peer) = self.already_placed(em.command_key()) {
            let mc = member_correlation(em.command_key(), &json!({}), None);
            self.listen_for(&peer, &mc, &em, "DeployModel", None, None);
            return;
        }
        let reservation = self.state.lock().unwrap().reserved.get(em.command_key()).cloned();
        let Some(Reservation {
            id,
            device: Some(device),
            ..
        }) = reservation
        else {
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": "the command was accepted but its placement is gone; send it again" }),
            );
            return;
        };
        let member = self
            .split_device(&device.0)
            .and_then(|(peer, d)| self.member(peer).map(|m| (m, d)));
        let Some((member, member_device)) = member else {
            self.tell(
                &em,
                "DeploymentFailed",
                json!({ "deployment": id, "model": data.model, "reason": format!("device {} names no member of this cloud", device.0), "fix": "get-hardware-state lists the devices; deploy again on one of them" }),
            );
            return;
        };
        let placed = self
            .place_on(
                &member,
                &em,
                "DeployModel",
                "deploy-model",
                {
                    let mut body = json!({ "model": data.model, "engine": data.engine, "memory_bytes": data.memory_bytes, "device": member_device });
                    if let Some(i) = data.isolation.filter(|i| *i > Isolation::Process) {
                        body["isolation"] = json!(i);
                    }
                    body
                },
            )
            .await;
        if let Err(e) = placed {
            self.tell(
                &em,
                "DeploymentFailed",
                json!({ "deployment": id, "model": data.model, "reason": e.message, "fix": "read the peer's refusal in the reason, then deploy again", "peer": member.name }),
            );
        }
    }

    fn admit_undeploy(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "deploy")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        let mut s = self.state.lock().unwrap();
        let live: Vec<String> = s
            .deployments
            .values()
            .filter(|d| who.grant.is_all() || d.holder == who.holder())
            .map(|d| d.id.clone())
            .collect();
        match s.deployments.get_mut(id) {
            None => Err(BestError::bad_request(
                "NO_SUCH_DEPLOYMENT",
                format!(
                    "no deployment {id}: the live ones are {}; get-workloads lists them",
                    crate::lifecycle::list(live.iter())
                ),
            )
            .with_details(json!({ "deployment": id, "live": live }))),
            Some(d) if !who.grant.is_all() && d.holder != who.holder() => Err(not_yours("deployment", id)),
            Some(d) if d.phase == Phase::Ending => Err(BestError::bad_request(
                "ALREADY_ENDING",
                format!("deployment {id} is already ending: its Undeployed or DeploymentFailed event follows"),
            )
            .with_details(json!({ "deployment": id }))),
            Some(d) => {
                d.phase = Phase::Ending;
                Ok(())
            }
        }
    }

    async fn undeploy(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = cmd.data["deployment"].as_str().unwrap_or_default().to_string();
        let Some(d) = self.state.lock().unwrap().deployments.get(&id).cloned() else {
            self.tell(&em, "Undeployed", json!({ "deployment": id, "model": null }));
            return;
        };
        let member = d.peer.as_deref().and_then(|p| self.member(p));
        let outcome = match &member {
            Some(m) => {
                self.place_on(m, &em, "UndeployModel", "undeploy-model", json!({ "deployment": id }))
                    .await
            }
            None => Err(BestError::internal(format!("deployment {id} names no member peer"))),
        };
        if let Err(e) = outcome {
            if let Some(d) = self.state.lock().unwrap().deployments.get_mut(&id) {
                d.phase = if d.ready { Phase::Ready } else { Phase::Starting };
            }
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": format!("{}; the deployment stays", e.message) }),
            );
        }
    }

    async fn admit_run_job(&self, cmd: Envelope, who: Credential, key: String) -> Result<(), BestError> {
        require(&who, "jobs")?;
        let data: RunJobData = parse(&cmd.data)?;
        if data.device.is_some() && data.memory_bytes.is_none() {
            return Err(BestError::bad_request(
                "DEVICE_NEEDS_MEMORY",
                "device names a device but memory_bytes is missing: send memory_bytes with it, or omit device to run with none",
            )
            .with_details(json!({ "field": "memory_bytes" })));
        }
        if has_share(&who) && data.memory_bytes.is_none() {
            return Err(BestError::bad_request(
                "JOB_NEEDS_DEVICE",
                "this credential has a share, so its jobs run on a device, where the share counts them, never on the host with no device: send memory_bytes, the device memory the job needs",
            )
            .with_details(json!({ "field": "memory_bytes" })));
        }
        // Run again after a restart: placed before orders were told, or an order the fold already holds.
        if self.already_placed(&key).is_some() || self.state.lock().unwrap().orders.contains_key(&order_id(&key)) {
            return Ok(());
        }
        let (host, peers, isolations) = self.combined().await;
        let host = match data.memory_bytes {
            Some(_) => usable_by(host, &who, data.device.as_deref()).map_err(|e| Self::with_peers(e, peers.clone()))?,
            None => host,
        };
        let host = self
            .held_to(host, &isolations, data.isolation)
            .map_err(|e| Self::with_peers(e, peers.clone()))?;
        let _admitting = self.holdings.admitting();
        let held = self.holdings.of(&who.holder());
        let mut state = self.state.lock().unwrap();
        within_share(held.memory_bytes, &who, data.memory_bytes.unwrap_or(0))?;
        within_count("job", held.jobs, who.grant.jobs)?;
        let placement = match data.memory_bytes {
            Some(needed) => match place(
                &host,
                &state,
                &any_compute(),
                needed,
                data.device.as_deref(),
                &format!("a job from {}", data.image),
                mine(&who).as_deref(),
            ) {
                Ok(p) => Some(p),
                // No room now, where room can come free: the order is taken, and waits its turn.
                Err(e) if e.code == "INSUFFICIENT_MEMORY" && could_ever_hold(&host, needed, data.device.as_deref()) => {
                    None
                }
                Err(e) => return Err(Self::with_peers(e, peers)),
            },
            None => Some({
                // No device wanted: the first member answering takes it, which is the same one every time.
                let first = self.first_up(&host, data.isolation).ok_or_else(|| {
                    BestError::bad_request(
                        "NO_PEER",
                        format!(
                            "no member peer of cloud {} answers: get-hardware-state lists the members and their state",
                            self.name
                        ),
                    )
                    .with_details(json!({ "cloud": self.name, "peers": peers }))
                })?;
                (
                    DeviceId(format!("{}/{}/", self.name, first)),
                    best_peer_gpu::Compute::Cpu,
                )
            }),
        };
        if accelerators_only(&who) {
            self.held_to_accelerators.lock().unwrap().insert(key.clone());
        }
        state.reserved.insert(
            key.clone(),
            Reservation {
                id: order_id(&key),
                device: placement.as_ref().map(|(d, _)| d.clone()),
                compute: placement.map(|(_, c)| c),
                memory_bytes: data.memory_bytes.unwrap_or(0),
                holder: who.holder(),
                boxed: crate::lifecycle::boxed(&who),
            },
        );
        Ok(())
    }

    /// Takes the order: `JobQueued` holds it whole, then it is sent at once when admission found it the room, or
    /// waits for the placement step.
    async fn run_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let Ok(data) = parse::<RunJobData>(&cmd.data) else {
            return;
        };
        let key = em.command_key().to_string();
        let id = order_id(&key);
        self.keys.lock().unwrap().insert(id.clone(), key.clone());
        // Run again after a restart: the fold holds the order and the rebuild listens for it; the queue goes on.
        if self.state.lock().unwrap().orders.contains_key(&id) {
            self.kick();
            return;
        }
        // Placed before orders were told: the member runs it; listen for the rest of its facts.
        if let Some(peer) = self.already_placed(&key) {
            let mc = member_correlation(&key, &json!({}), None);
            self.listen_for(&peer, &mc, &em, "RunJob", None, None);
            return;
        }
        let reservation = self.state.lock().unwrap().reserved.get(&key).cloned();
        let Some(r) = reservation else {
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": "the command was accepted but its placement is gone; send it again" }),
            );
            return;
        };
        let waiting = r.device.is_none();
        let order = Order {
            id: id.clone(),
            correlation: em.correlation().to_string(),
            holder: r.holder.clone(),
            image: data.image.clone(),
            args: data.args.clone(),
            memory_bytes: data.memory_bytes,
            device: data.device.clone(),
            queue_seconds: Some(data.queue_seconds.unwrap_or(DEFAULT_QUEUE_SECONDS)),
            deadline_seconds: data.deadline_seconds,
            accelerators_only: self.held_to_accelerators.lock().unwrap().remove(&key),
            isolation: data.isolation,
            attempt: 1,
            queued_at: String::new(),
            arrival: 0,
            placed: None,
            job: None,
            started_at: None,
        };
        let reason = waiting.then(|| {
            format!(
                "no member peer of cloud {} has {} bytes free on a device that runs it now: it is placed as soon as one has, after the orders before it",
                self.name,
                data.memory_bytes.unwrap_or(0)
            )
        });
        self.tell(&em, "JobQueued", queued_fact(&order, 1, waiting, reason, None));
        match r.device {
            Some(device) => self.dispatch(&order, device).await,
            None => self.kick(),
        }
    }

    fn admit_stop_job(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "jobs")?;
        let named = cmd.data["job"].as_str().unwrap_or_default();
        let mut s = self.state.lock().unwrap();
        // An order: one not started is stopped here; one running is its job.
        let id = match s.orders.get(named) {
            Some(o) if !who.grant.is_all() && o.holder != who.holder() => return Err(not_yours("job", named)),
            Some(o) => match &o.job {
                None => return Ok(()),
                Some(j) => j.clone(),
            },
            None => named.to_string(),
        };
        let id = id.as_str();
        let running: Vec<String> = s
            .jobs
            .values()
            .filter(|j| who.grant.is_all() || j.holder == who.holder())
            .map(|j| j.id.clone())
            .collect();
        match s.jobs.get_mut(id) {
            None => Err(BestError::bad_request(
                "NO_SUCH_JOB",
                format!(
                    "no job {id} is running: the running ones are {}; get-workloads lists them",
                    crate::lifecycle::list(running.iter())
                ),
            )
            .with_details(json!({ "job": id, "running": running }))),
            Some(j) if !who.grant.is_all() && j.holder != who.holder() => Err(not_yours("job", id)),
            Some(j) if j.phase == JobPhase::Stopping => Err(BestError::bad_request(
                "ALREADY_STOPPING",
                format!("job {id} is already stopping: its JobStopped event follows"),
            )
            .with_details(json!({ "job": id }))),
            Some(j) => {
                j.phase = JobPhase::Stopping;
                Ok(())
            }
        }
    }

    async fn stop_job(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let named = cmd.data["job"].as_str().unwrap_or_default().to_string();
        // Not between a placement step's choice and its JobPlaced: the order is stopped either before it is sent,
        // or as one sent.
        let _no_step = self.steps.lock().await;
        let order = self.state.lock().unwrap().orders.get(&named).cloned();
        // An order not started ends before it started: under its own correlation, which completes it, and under
        // the stop's. A member it was sent to that starts it all the same is told to stop it when it says so.
        if let Some(o) = order.as_ref().filter(|o| o.job.is_none()) {
            if o.placed.is_some() {
                self.stopped_unstarted.lock().unwrap().insert(o.id.clone());
            }
            let stopped = json!({ "job": o.id, "reason": "stopped before it started" });
            self.tell(&self.order_emitter(o), "JobStopped", stopped.clone());
            self.tell(&em, "JobStopped", stopped);
            return;
        }
        let id = order.and_then(|o| o.job).unwrap_or(named);
        let Some(j) = self.state.lock().unwrap().jobs.get(&id).cloned() else {
            self.tell(&em, "JobStopped", json!({ "job": id }));
            return;
        };
        let member = j.peer.as_deref().and_then(|p| self.member(p));
        let outcome = match &member {
            Some(m) => self.place_on(m, &em, "StopJob", "stop-job", json!({ "job": id })).await,
            None => Err(BestError::internal(format!("job {id} names no member peer"))),
        };
        if let Err(e) = outcome {
            if let Some(j) = self.state.lock().unwrap().jobs.get_mut(&id) {
                j.phase = JobPhase::Running;
            }
            self.tell(
                &em,
                "CommandFailed",
                json!({ "type": cmd.r#type, "reason": format!("{}; the job keeps running", e.message) }),
            );
        }
    }

    fn admit_prompt(&self, cmd: Envelope, who: &Credential) -> Result<(), BestError> {
        require(who, "prompt")?;
        let id = cmd.data["deployment"].as_str().unwrap_or_default();
        ready_deployment(&self.state.lock().unwrap(), id, who).map(|_| ())
    }

    /// A prompt goes to the member that holds the deployment, as the member's own prompt command; its answer comes
    /// back on the member's stream and is relayed under the caller's correlation with the cloud and the peer named.
    async fn prompt(self: Arc<Self>, cmd: Envelope, em: Emitter) {
        let id = cmd.data["deployment"].as_str().unwrap_or_default().to_string();
        let member = self
            .state
            .lock()
            .unwrap()
            .deployments
            .get(&id)
            .and_then(|d| d.peer.clone())
            .and_then(|p| self.member(&p));
        let outcome = match &member {
            Some(m) => self.place_on(m, &em, "Prompt", "prompt", cmd.data.clone()).await,
            None => Err(BestError::internal(format!("deployment {id} names no member peer"))),
        };
        if let Err(e) = outcome {
            self.tell(
                &em,
                "PromptFailed",
                json!({ "deployment": id, "reason": e.message, "fix": "read the peer's refusal in the reason, then prompt again", "peer": member.map(|m| m.name.clone()) }),
            );
        }
    }
}

/// The id and correlation a member is given for a cloud command: unique to the cloud command (its sender's holder
/// and its id, the id hashed when that would be too long for an envelope), or, for a command of the cloud's own,
/// the cloud's identity on the member (`own`, the holder of its credential there) and the workload it ends, so a
/// cloud the member admitted again under a new credential owns its new correlations and is refused for none.
fn member_correlation(key: &str, data: &Value, own: Option<&str>) -> String {
    let (sender, id) = key.split_once(':').unwrap_or(("", key));
    match (sender.is_empty(), data["deployment"].as_str().or(data["job"].as_str())) {
        (true, Some(workload)) => format!("cloud-{}-{workload}", own.unwrap_or("none")),
        _ => {
            let holder = holder_of_hash(sender);
            if holder.len() + 1 + id.len() > 200 {
                format!("{holder}-{}", &hash_key(id)[..32])
            } else {
                format!("{holder}-{id}")
            }
        }
    }
}

/// The device memory a member has promised to its workloads, by its own device ids, from its `get-workloads`.
fn promised_by_device(w: &Value) -> HashMap<String, u64> {
    let mut out: HashMap<String, u64> = HashMap::new();
    for list in [&w["deployments"], &w["jobs"]] {
        for x in list.as_array().into_iter().flatten() {
            if let (Some(device), Some(bytes)) = (x["device"].as_str(), x["memory_bytes"].as_u64()) {
                *out.entry(device.to_string()).or_default() += bytes;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_command_is_named_for_the_cloud_command_and_fits_an_envelope() {
        let short = member_correlation("abcdef0123456789abcdef:d1", &json!({}), None);
        assert_eq!(short, "abcdef0123456789-d1");
        let long = member_correlation(&format!("abcdef0123456789abcdef:{}", "x".repeat(250)), &json!({}), None);
        assert!(long.len() <= 64, "{long}");
        assert!(long.starts_with("abcdef0123456789-"));
        assert_eq!(
            member_correlation(":anything", &json!({ "deployment": "dep-1" }), Some("0123456789abcdef")),
            "cloud-0123456789abcdef-dep-1",
            "a command of the cloud's own carries the cloud's identity on the member"
        );
    }

    /// A member's stream as the socket delivers it: `Alive` every `every`, `times` times, then the member closes it.
    fn keep_alives(every: Duration, times: usize) -> impl Stream<Item = Heard> {
        futures::stream::unfold(0usize, move |n| async move {
            if n == times {
                return None;
            }
            tokio::time::sleep(every).await;
            Some((Heard::Alive, n + 1))
        })
    }

    #[tokio::test]
    async fn a_quiet_member_whose_socket_is_alive_is_read_on_and_not_taken_for_silent() {
        // Keep-alives alone, each well inside the silence allowed, for longer than that silence: the stream is read
        // to its end and no event is relayed. Before the fix every keep-alive was swallowed by the parser, and a
        // member with nothing to tell for a minute was reconnected every minute. The margin between a step and the
        // silence is wide, so a loaded runner's stall is not taken for silence.
        let silence = Duration::from_millis(500);
        let mut relayed = 0;
        let stopped =
            read_until_stopped(keep_alives(Duration::from_millis(20), 30), silence, |_, _| relayed += 1).await;
        assert_eq!(stopped, Stopped::Ended);
        assert_eq!(relayed, 0);
    }

    #[tokio::test]
    async fn a_socket_with_nothing_on_it_for_the_silence_allowed_is_silent() {
        let started = tokio::time::Instant::now();
        let stopped = read_until_stopped(
            futures::stream::pending::<Heard>(),
            Duration::from_millis(60),
            |_, _| {},
        )
        .await;
        assert_eq!(stopped, Stopped::Silent);
        assert!(started.elapsed() >= Duration::from_millis(60));
    }

    #[tokio::test]
    async fn events_between_keep_alives_are_relayed_in_order() {
        let e = |t: &str| Envelope::event("s", t, json!({}), None, None);
        let items = vec![
            Heard::Alive,
            Heard::Event("1".into(), Box::new(e("A"))),
            Heard::Alive,
            Heard::Event("2".into(), Box::new(e("B"))),
        ];
        let mut got = Vec::new();
        let stopped = read_until_stopped(futures::stream::iter(items), Duration::from_secs(1), |id, e| {
            got.push((id, e.r#type))
        })
        .await;
        assert_eq!(stopped, Stopped::Ended);
        assert_eq!(
            got,
            vec![("1".to_string(), "A".to_string()), ("2".to_string(), "B".to_string())]
        );
    }
}
