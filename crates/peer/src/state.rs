//! The peer's own state: what is deployed and what runs, folded from the events the peer told. Every fact passes
//! through [`State::apply`], live and on replay, so the state after a restart is the state the log says.

use std::collections::{BTreeMap, HashMap};

use best_peer_door::Envelope;
use best_peer_engine::Kind;
use best_peer_gpu::{Compute, DeviceId};
use best_peer_runtime::{ContainerId, ImageRef};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The container runs; the engine is not yet serving the model.
    Starting,
    /// The model answers: the deployment takes prompts.
    Ready,
    /// An undeploy or a failure is ending it; its exit is expected and is not an ending of its own.
    Ending,
}

#[derive(Clone, Debug)]
pub struct Deployment {
    pub id: String,
    pub model: String,
    pub engine: Kind,
    pub device: DeviceId,
    pub memory_bytes: u64,
    pub container: ContainerId,
    /// The host port the engine is reached at.
    pub port: u16,
    pub ready: bool,
    /// The credential that deployed it, as `holder` in DeploymentStarted; empty for one told before holders existed.
    pub holder: String,
    /// The correlation id of the command that deployed it: what every later fact about it carries.
    pub correlation: String,
    pub phase: Phase,
    /// On a cloud, the member peer it was placed on, as `peer` in DeploymentStarted.
    pub peer: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    Running,
    /// A stop is in progress; the exit is expected.
    Stopping,
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub image: ImageRef,
    pub device: Option<DeviceId>,
    pub memory_bytes: u64,
    pub container: ContainerId,
    pub correlation: String,
    pub phase: JobPhase,
    /// The credential that ran it, as `holder` in JobStarted.
    pub holder: String,
    /// On a cloud, the member peer it was placed on, as `peer` in JobStarted.
    pub peer: Option<String>,
    /// The most host memory its container may hold, as JobStarted told it; none for no ceiling.
    pub host_memory_bytes: Option<u64>,
}

/// What an admitted command was given before its handler told the first fact: its id, and the device and memory
/// promised to it. Promised memory counts against the device until the deployment or job ends.
#[derive(Clone, Debug)]
pub struct Reservation {
    pub id: String,
    pub device: Option<DeviceId>,
    pub compute: Option<Compute>,
    pub memory_bytes: u64,
    /// The credential the command came from: what the started event will name as `holder`.
    pub holder: String,
    /// For a job, whether it runs in the closed box, as its credential's grant decided at admission.
    pub boxed: bool,
}

/// An order a cloud took: a job as `run-job` asked for it, from `JobQueued` until its job ends. It waits while it
/// is neither placed nor started; `JobPlaced` names the member it was sent to, and the member's `JobStarted`, which
/// names the order, the job it became.
#[derive(Clone, Debug)]
pub struct Order {
    /// The order's own id, what `JobQueued` names as `job` and `stop-job` may name while it waits.
    pub id: String,
    pub correlation: String,
    pub holder: String,
    pub image: String,
    pub args: Vec<String>,
    pub memory_bytes: Option<u64>,
    /// The device the order pinned, `cloud/peer/device`.
    pub device: Option<String>,
    pub queue_seconds: Option<u64>,
    pub deadline_seconds: Option<u64>,
    /// Whether its credential runs on the accelerators alone.
    pub accelerators_only: bool,
    /// The isolation it asked for: it is placed only on a device that offers at least that.
    pub isolation: Option<best_peer_runtime::Isolation>,
    /// 1, then 2 once a lost member's order was queued again.
    pub attempt: u32,
    /// When it was queued, this attempt, as `JobQueued` told it.
    pub queued_at: String,
    /// Its place in the order of arrival.
    pub arrival: u64,
    /// The member peer it was sent to, and the device there, once placed.
    pub placed: Option<(String, Option<String>)>,
    /// The job it became, and when it started.
    pub job: Option<String>,
    pub started_at: Option<String>,
    /// The size it ordered from the cloud's menu, as the menu had it, and the menu's currency; none for an order of
    /// memory_bytes.
    pub size: Option<(crate::menu::Size, String)>,
    /// What it got, as `JobPlaced` told it, in the size's terms: the size, its price and the currency.
    pub receipt: Option<Value>,
}

impl Order {
    /// Neither placed nor started: it waits for room.
    pub fn waiting(&self) -> bool {
        self.placed.is_none() && self.job.is_none()
    }
}

/// What a container belongs to.
#[derive(Clone, Debug)]
pub enum Owner {
    Deployment(Deployment),
    Job(String),
}

#[derive(Default)]
pub struct State {
    pub deployments: BTreeMap<String, Deployment>,
    pub jobs: BTreeMap<String, Job>,
    /// Admitted and not yet started, by the command's own key (the sender and the envelope id), never by a
    /// correlation id a client may share across commands.
    pub reserved: HashMap<String, Reservation>,
    /// On a cloud, the orders taken and not yet ended, by the order's id.
    pub orders: BTreeMap<String, Order>,
    /// How many orders were ever queued: the next one's place in the order of arrival.
    arrivals: u64,
}

impl State {
    /// What `holder` holds here, for the door's holdings: device memory, and the deployments and jobs running or
    /// admitted.
    pub fn holdings_of(&self, holder: &str) -> crate::holdings::Held {
        let admitted = |kind: &str| {
            self.reserved
                .values()
                .filter(|r| r.holder == holder && r.id.starts_with(kind))
                .count()
        };
        crate::holdings::Held {
            memory_bytes: self.held_by(holder),
            deployments: self.deployments.values().filter(|d| d.holder == holder).count() + admitted("dep-"),
            jobs: self.jobs.values().filter(|j| j.holder == holder).count() + admitted("job-"),
        }
    }

    /// The device memory promised to one holder's workloads, admitted ones included: what a share is measured
    /// against.
    pub fn held_by(&self, holder: &str) -> u64 {
        let deployments = self
            .deployments
            .values()
            .filter(|d| d.holder == holder)
            .map(|d| d.memory_bytes);
        let jobs = self
            .jobs
            .values()
            .filter(|j| j.holder == holder)
            .map(|j| j.memory_bytes);
        let admitted = self
            .reserved
            .values()
            .filter(|r| r.holder == holder)
            .map(|r| r.memory_bytes);
        deployments.chain(jobs).chain(admitted).sum()
    }

    /// Memory on `device` promised to what is admitted, starting or running there.
    pub fn reserved_on(&self, device: &DeviceId) -> u64 {
        let deployments = self
            .deployments
            .values()
            .filter(|d| &d.device == device)
            .map(|d| d.memory_bytes);
        let jobs = self
            .jobs
            .values()
            .filter(|j| j.device.as_ref() == Some(device))
            .map(|j| j.memory_bytes);
        let admitted = self
            .reserved
            .values()
            .filter(|r| r.device.as_ref() == Some(device))
            .map(|r| r.memory_bytes);
        deployments.chain(jobs).chain(admitted).sum()
    }

    /// What holds memory on `device`, for a refusal that says what to undeploy.
    /// What holds memory on `device`, by name: every workload, or with `mine` only that holder's, which is what a
    /// credential that does not act for every holder may be told.
    pub fn holders_on(&self, device: &DeviceId, mine: Option<&str>) -> Vec<Value> {
        let shown = |holder: &str| mine.is_none_or(|m| m == holder);
        let mut holders: Vec<Value> = self
            .deployments
            .values()
            .filter(|d| &d.device == device && shown(&d.holder))
            .map(|d| serde_json::json!({ "deployment": d.id, "model": d.model, "memory_bytes": d.memory_bytes }))
            .collect();
        holders.extend(
            self.jobs
                .values()
                .filter(|j| j.device.as_ref() == Some(device) && shown(&j.holder))
                .map(|j| serde_json::json!({ "job": j.id, "image": j.image.0, "memory_bytes": j.memory_bytes })),
        );
        holders
    }

    pub fn by_container(&self, id: &ContainerId) -> Option<Owner> {
        if let Some(d) = self.deployments.values().find(|d| &d.container == id) {
            return Some(Owner::Deployment(d.clone()));
        }
        self.jobs
            .values()
            .find(|j| &j.container == id)
            .map(|j| Owner::Job(j.id.clone()))
    }

    /// The reservation that became, or would have become, the workload `id` is released.
    fn release(&mut self, id: &str) {
        self.reserved.retain(|_, r| r.id != id);
    }

    /// The orders that wait, oldest first.
    pub fn waiting(&self) -> Vec<Order> {
        let mut w: Vec<Order> = self.orders.values().filter(|o| o.waiting()).cloned().collect();
        w.sort_by_key(|o| o.arrival);
        w
    }

    /// The order the job `job` became.
    pub fn order_of_job(&self, job: &str) -> Option<Order> {
        self.orders.values().find(|o| o.job.as_deref() == Some(job)).cloned()
    }

    /// Folds one fact in. An event about a deployment or job this state does not know is a fact about something
    /// that ended before the log was rebuilt, or about nothing: it changes nothing.
    pub fn apply(&mut self, e: &Envelope) {
        let data = &e.data;
        let text = |k: &str| data[k].as_str().unwrap_or_default().to_string();
        let correlation = e.effective_correlation();
        match e.r#type.as_str() {
            "DeploymentStarted" => {
                let engine: Kind = match serde_json::from_value(data["engine"].clone()) {
                    Ok(k) => k,
                    Err(_) => return,
                };
                let id = text("deployment");
                self.release(&id);
                self.deployments.insert(
                    id.clone(),
                    Deployment {
                        id,
                        model: text("model"),
                        engine,
                        device: DeviceId(text("device")),
                        memory_bytes: data["memory_bytes"].as_u64().unwrap_or(0),
                        container: ContainerId(text("container")),
                        port: data["port"].as_u64().unwrap_or(0) as u16,
                        ready: false,
                        holder: text("holder"),
                        correlation,
                        phase: Phase::Starting,
                        peer: data["peer"].as_str().map(str::to_string),
                    },
                );
            }
            "DeploymentReady" => {
                if let Some(d) = self.deployments.get_mut(&text("deployment")) {
                    d.ready = true;
                    d.phase = Phase::Ready;
                }
            }
            "DeploymentFailed" | "DeploymentEnded" | "Undeployed" | "OutOfMemory" => {
                let id = text("deployment");
                self.release(&id);
                self.deployments.remove(&id);
            }
            "JobQueued" => {
                let id = text("job");
                // Queued again after its member was lost: the job it had become is gone with the member.
                if let Some(old) = data["instead_of"].as_str() {
                    self.release(old);
                    self.jobs.remove(old);
                }
                let attempt = data["attempt"].as_u64().unwrap_or(1) as u32;
                // Queued again, it keeps its place; its wait is counted again only for a new attempt.
                let (arrival, queued_at) = match self.orders.get(&id) {
                    Some(o) if o.attempt == attempt => (o.arrival, o.queued_at.clone()),
                    Some(o) => (o.arrival, e.time.clone()),
                    None => {
                        self.arrivals += 1;
                        (self.arrivals - 1, e.time.clone())
                    }
                };
                let args = data["args"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                self.orders.insert(
                    id.clone(),
                    Order {
                        id,
                        correlation,
                        holder: text("holder"),
                        image: text("image"),
                        args,
                        memory_bytes: data["memory_bytes"].as_u64(),
                        device: data["device"].as_str().map(str::to_string),
                        queue_seconds: data["queue_seconds"].as_u64(),
                        deadline_seconds: data["deadline_seconds"].as_u64(),
                        accelerators_only: data["accelerators_only"].as_bool().unwrap_or(false),
                        isolation: serde_json::from_value(data["isolation"].clone()).ok(),
                        attempt,
                        queued_at,
                        arrival,
                        placed: None,
                        job: None,
                        started_at: None,
                        size: serde_json::from_value::<crate::menu::Size>(data["size"].clone())
                            .ok()
                            .map(|z| (z, data["size"]["currency"].as_str().unwrap_or_default().to_string())),
                        receipt: None,
                    },
                );
            }
            "JobPlaced" => {
                if let Some(o) = self.orders.get_mut(&text("job")) {
                    o.placed = Some((text("peer"), data["device"].as_str().map(str::to_string)));
                    o.receipt = data.get("receipt").filter(|r| r.is_object()).cloned();
                }
            }
            "JobStarted" => {
                let id = text("job");
                self.release(&id);
                if let Some(o) = data["order"].as_str().and_then(|o| self.orders.get_mut(o)) {
                    o.job = Some(id.clone());
                    o.started_at = Some(e.time.clone());
                    let order = o.id.clone();
                    self.release(&order);
                }
                self.jobs.insert(
                    id.clone(),
                    Job {
                        id,
                        image: ImageRef(text("image")),
                        device: data["device"].as_str().map(|d| DeviceId(d.into())),
                        memory_bytes: data["memory_bytes"].as_u64().unwrap_or(0),
                        container: ContainerId(text("container")),
                        correlation,
                        phase: JobPhase::Running,
                        holder: text("holder"),
                        peer: data["peer"].as_str().map(str::to_string),
                        host_memory_bytes: data["host_memory_bytes"].as_u64(),
                    },
                );
            }
            "JobFinished" | "JobFailed" | "JobStopped" => {
                let id = text("job");
                self.release(&id);
                self.jobs.remove(&id);
                // The order ends with its job, or by its own id when it ended before it started.
                self.orders
                    .retain(|_, o| o.id != id && o.job.as_deref() != Some(id.as_str()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(r#type: &str, corr: &str, data: Value) -> Envelope {
        Envelope::event("io.best.agents", r#type, data, Some(corr.into()), None)
    }

    fn reserve(s: &mut State, key: &str, id: &str, bytes: u64) {
        s.reserved.insert(
            key.into(),
            Reservation {
                id: id.into(),
                device: Some("gpu-0".into()),
                compute: Some(Compute::Cuda("12".into())),
                memory_bytes: bytes,
                holder: "h".into(),
                boxed: false,
            },
        );
    }

    #[test]
    fn the_state_is_the_fold_of_the_facts_and_memory_is_promised_until_the_end() {
        let mut s = State::default();
        reserve(&mut s, "alice:cmd-1", "dep-1", 8);
        assert_eq!(s.reserved_on(&"gpu-0".into()), 8, "admitted memory is promised");
        s.apply(&ev(
            "DeploymentStarted",
            "c1",
            json!({ "deployment": "dep-1", "model": "m", "engine": "ollama", "device": "gpu-0", "memory_bytes": 8, "container": "k-1", "port": 41434 }),
        ));
        assert!(s.reserved.is_empty(), "the reservation became the deployment");
        assert_eq!(s.deployments["dep-1"].phase, Phase::Starting);
        assert_eq!(s.deployments["dep-1"].port, 41434);
        assert_eq!(s.reserved_on(&"gpu-0".into()), 8);
        s.apply(&ev(
            "DeploymentReady",
            "c1",
            json!({ "deployment": "dep-1", "model": "m", "engine": "ollama" }),
        ));
        assert_eq!(s.deployments["dep-1"].phase, Phase::Ready);
        assert!(s.deployments["dep-1"].ready);
        assert!(matches!(s.by_container(&ContainerId("k-1".into())), Some(Owner::Deployment(d)) if d.id == "dep-1"));
        s.apply(&ev(
            "JobStarted",
            "c2",
            json!({ "job": "job-1", "image": "busybox", "device": "gpu-0", "memory_bytes": 2, "container": "k-2" }),
        ));
        assert_eq!(s.reserved_on(&"gpu-0".into()), 10);
        assert_eq!(s.holders_on(&"gpu-0".into(), None).len(), 2);
        assert_eq!(
            s.holders_on(&"gpu-0".into(), Some("nobody")).len(),
            0,
            "another holder is told nothing"
        );
        s.apply(&ev("JobFinished", "c2", json!({ "job": "job-1", "exit_code": 0 })));
        s.apply(&ev("Undeployed", "c1", json!({ "deployment": "dep-1" })));
        assert_eq!(s.reserved_on(&"gpu-0".into()), 0);
        assert!(s.by_container(&ContainerId("k-1".into())).is_none());
        s.apply(&ev("Undeployed", "c9", json!({ "deployment": "never" })));
        assert!(s.deployments.is_empty() && s.jobs.is_empty());
    }

    #[test]
    fn an_order_is_folded_from_queued_to_placed_to_started_and_ends_with_its_job() {
        let mut s = State::default();
        let queued = |job: &str, attempt: u64, extra: Value| {
            let mut d = json!({ "job": job, "image": "busybox", "args": ["a"], "memory_bytes": 4, "holder": "h", "attempt": attempt, "waiting": true });
            for (k, v) in extra.as_object().unwrap() {
                d[k] = v.clone();
            }
            d
        };
        s.apply(&ev(
            "JobQueued",
            "c1",
            queued(
                "job-1",
                1,
                json!({ "queue_seconds": 60, "isolation": "user-namespace" }),
            ),
        ));
        s.apply(&ev("JobQueued", "c2", queued("job-2", 1, json!({}))));
        assert_eq!(
            s.waiting().iter().map(|o| o.id.as_str()).collect::<Vec<_>>(),
            ["job-1", "job-2"],
            "oldest first"
        );
        assert_eq!(s.orders["job-1"].args, ["a"]);
        assert_eq!(s.orders["job-1"].queue_seconds, Some(60));
        assert_eq!(
            s.orders["job-1"].isolation,
            Some(best_peer_runtime::Isolation::UserNamespace),
            "the ask is folded, so it holds after a restart"
        );
        assert_eq!(s.orders["job-2"].isolation, None);
        s.apply(&ev(
            "JobPlaced",
            "c1",
            json!({ "job": "job-1", "peer": "a", "device": "lab/a/gpu-0" }),
        ));
        assert_eq!(s.waiting().len(), 1, "a placed order no longer waits");
        s.apply(&ev(
            "JobStarted",
            "c1",
            json!({ "job": "run-9", "order": "job-1", "image": "busybox", "container": "k", "peer": "a" }),
        ));
        assert_eq!(s.order_of_job("run-9").unwrap().id, "job-1");
        // Queued again after its member was lost: the job is gone, the order keeps its place and counts a new wait.
        s.apply(&ev(
            "JobQueued",
            "c1",
            queued("job-1", 2, json!({ "instead_of": "run-9" })),
        ));
        assert!(!s.jobs.contains_key("run-9"));
        assert_eq!(s.waiting()[0].id, "job-1", "it keeps its place");
        assert_eq!(s.orders["job-1"].attempt, 2);
        assert!(s.orders["job-1"].placed.is_none() && s.orders["job-1"].job.is_none());
        // Back to waiting at the same attempt (a member had no room after all): its wait is not counted again.
        let again_at = s.orders["job-1"].queued_at.clone();
        s.apply(&ev("JobQueued", "c1", queued("job-1", 2, json!({}))));
        assert_eq!(s.orders["job-1"].queued_at, again_at);
        // Ended by its own id before it started, or with the job it became.
        s.apply(&ev("JobStopped", "c2", json!({ "job": "job-2" })));
        assert!(!s.orders.contains_key("job-2"));
        s.apply(&ev(
            "JobStarted",
            "c1",
            json!({ "job": "run-10", "order": "job-1", "image": "busybox", "container": "k2", "peer": "b" }),
        ));
        s.apply(&ev("JobFinished", "c1", json!({ "job": "run-10", "exit_code": 0 })));
        assert!(s.orders.is_empty() && s.jobs.is_empty());
    }

    #[test]
    fn two_commands_sharing_a_correlation_id_keep_their_own_reservations() {
        let mut s = State::default();
        reserve(&mut s, "alice:cmd-1", "dep-1", 8);
        reserve(&mut s, "alice:cmd-2", "dep-2", 4);
        assert_eq!(s.reserved_on(&"gpu-0".into()), 12);
        // Both commands carry the correlation "wf"; the first one's start releases only its own reservation.
        s.apply(&ev(
            "DeploymentStarted",
            "wf",
            json!({ "deployment": "dep-1", "model": "m", "engine": "ollama", "device": "gpu-0", "memory_bytes": 8, "container": "k-1", "port": 1 }),
        ));
        assert_eq!(s.reserved.len(), 1);
        assert_eq!(s.reserved["alice:cmd-2"].id, "dep-2");
        assert_eq!(s.reserved_on(&"gpu-0".into()), 12);
        // A failure of the second before it started releases its promise and nothing else.
        s.apply(&ev("DeploymentFailed", "wf", json!({ "deployment": "dep-2" })));
        assert!(s.reserved.is_empty());
        assert_eq!(s.reserved_on(&"gpu-0".into()), 8);
    }
}
