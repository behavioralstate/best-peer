//! The queue a door keeps for its orders, the same at a machine's own door and at the cloud door above the machines
//! (behavioralstate/spec#58, #76). An order is taken and told as `JobQueued`, with `waiting` while no device has its
//! room; the orders that wait are placed first come, first served, an order that does not fit yet holding back none
//! that does; `queue_seconds` ends a wait unplaced, `deadline_seconds` stops a run, and a stop of a waiting order ends
//! it before it started. What the queue waits for is a device a size or `memory_bytes` fits, whatever it is: a whole
//! card, a MIG instance or the host's CPU. Each door keeps its own placement: the cloud places on its members, a peer
//! on its own devices. This module holds what the two share.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use best_peer_door::auth::hash_key;
use futures::future::BoxFuture;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use best_peer_gpu::Host;

use crate::lifecycle::{any_compute, place};
use crate::state::{JobPhase, Order, State};

/// How long an order may wait for room when it names no `queue_seconds`, at a door where waiting is the default: a
/// day, as RunPod's default time-to-live.
pub const DEFAULT_QUEUE_SECONDS: u64 = 24 * 60 * 60;

/// An order's id: the command's key hashed, so the command run again after a restart finds its order.
pub fn order_id(key: &str) -> String {
    format!("job-{}", &hash_key(key)[..12])
}

/// Whether `seconds` from `since` have passed at `now`; a bound not set, or a time that does not read, never has.
pub fn past(since: Option<&str>, seconds: Option<u64>, now: OffsetDateTime) -> bool {
    match (since.and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok()), seconds) {
        (Some(t), Some(s)) => now >= t + time::Duration::seconds(s as i64),
        _ => false,
    }
}

/// Whether a device of `host` that runs a job could hold `needed` once nothing else held it there: an order that
/// fits nowhere now waits only when room can come free.
pub fn could_ever_hold(host: &Host, needed: u64, pinned: Option<&str>) -> bool {
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
pub fn queued_fact(o: &Order, attempt: u32, waiting: bool, reason: Option<String>, instead_of: Option<&str>) -> Value {
    let mut v = json!({
        "job": o.id, "image": o.image, "args": o.args, "memory_bytes": o.memory_bytes, "device": o.device,
        "queue_seconds": o.queue_seconds, "deadline_seconds": o.deadline_seconds, "holder": o.holder,
        "accelerators_only": o.accelerators_only, "isolation": o.isolation, "attempt": attempt, "waiting": waiting,
    });
    if o.boxed {
        v["boxed"] = json!(true);
    }
    if let Some((size, currency)) = &o.size {
        let mut z = serde_json::to_value(size).unwrap_or(Value::Null);
        z["currency"] = json!(currency);
        v["size"] = z;
    }
    if let Some(r) = reason {
        v["reason"] = json!(r);
    }
    if let Some(i) = instead_of {
        v["instead_of"] = json!(i);
    }
    v
}

/// What the queue owes at `now`: the orders that waited past their `queue_seconds`, and the jobs running past their
/// order's `deadline_seconds`, each with the job's id and the member peer it runs on, where there is one.
pub struct Due {
    pub expired: Vec<Order>,
    pub overdue: Vec<(Order, String, Option<String>)>,
}

pub fn due(s: &State, now: OffsetDateTime) -> Due {
    let expired = s
        .waiting()
        .into_iter()
        .filter(|o| past(Some(&o.queued_at), o.queue_seconds, now))
        .collect();
    let overdue = s
        .orders
        .values()
        .filter(|o| past(o.started_at.as_deref(), o.deadline_seconds, now))
        .filter_map(|o| {
            let j = s.jobs.get(o.job.as_deref()?)?;
            (j.phase == JobPhase::Running).then(|| (o.clone(), j.id.clone(), j.peer.clone()))
        })
        .collect();
    Due { expired, overdue }
}

/// `JobFailed`'s reason for an order that waited past its `queue_seconds`, with the place it waited for (`where`).
pub fn expired_reason(o: &Order, place: &str) -> String {
    format!(
        "{place} had the room for it within its queue_seconds ({} s): it was never placed",
        o.queue_seconds.unwrap_or(0)
    )
}

/// `JobStopped`'s reason for a job its door stopped at its `deadline_seconds`.
pub fn deadline_reason(o: &Order) -> String {
    format!(
        "it ran past its deadline_seconds ({} s), so the door stopped it",
        o.deadline_seconds.unwrap_or(0)
    )
}

/// One placement step at a time, however it was asked for: a step asked for while one runs makes that one run once
/// more when it ends, so no order is left waiting for a step nobody runs.
#[derive(Default)]
pub struct Stepper {
    stepping: AtomicBool,
    again: AtomicBool,
}

/// A door that keeps a queue: its stepper, and one placement step.
pub trait Steps: Send + Sync + 'static {
    fn stepper(&self) -> &Stepper;
    fn step_now(self: Arc<Self>) -> BoxFuture<'static, ()>;
}

/// Starts a placement step on `door`, unless one runs, which then runs once more when it ends.
pub fn kick<T: Steps>(door: &Weak<T>) {
    let Some(me) = door.upgrade() else {
        return;
    };
    if me.stepper().stepping.swap(true, Ordering::SeqCst) {
        me.stepper().again.store(true, Ordering::SeqCst);
        return;
    }
    tokio::spawn(async move {
        loop {
            me.stepper().again.store(false, Ordering::SeqCst);
            me.clone().step_now().await;
            if me.stepper().again.load(Ordering::SeqCst) {
                continue;
            }
            me.stepper().stepping.store(false, Ordering::SeqCst);
            // Asked for between the last look and now: this task takes it, unless another already has.
            if me.stepper().again.load(Ordering::SeqCst) && !me.stepper().stepping.swap(true, Ordering::SeqCst) {
                continue;
            }
            break;
        }
    });
}
