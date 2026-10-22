//! Whether each device takes new work: free, or busy while its owner uses it or holds it.
//!
//! Owner use is read from the driver: the processes on a card that are not the peer's own workloads, holding more
//! than a set amount of its memory or a set share of its compute for a set time, turn it busy; it frees after a quiet
//! period, so a pause between two of the owner's sessions does not let an order in. It is a reading of the hardware,
//! as free memory is, and is never told as an event: the log would become a dated record of when the owner sits at
//! their own machine, kept in every backup and relayed by every cloud the peer is a member of. A hold is the owner's
//! own act at the machine, told as `DeviceHeld` and `DeviceReleased` and folded into the state, so it outlives a
//! restart. A device is busy while either applies; a busy device takes no new work, and what runs on it runs on.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json};
use best_peer_door::Auth;
use best_peer_gpu::{Availability, DeviceId, Host, Usage};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// How often the driver is read for the owner's use.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(5);

/// The longest reason an owner may give a hold: one line a client reads.
pub const MAX_REASON: usize = 80;

/// What `JobStopped` and `DeploymentEnded` say of a workload a hold ended, followed by the owner's reason where
/// they gave one.
pub const HELD_REASON: &str = "held by its owner";

/// The reason a workload a hold ended is told: [`HELD_REASON`], and the owner's after it where they gave one.
pub fn held_reason(reason: Option<&str>) -> String {
    match reason {
        Some(r) => format!("{HELD_REASON}: {r}"),
        None => HELD_REASON.to_string(),
    }
}

/// Whether `reason` is one a hold ended a workload with.
pub fn ended_by_hold(reason: &str) -> bool {
    reason == HELD_REASON || reason.starts_with(&format!("{HELD_REASON}: "))
}

/// When owner use turns a device busy and when it frees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thresholds {
    /// More device memory than this in processes not the peer's.
    pub memory_bytes: u64,
    /// Or more of the device's compute than this, in percent.
    pub utilisation_pct: u8,
    /// For this long, before the device is busy.
    pub busy_after: Duration,
    /// Under both for this long, before it is free again.
    pub free_after: Duration,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            memory_bytes: 2 << 30,
            utilisation_pct: 30,
            busy_after: Duration::from_secs(30),
            free_after: Duration::from_secs(300),
        }
    }
}

/// The operator's thresholds from `BEST_PEER_BUSY` (`on` when unset, or `off`), `BEST_PEER_BUSY_MEMORY` (`2G`),
/// `BEST_PEER_BUSY_UTILISATION` (percent), `BEST_PEER_BUSY_AFTER` and `BEST_PEER_FREE_AFTER` (`30s`, `5m`); none when
/// the operator turned owner use off. A value that does not read is refused by name, with what it takes, with owner use
/// off too.
pub fn thresholds(
    busy: Option<&str>,
    memory: Option<&str>,
    utilisation: Option<&str>,
    busy_after: Option<&str>,
    free_after: Option<&str>,
) -> Result<Option<Thresholds>, String> {
    let on = match busy.map(str::trim) {
        None | Some("on") => true,
        Some("off") => false,
        Some(other) => {
            return Err(format!(
                "BEST_PEER_BUSY={other:?} is not a setting: on (the default) finds when the owner uses a card, off never does"
            ))
        }
    };
    let mut t = Thresholds::default();
    if let Some(m) = memory {
        t.memory_bytes = crate::parse_memory(m).map_err(|why| format!("BEST_PEER_BUSY_MEMORY: {why}"))?;
    }
    if let Some(u) = utilisation {
        t.utilisation_pct = match u.trim().parse::<u8>() {
            Ok(n) if n <= 100 => n,
            _ => {
                return Err(format!(
                    "BEST_PEER_BUSY_UTILISATION={u:?} is not a percentage: write a whole number from 0 to 100"
                ))
            }
        };
    }
    if let Some(a) = busy_after {
        t.busy_after = crate::parse_duration(a).map_err(|why| format!("BEST_PEER_BUSY_AFTER: {why}"))?;
    }
    if let Some(f) = free_after {
        t.free_after = crate::parse_duration(f).map_err(|why| format!("BEST_PEER_FREE_AFTER: {why}"))?;
    }
    Ok(on.then_some(t))
}

/// What the owner's processes hold of one device at one reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    pub device: DeviceId,
    pub memory_bytes: u64,
    pub utilisation_pct: u8,
}

/// The owner's share of each device in `usage`: every process that is not one of the peer's (`peers`). An engine
/// that cannot name its processes (`None`) leaves a device the peer holds a workload on (`holds`) unread, since its
/// own engine would count as the owner there.
pub fn readings(usage: &[Usage], peers: Option<&[u32]>, holds: &HashSet<DeviceId>) -> Vec<Reading> {
    usage
        .iter()
        .filter(|u| peers.is_some() || !holds.contains(&u.device))
        .map(|u| {
            let theirs: Vec<_> = u
                .processes
                .iter()
                .filter(|p| !peers.is_some_and(|mine| mine.contains(&p.pid)))
                .collect();
            Reading {
                device: u.device.clone(),
                memory_bytes: theirs.iter().filter_map(|p| p.memory_bytes).sum(),
                utilisation_pct: theirs
                    .iter()
                    .map(|p| u32::from(p.utilisation_pct.unwrap_or(0)))
                    .sum::<u32>()
                    .min(100) as u8,
            }
        })
        .collect()
}

#[derive(Default)]
struct Seen {
    over_since: Option<Instant>,
    under_since: Option<Instant>,
    busy: bool,
}

/// The owner's use of each device over time: over the thresholds long enough, busy; under them long enough, free.
pub struct Watch {
    pub thresholds: Thresholds,
    seen: Mutex<HashMap<DeviceId, Seen>>,
}

impl Watch {
    pub fn new(thresholds: Thresholds) -> Self {
        Self {
            thresholds,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Takes the readings at `now`; a device not read is under the thresholds. Answers whether a device turned free,
    /// which may let an order in.
    pub fn observe(&self, now: Instant, readings: &[Reading]) -> bool {
        let t = &self.thresholds;
        let mut seen = self.seen.lock().unwrap();
        let read: HashMap<&DeviceId, &Reading> = readings.iter().map(|r| (&r.device, r)).collect();
        for r in readings {
            seen.entry(r.device.clone()).or_default();
        }
        let mut freed = false;
        for (device, s) in seen.iter_mut() {
            let over = read
                .get(device)
                .is_some_and(|r| r.memory_bytes > t.memory_bytes || r.utilisation_pct > t.utilisation_pct);
            if over {
                s.under_since = None;
                let since = *s.over_since.get_or_insert(now);
                if !s.busy && now.duration_since(since) >= t.busy_after {
                    s.busy = true;
                }
            } else {
                s.over_since = None;
                let since = *s.under_since.get_or_insert(now);
                if s.busy && now.duration_since(since) >= t.free_after {
                    s.busy = false;
                    freed = true;
                }
            }
        }
        freed
    }

    /// Whether the owner is using `device` now.
    pub fn in_use(&self, device: &DeviceId) -> bool {
        self.seen.lock().unwrap().get(device).is_some_and(|s| s.busy)
    }
}

/// A hold the owner placed on a device, as `DeviceHeld` told it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hold {
    pub until: Option<String>,
    pub reason: Option<String>,
}

impl Hold {
    /// Whether it still holds at `now`: it has no end, or its end has not come. An end that does not read holds.
    pub fn holds_at(&self, now: OffsetDateTime) -> bool {
        match self.until.as_deref().map(|u| OffsetDateTime::parse(u, &Rfc3339)) {
            Some(Ok(until)) => now < until,
            _ => true,
        }
    }
}

/// Sets each device's availability on `host` from the holds and the owner's use at `now`: busy while either applies;
/// its `until` from the hold, and none while the owner uses it, since nobody knows when they will stop; its reason
/// the one the owner gave the hold.
pub fn annotate(host: &mut Host, holds: &HashMap<String, Hold>, watch: Option<&Watch>, now: OffsetDateTime) {
    for d in &mut host.devices {
        let hold = holds.get(&d.id.0).filter(|h| h.holds_at(now));
        let in_use = watch.is_some_and(|w| w.in_use(&d.id));
        d.availability = match (hold, in_use) {
            (None, false) => Availability::Free,
            (hold, in_use) => Availability::Busy {
                until: hold.and_then(|h| h.until.clone()).filter(|_| !in_use),
                reason: hold.and_then(|h| h.reason.clone()),
            },
        };
    }
}

/// A reason as the owner gave it, checked: one line of `MAX_REASON` characters at most.
pub fn reason(text: &str) -> Result<String, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("--reason needs the words, or leave it out: a hold needs no reason".into());
    }
    if t.chars().any(char::is_control) {
        return Err("--reason is one line: no line break or control character".into());
    }
    if t.chars().count() > MAX_REASON {
        return Err(format!(
            "--reason is {MAX_REASON} characters at most: a client reads it in a line"
        ));
    }
    Ok(t.to_string())
}

/// What `best-peer hold` posts: the admin token as the proof; the devices, comma-separated, every one when none;
/// the end, RFC 3339; the reason; and whether what runs on them ends now.
#[derive(serde::Deserialize)]
struct HoldForm {
    proof: String,
    #[serde(default)]
    devices: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    now: Option<String>,
}

/// What `best-peer release` posts: the proof, and the devices, every one held when none.
#[derive(serde::Deserialize)]
struct ReleaseForm {
    proof: String,
    #[serde(default)]
    devices: Option<String>,
}

type Owner = (Arc<crate::lifecycle::Peer>, Arc<Auth>);

/// The two routes the person at the machine holds and releases its devices by, with the same proof `approve` takes:
/// no credential reaches them, whatever it may do.
pub fn router(peer: Arc<crate::lifecycle::Peer>, auth: Arc<Auth>) -> axum::Router {
    axum::Router::new()
        .route("/owner/hold", post(hold))
        .route("/owner/release", post(release))
        .with_state((peer, auth))
}

fn named(devices: Option<String>) -> Option<Vec<String>> {
    devices.map(|d| {
        d.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
}

async fn hold(State((peer, auth)): State<Owner>, Form(f): Form<HoldForm>) -> Response {
    if let Err(e) = auth.attest(&f.proof).await {
        return e.into_response();
    }
    let now = f.now.as_deref() == Some("true");
    match peer.hold(named(f.devices), f.until, f.reason, now).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn release(State((peer, auth)): State<Owner>, Form(f): Form<ReleaseForm>) -> Response {
    if let Err(e) = auth.attest(&f.proof).await {
        return e.into_response();
    }
    match peer.release(named(f.devices)) {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use best_peer_gpu::{Fake, Process};

    const GB: u64 = 1 << 30;

    fn reading(memory_bytes: u64, utilisation_pct: u8) -> Vec<Reading> {
        vec![Reading {
            device: "gpu-0".into(),
            memory_bytes,
            utilisation_pct,
        }]
    }

    #[test]
    fn a_device_turns_busy_only_after_the_owners_use_lasts_and_free_only_after_a_quiet_period() {
        let w = Watch::new(Thresholds::default());
        let t0 = Instant::now();
        let gpu: DeviceId = "gpu-0".into();
        assert!(!w.observe(t0, &reading(3 * GB, 0)));
        assert!(!w.in_use(&gpu), "over the memory threshold, not yet for long enough");
        w.observe(t0 + Duration::from_secs(29), &reading(3 * GB, 0));
        assert!(!w.in_use(&gpu));
        w.observe(t0 + Duration::from_secs(30), &reading(3 * GB, 0));
        assert!(w.in_use(&gpu), "thirty seconds over: busy");
        assert!(!w.observe(t0 + Duration::from_secs(31), &reading(0, 0)));
        w.observe(t0 + Duration::from_secs(200), &reading(0, 50));
        assert!(w.in_use(&gpu), "a pause shorter than the quiet period keeps it busy");
        assert!(!w.observe(t0 + Duration::from_secs(201), &reading(0, 0)));
        assert!(!w.observe(t0 + Duration::from_secs(500), &reading(0, 0)));
        assert!(w.in_use(&gpu));
        assert!(
            w.observe(t0 + Duration::from_secs(501), &reading(0, 0)),
            "turning free is said"
        );
        assert!(!w.in_use(&gpu), "five minutes under both: free");
    }

    #[test]
    fn the_desktop_alone_never_turns_a_device_busy_and_compute_alone_does() {
        let w = Watch::new(Thresholds::default());
        let t0 = Instant::now();
        let gpu: DeviceId = "gpu-0".into();
        for s in 0..120 {
            w.observe(t0 + Duration::from_secs(s), &reading(300 << 20, 2));
        }
        assert!(
            !w.in_use(&gpu),
            "a compositor's few hundred MiB and a trickle of compute"
        );
        w.observe(t0 + Duration::from_secs(200), &reading(GB, 31));
        w.observe(t0 + Duration::from_secs(230), &reading(GB, 31));
        assert!(w.in_use(&gpu), "above 30% of the compute for thirty seconds");
        let at_threshold = Watch::new(Thresholds::default());
        at_threshold.observe(t0, &reading(2 * GB, 30));
        at_threshold.observe(t0 + Duration::from_secs(60), &reading(2 * GB, 30));
        assert!(!at_threshold.in_use(&gpu), "more than the thresholds, not as much");
    }

    #[test]
    fn a_device_no_longer_read_counts_as_quiet() {
        let w = Watch::new(Thresholds::default());
        let t0 = Instant::now();
        w.observe(t0, &reading(3 * GB, 0));
        w.observe(t0 + Duration::from_secs(30), &reading(3 * GB, 0));
        assert!(w.in_use(&"gpu-0".into()));
        w.observe(t0 + Duration::from_secs(31), &[]);
        assert!(w.observe(t0 + Duration::from_secs(331), &[]));
        assert!(!w.in_use(&"gpu-0".into()));
    }

    fn usage(pairs: &[(u32, u64, u8)]) -> Vec<Usage> {
        vec![Usage {
            device: "gpu-0".into(),
            processes: pairs
                .iter()
                .map(|&(pid, m, u)| Process {
                    pid,
                    memory_bytes: Some(m),
                    utilisation_pct: Some(u),
                })
                .collect(),
        }]
    }

    #[test]
    fn the_peers_own_processes_are_never_the_owners_use() {
        let u = usage(&[(100, 300 << 20, 1), (4120, 20 * GB, 90), (7000, 3 * GB, 40)]);
        let r = readings(&u, Some(&[4120]), &HashSet::new());
        assert_eq!(r[0].memory_bytes, (300 << 20) + 3 * GB);
        assert_eq!(r[0].utilisation_pct, 41);
        let busy_game = usage(&[(1, 0, 70), (2, 0, 70)]);
        assert_eq!(readings(&busy_game, Some(&[]), &HashSet::new())[0].utilisation_pct, 100);
    }

    #[test]
    fn an_engine_that_cannot_name_its_processes_leaves_the_devices_it_holds_unread() {
        let u = usage(&[(4120, 20 * GB, 90)]);
        let held: HashSet<DeviceId> = ["gpu-0".into()].into();
        assert!(
            readings(&u, None, &held).is_empty(),
            "its own engine would read as the owner"
        );
        assert_eq!(readings(&u, None, &HashSet::new())[0].memory_bytes, 20 * GB);
    }

    #[test]
    fn a_hold_and_the_owners_use_each_make_a_device_busy_and_only_a_hold_says_until_when() {
        let now = OffsetDateTime::parse("2026-10-20T12:00:00Z", &Rfc3339).unwrap();
        let fake = Fake::new()
            .with_device(Fake::cuda_card("gpu-0", "A", 24, "12.4"))
            .with_device(Fake::cuda_card("gpu-1", "B", 24, "12.4"))
            .with_device(Fake::host_cpu("cpu", 64));
        let mut host = best_peer_gpu::Gpu::snapshot(&fake).unwrap();
        let holds = HashMap::from([
            (
                "gpu-0".to_string(),
                Hold {
                    until: Some("2026-10-20T13:00:00Z".into()),
                    reason: Some("maintenance".into()),
                },
            ),
            (
                "cpu".to_string(),
                Hold {
                    until: Some("2026-10-20T11:00:00Z".into()),
                    reason: None,
                },
            ),
        ]);
        let w = Watch::new(Thresholds {
            busy_after: Duration::ZERO,
            ..Thresholds::default()
        });
        w.observe(
            Instant::now(),
            &[Reading {
                device: "gpu-1".into(),
                memory_bytes: 8 * GB,
                utilisation_pct: 0,
            }],
        );
        annotate(&mut host, &holds, Some(&w), now);
        let of = |id: &str| host.devices.iter().find(|d| d.id.0 == id).unwrap().availability.clone();
        assert_eq!(
            of("gpu-0"),
            Availability::Busy {
                until: Some("2026-10-20T13:00:00Z".into()),
                reason: Some("maintenance".into())
            }
        );
        assert_eq!(
            of("gpu-1"),
            Availability::Busy {
                until: None,
                reason: None
            }
        );
        assert_eq!(of("cpu"), Availability::Free, "a hold whose end has come holds nothing");
        let both = HashMap::from([(
            "gpu-1".to_string(),
            Hold {
                until: Some("2026-10-20T13:00:00Z".into()),
                reason: None,
            },
        )]);
        annotate(&mut host, &both, Some(&w), now);
        assert_eq!(
            host.devices.iter().find(|d| d.id.0 == "gpu-1").unwrap().availability,
            Availability::Busy {
                until: None,
                reason: None
            },
            "while the owner uses it, nobody knows when it frees"
        );
    }

    #[test]
    fn the_operators_thresholds_are_read_and_a_value_that_does_not_read_is_refused_by_name() {
        assert_eq!(
            thresholds(None, None, None, None, None).unwrap(),
            Some(Thresholds::default())
        );
        assert_eq!(thresholds(Some("off"), Some("4G"), None, None, None).unwrap(), None);
        assert!(
            thresholds(Some("off"), Some("nonsense"), None, None, None)
                .unwrap_err()
                .contains("BEST_PEER_BUSY_MEMORY"),
            "a typo is told while owner use is off, not once it is turned on"
        );
        let t = thresholds(Some("on"), Some("4G"), Some("50"), Some("1m"), Some("10m"))
            .unwrap()
            .unwrap();
        assert_eq!(
            t,
            Thresholds {
                memory_bytes: 4 * GB,
                utilisation_pct: 50,
                busy_after: Duration::from_secs(60),
                free_after: Duration::from_secs(600)
            }
        );
        assert!(thresholds(Some("maybe"), None, None, None, None)
            .unwrap_err()
            .contains("BEST_PEER_BUSY="));
        assert!(thresholds(None, Some("lots"), None, None, None)
            .unwrap_err()
            .contains("BEST_PEER_BUSY_MEMORY"));
        assert!(thresholds(None, None, Some("101"), None, None)
            .unwrap_err()
            .contains("BEST_PEER_BUSY_UTILISATION"));
        assert!(thresholds(None, None, None, Some("soon"), None)
            .unwrap_err()
            .contains("BEST_PEER_BUSY_AFTER"));
        assert!(thresholds(None, None, None, None, Some("0"))
            .unwrap_err()
            .contains("BEST_PEER_FREE_AFTER"));
    }

    #[test]
    fn a_reason_is_one_short_line() {
        assert_eq!(reason("  maintenance ").unwrap(), "maintenance");
        assert!(reason("").is_err());
        assert!(reason("two\nlines").is_err());
        assert!(reason(&"x".repeat(81)).is_err());
        assert_eq!(reason(&"é".repeat(80)).unwrap().chars().count(), 80);
    }
}
