//! What an order by size used and what it cost, read back from the workspace's own facts (behavioralstate/spec#61).
//! A job ordered by size runs from its `JobStarted`, whose receipt carries the size, the device and the price per
//! second, to its end: `JobFinished`, `JobFailed` or `JobStopped`, or, on a member peer that was lost, the last moment
//! the member was heard (`PeerLost`'s `last_heard`), never the moment of the loss. The price is the receipt's until a
//! `MenuSetV1` changes the size's price on the job's cloud: each stretch is billed at the price it had, so a later
//! change to the menu never rewrites what was billed, and a size dropped from the menu keeps the price it had.
//!
//! The factor is the share of compute a job had against what its size gives it uncontended (behavioralstate/spec#64,
//! decision 7): 1 on a device held whole or a MIG slice, which nothing contends. A device whose compute is split
//! between jobs will tell its shares as they change, each change one more cut here; that comes with the spike in
//! behavioralstate/spec#65.
//!
//! A workspace's spending cap ([`Purse`]) is checked when an order by size is taken, against what was spent, what
//! the open orders may still spend and the order's own most: its price times its `deadline_seconds`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use best_peer_door::{BestError, Envelope, EventLog};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Where a job's price or factor changed: from `from` on, until the next cut or the job's end.
#[derive(Clone, Debug, PartialEq)]
struct Cut {
    from: OffsetDateTime,
    price: f64,
    factor: f64,
}

/// One job ordered by size, as the facts tell it.
#[derive(Clone, Debug)]
pub struct Metered {
    pub job: String,
    /// The order it ran for, what `JobQueued` named.
    pub order: Option<String>,
    pub holder: Option<String>,
    pub cloud: String,
    pub peer: Option<String>,
    pub size: String,
    pub currency: String,
    device: Option<String>,
    gpu: Option<String>,
    started: OffsetDateTime,
    ended: Option<OffsetDateTime>,
    /// Ended by its member's loss: the end is the last moment the member was heard.
    end_inferred: bool,
    cuts: Vec<Cut>,
}

/// One stretch of a job inside a window, at one price and one factor.
struct Stretch {
    from: OffsetDateTime,
    to: OffsetDateTime,
    price: f64,
    factor: f64,
}

impl Stretch {
    fn seconds(&self) -> f64 {
        (self.to - self.from).as_seconds_f64()
    }

    fn cost(&self) -> f64 {
        self.seconds() * self.price * self.factor
    }
}

impl Metered {
    /// Still running at the last fact read.
    pub fn running(&self) -> bool {
        self.ended.is_none()
    }

    /// Its stretches between `from` and `to`, a running job's up to `now`.
    fn stretches(&self, now: OffsetDateTime, from: Option<OffsetDateTime>, to: OffsetDateTime) -> Vec<Stretch> {
        let end = self.ended.unwrap_or(now).min(to);
        self.cuts
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                let next = self.cuts.get(i + 1).map_or(end, |n| n.from.min(end));
                let a = from.map_or(c.from, |f| c.from.max(f));
                (next > a).then_some(Stretch {
                    from: a,
                    to: next,
                    price: c.price,
                    factor: c.factor,
                })
            })
            .collect()
    }

    /// What it cost up to `now`, every stretch.
    pub fn cost(&self, now: OffsetDateTime) -> f64 {
        self.stretches(now, None, now).iter().map(Stretch::cost).sum()
    }

    /// Its usage between `from` and `to`, as `get-usage` answers it; none when it did not run then.
    fn view(&self, now: OffsetDateTime, from: Option<OffsetDateTime>, to: OffsetDateTime) -> Option<Value> {
        let stretches = self.stretches(now, from, to);
        // A job that ran no billable time, ended where it began, is listed when it lies in the window, at nothing.
        let end = self.ended.unwrap_or(now);
        if stretches.is_empty() && (self.started > to || from.is_some_and(|f| end < f)) {
            return None;
        }
        let seconds: f64 = stretches.iter().map(Stretch::seconds).sum();
        let cost: f64 = stretches.iter().map(Stretch::cost).sum();
        let factor = if seconds > 0.0 {
            stretches.iter().map(|s| s.seconds() * s.factor).sum::<f64>() / seconds
        } else {
            1.0
        };
        let intervals: Vec<Value> = stretches
            .iter()
            .map(|s| {
                json!({
                    "from": text(s.from), "to": text(s.to), "seconds": round(s.seconds(), 3),
                    "price_per_second": s.price, "factor": s.factor, "cost": round(s.cost(), 6),
                })
            })
            .collect();
        Some(json!({
            "job": self.job, "order": self.order, "cloud": self.cloud, "peer": self.peer, "device": self.device,
            "gpu": self.gpu, "size": self.size, "currency": self.currency,
            "started": text(self.started), "ended": self.ended.map(text), "running": self.running(),
            "end_inferred": self.end_inferred,
            "seconds": round(seconds, 3), "factor": round(factor, 6), "cost": round(cost, 6),
            "intervals": intervals,
        }))
    }
}

pub fn text(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn round(x: f64, places: i32) -> f64 {
    let p = 10f64.powi(places);
    (x * p).round() / p
}

/// Reads a time the way the door writes them, RFC 3339.
pub fn parse_time(t: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(t, &Rfc3339).ok()
}

/// The facts only a member peer tells, relayed by its cloud: what it said, never what the cloud did or saw. Those
/// the cloud also tells itself about a member are left out (`JobFailed`, `JobStopped`, `DeploymentFailed`,
/// `DeploymentEnded`, `Undeployed`, `PromptFailed`), since one of them names the member without the member saying
/// anything.
const MEMBER_WORDS: &[&str] = &[
    "ImagePulling",
    "ImagePulled",
    "DeploymentStarted",
    "DeploymentReady",
    "JobStarted",
    "JobFinished",
    "OutOfMemory",
    "PromptAnswered",
];

/// The fold of a workspace's facts into its jobs by size, in the order the log holds them.
#[derive(Default)]
pub struct Fold {
    jobs: Vec<Metered>,
    /// The jobs still running, by `(cloud, job)`, as an index into `jobs`.
    running: HashMap<(String, String), usize>,
    /// The last fact a member peer told, by `(cloud, peer)`: where a job on a member lost is billed to when the
    /// loss does not say when the member was last heard.
    last_fact: HashMap<(String, String), OffsetDateTime>,
}

impl Fold {
    pub fn see(&mut self, e: &Envelope) {
        let Some(at) = parse_time(&e.time) else {
            return;
        };
        let d = &e.data;
        let cloud = d["cloud"].as_str().unwrap_or_default().to_string();
        if let Some(peer) = d["peer"]
            .as_str()
            .filter(|_| !cloud.is_empty() && MEMBER_WORDS.contains(&e.r#type.as_str()))
        {
            self.last_fact.insert((cloud.clone(), peer.to_string()), at);
        }
        match e.r#type.as_str() {
            "JobStarted" => self.started(&cloud, d, at),
            "JobFinished" | "JobFailed" | "JobStopped" => {
                let key = (cloud, d["job"].as_str().unwrap_or_default().to_string());
                if let Some(i) = self.running.remove(&key) {
                    self.jobs[i].ended = Some(at.max(self.jobs[i].started));
                }
            }
            "PeerLost" => {
                let peer = d["peer"].as_str().unwrap_or_default().to_string();
                let heard = d["last_heard"].as_str().and_then(parse_time);
                let fact = self.last_fact.get(&(cloud.clone(), peer.clone())).copied();
                let last = heard.or(fact);
                let lost: Vec<(String, String)> = self
                    .running
                    .iter()
                    .filter(|(k, i)| k.0 == cloud && self.jobs[**i].peer.as_deref() == Some(peer.as_str()))
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in lost {
                    if let Some(i) = self.running.remove(&key) {
                        let j = &mut self.jobs[i];
                        j.ended = Some(last.unwrap_or(j.started).clamp(j.started, at.max(j.started)));
                        j.end_inferred = true;
                    }
                }
            }
            "MenuSetV1" => self.menu_set(&cloud, d, at),
            _ => {}
        }
    }

    /// A job's start, where its receipt prices it; a job ordered by memory_bytes is the owner's machine and unpriced.
    fn started(&mut self, cloud: &str, d: &Value, at: OffsetDateTime) {
        let r = &d["receipt"];
        let (Some(job), Some(size), Some(price), Some(currency)) = (
            d["job"].as_str(),
            r["size"].as_str(),
            r["price_per_second"].as_f64(),
            r["currency"].as_str(),
        ) else {
            return;
        };
        let key = (cloud.to_string(), job.to_string());
        if self.running.contains_key(&key) {
            return;
        }
        let owned = |v: &Value| v.as_str().map(str::to_string);
        self.running.insert(key, self.jobs.len());
        self.jobs.push(Metered {
            job: job.into(),
            order: owned(&d["order"]),
            holder: owned(&d["holder"]),
            cloud: cloud.into(),
            peer: owned(&d["peer"]),
            size: size.into(),
            currency: currency.into(),
            device: owned(&r["device"]),
            gpu: owned(&r["gpu"]),
            started: at,
            ended: None,
            end_inferred: false,
            cuts: vec![Cut {
                from: at,
                price,
                factor: 1.0,
            }],
        });
    }

    /// A menu set on `cloud`: each running job whose size it prices otherwise, in the job's currency, is billed at
    /// the new price from now.
    fn menu_set(&mut self, cloud: &str, d: &Value, at: OffsetDateTime) {
        let currency = d["currency"].as_str().unwrap_or_default();
        let prices: HashMap<&str, f64> = d["sizes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| Some((s["name"].as_str()?, s["price_per_second"].as_f64()?)))
            .collect();
        for (key, i) in &self.running {
            let j = &mut self.jobs[*i];
            if key.0 != cloud || j.currency != currency {
                continue;
            }
            let (Some(price), Some(last)) = (prices.get(j.size.as_str()), j.cuts.last()) else {
                continue;
            };
            if *price != last.price {
                let factor = last.factor;
                j.cuts.push(Cut {
                    from: at.max(last.from),
                    price: *price,
                    factor,
                });
            }
        }
    }

    pub fn jobs(self) -> Vec<Metered> {
        self.jobs
    }
}

/// Every job by size the log tells, as it stands now.
pub fn metered(log: &EventLog) -> Vec<Metered> {
    let mut f = Fold::default();
    log.replay(|e| f.see(e));
    f.jobs()
}

/// What `get-usage` answers for `jobs` between `from` and `to`: each job that ran then, with its intervals, and the
/// totals per currency.
pub fn usage(jobs: &[Metered], now: OffsetDateTime, from: Option<OffsetDateTime>, to: OffsetDateTime) -> Value {
    let views: Vec<Value> = jobs.iter().filter_map(|j| j.view(now, from, to)).collect();
    let mut totals: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    for v in &views {
        let t = totals
            .entry(v["currency"].as_str().unwrap_or_default().to_string())
            .or_default();
        t.0 += v["seconds"].as_f64().unwrap_or(0.0);
        t.1 += v["cost"].as_f64().unwrap_or(0.0);
    }
    let totals: Vec<Value> = totals
        .into_iter()
        .map(|(currency, (seconds, cost))| {
            json!({ "currency": currency, "seconds": round(seconds, 3), "cost": round(cost, 6) })
        })
        .collect();
    json!({
        "from": from.map(text),
        "to": text(to),
        "jobs": views,
        "totals": totals,
    })
}

/// A workspace's spending cap: an amount in one currency.
#[derive(Clone, Debug, PartialEq)]
pub struct Cap {
    pub amount: f64,
    pub currency: String,
}

/// An order open on a cloud, as the cap counts it: its id, its menu's currency, and the most it may cost (its price
/// times its deadline), none for an order with no deadline.
#[derive(Clone, Debug, PartialEq)]
pub struct Open {
    pub order: String,
    pub currency: String,
    pub most: Option<f64>,
}

type Opens = Box<dyn Fn() -> Vec<Open> + Send + Sync>;

/// A workspace's spending: its cap, and the clouds whose open orders count against it.
pub struct Purse {
    log: Arc<EventLog>,
    cap: Mutex<Option<Cap>>,
    clouds: Mutex<Vec<Opens>>,
}

impl Purse {
    pub fn new(log: Arc<EventLog>) -> Self {
        Self {
            log,
            cap: Mutex::new(None),
            clouds: Mutex::new(Vec::new()),
        }
    }

    pub fn set(&self, cap: Option<Cap>) {
        *self.cap.lock().unwrap() = cap;
    }

    pub fn cap(&self) -> Option<Cap> {
        self.cap.lock().unwrap().clone()
    }

    /// Adds a cloud: `opens` answers the orders it has taken and not ended, admitted ones included.
    pub fn add(&self, opens: impl Fn() -> Vec<Open> + Send + Sync + 'static) {
        self.clouds.lock().unwrap().push(Box::new(opens));
    }

    /// In `currency`: what the workspace's jobs by size cost up to now, and what its open orders may still spend
    /// above what their running jobs already did.
    pub fn standing(&self, currency: &str) -> (f64, f64) {
        let now = OffsetDateTime::now_utc();
        let jobs = metered(&self.log);
        let mine = jobs.iter().filter(|j| j.currency == currency);
        let spent: f64 = mine.clone().map(|j| j.cost(now)).sum();
        let mut running: HashMap<&str, f64> = HashMap::new();
        for j in mine.filter(|j| j.running()) {
            if let Some(o) = &j.order {
                *running.entry(o.as_str()).or_default() += j.cost(now);
            }
        }
        // By the order's id: an order read both as admitted and as taken, in the moment between, counts once.
        let mut open: HashMap<String, f64> = HashMap::new();
        for cloud in self.clouds.lock().unwrap().iter() {
            for o in cloud() {
                if let (true, Some(most)) = (o.currency == currency, o.most) {
                    open.insert(o.order, most);
                }
            }
        }
        let held: f64 = open
            .iter()
            .map(|(order, most)| (most - running.get(order.as_str()).copied().unwrap_or(0.0)).max(0.0))
            .sum();
        (spent, held)
    }

    /// Refuses an order of `size` at `price` per second in `currency`, running at most `deadline` seconds, when the
    /// workspace's cap does not allow it, in words; any order when there is no cap.
    pub fn allows(&self, size: &str, price: f64, currency: &str, deadline: Option<u64>) -> Result<(), BestError> {
        let Some(cap) = self.cap() else {
            return Ok(());
        };
        if currency != cap.currency {
            return Err(BestError::bad_request(
                "SPENDING_CAP_CURRENCY",
                format!(
                    "this workspace's spending cap is in {} and this cloud's menu prices in {currency}, so the order's cost cannot be held to it: ask the workspace's owner to set the cap in {currency} with set-spending-cap, or the menu in {}",
                    cap.currency, cap.currency
                ),
            )
            .with_details(json!({ "field": "size", "cap_currency": cap.currency, "currency": currency })));
        }
        let Some(deadline) = deadline else {
            return Err(BestError::bad_request(
                "DEADLINE_NEEDED",
                format!(
                    "this workspace has a spending cap of {} {}, so an order by size bounds what it may cost: send deadline_seconds, how long its job may run",
                    cap.amount, cap.currency
                ),
            )
            .with_details(json!({ "field": "deadline_seconds" })));
        };
        let most = price * deadline as f64;
        let (spent, held) = self.standing(currency);
        if spent + held + most > cap.amount + 1e-9 {
            return Err(BestError::bad_request(
                "SPENDING_CAP",
                format!(
                    "size {size} at {price} {currency} a second for up to {deadline} seconds may cost {most:.2} {currency}; with {spent:.2} spent and {held:.2} held by the orders still open, it would pass this workspace's spending cap of {:.2} {currency}: send a shorter deadline_seconds, order a smaller size, or ask the workspace's owner to raise the cap with set-spending-cap",
                    cap.amount
                ),
            )
            .with_details(json!({
                "field": "deadline_seconds", "cap": cap.amount, "currency": currency,
                "spent": round(spent, 6), "held": round(held, 6), "most": round(most, 6)
            })));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(t: &str, r#type: &str, data: Value) -> Envelope {
        Envelope {
            specversion: "1.0".into(),
            id: format!("{type}-{t}"),
            source: "https://door.test".into(),
            r#type: r#type.into(),
            time: format!("2026-10-20T10:{t}Z"),
            datacontenttype: "application/json".into(),
            dataschema: None,
            correlationid: None,
            data,
            extensions: Default::default(),
        }
    }

    fn started(t: &str, job: &str, peer: &str, price: f64) -> Envelope {
        fact(
            t,
            "JobStarted",
            json!({ "cloud": "lab", "peer": peer, "job": job, "order": format!("o-{job}"), "holder": "h1",
                "receipt": { "size": "small", "gpu": "RTX 5090", "device": format!("lab/{peer}/gpu-0"), "shared": false, "share": 1.0, "price_per_second": price, "currency": "EUR" } }),
        )
    }

    fn menu(t: &str, price: f64) -> Envelope {
        fact(
            t,
            "MenuSetV1",
            json!({ "cloud": "lab", "currency": "EUR", "sizes": [{ "name": "small", "price_per_second": price }] }),
        )
    }

    fn fold(facts: &[Envelope]) -> Vec<Metered> {
        let mut f = Fold::default();
        for e in facts {
            f.see(e);
        }
        f.jobs()
    }

    fn at(t: &str) -> OffsetDateTime {
        parse_time(&format!("2026-10-20T10:{t}Z")).unwrap()
    }

    #[test]
    fn a_job_is_billed_from_its_start_to_its_end_at_its_receipts_price() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "01:40",
                "JobFinished",
                json!({ "cloud": "lab", "peer": "a", "job": "j1", "exit_code": 0 }),
            ),
        ]);
        let u = usage(&jobs, at("30:00"), None, at("30:00"));
        let j = &u["jobs"][0];
        assert_eq!(
            (j["seconds"].as_f64(), j["factor"].as_f64(), j["cost"].as_f64()),
            (Some(100.0), Some(1.0), Some(1.0))
        );
        assert_eq!(j["running"], false);
        assert_eq!(
            u["totals"],
            json!([{ "currency": "EUR", "seconds": 100.0, "cost": 1.0 }])
        );
    }

    #[test]
    fn a_menu_price_changed_mid_run_bills_each_interval_at_the_price_it_had() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            menu("01:00", 0.02),
            // Another cloud's menu, or a size's price unchanged, cuts nothing.
            fact(
                "01:10",
                "MenuSetV1",
                json!({ "cloud": "other", "currency": "EUR", "sizes": [{ "name": "small", "price_per_second": 9.0 }] }),
            ),
            menu("01:20", 0.02),
            fact("02:00", "JobStopped", json!({ "cloud": "lab", "job": "j1" })),
        ]);
        let u = usage(&jobs, at("30:00"), None, at("30:00"));
        let iv = u["jobs"][0]["intervals"].as_array().unwrap().clone();
        assert_eq!(iv.len(), 2, "{iv:?}");
        assert_eq!(
            (iv[0]["seconds"].as_f64(), iv[0]["price_per_second"].as_f64()),
            (Some(60.0), Some(0.01))
        );
        assert_eq!(
            (iv[1]["seconds"].as_f64(), iv[1]["price_per_second"].as_f64()),
            (Some(60.0), Some(0.02))
        );
        assert_eq!(u["jobs"][0]["cost"].as_f64(), Some(1.8));
        // A later change, after the job ended, rewrites nothing.
        let later = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "01:00",
                "JobFinished",
                json!({ "cloud": "lab", "job": "j1", "exit_code": 0 }),
            ),
            menu("05:00", 1.0),
        ]);
        assert_eq!(
            usage(&later, at("30:00"), None, at("30:00"))["jobs"][0]["cost"].as_f64(),
            Some(0.6)
        );
    }

    #[test]
    fn a_job_on_a_member_lost_is_billed_to_the_last_moment_the_member_was_heard() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            started("00:00", "j2", "b", 0.01),
            fact(
                "10:00",
                "PeerLost",
                json!({ "cloud": "lab", "peer": "a", "reason": "unreachable", "last_heard": "2026-10-20T10:02:30Z" }),
            ),
            // The member's own word after the loss changes nothing: the job ended at the loss.
            fact(
                "11:00",
                "JobFinished",
                json!({ "cloud": "lab", "peer": "a", "job": "j1", "exit_code": 0 }),
            ),
        ]);
        let u = usage(&jobs, at("20:00"), None, at("20:00"));
        let lost = u["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|j| j["job"] == "j1")
            .unwrap()
            .clone();
        assert_eq!(lost["seconds"].as_f64(), Some(150.0));
        assert_eq!(lost["end_inferred"], true);
        assert_eq!(lost["ended"], "2026-10-20T10:02:30Z");
        let other = u["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|j| j["job"] == "j2")
            .unwrap()
            .clone();
        assert_eq!(
            (other["running"].clone(), other["seconds"].as_f64()),
            (json!(true), Some(1200.0))
        );
    }

    #[test]
    fn what_the_cloud_told_of_a_member_after_it_was_last_heard_does_not_lengthen_the_bill() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            // The cloud's own facts naming the member: a placement and a prompt that failed for want of it.
            fact(
                "03:00",
                "JobPlaced",
                json!({ "cloud": "lab", "peer": "a", "job": "o2" }),
            ),
            fact(
                "04:00",
                "PromptFailed",
                json!({ "cloud": "lab", "peer": "a", "deployment": "d", "reason": "unreachable" }),
            ),
            fact(
                "05:00",
                "PeerLost",
                json!({ "cloud": "lab", "peer": "a", "reason": "unreachable", "last_heard": "2026-10-20T10:02:30Z" }),
            ),
        ]);
        let u = usage(&jobs, at("20:00"), None, at("20:00"));
        assert_eq!(u["jobs"][0]["seconds"].as_f64(), Some(150.0), "{u}");
        // Without last_heard, they are not the member's word either.
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "01:00",
                "PromptAnswered",
                json!({ "cloud": "lab", "peer": "a", "deployment": "d" }),
            ),
            fact(
                "04:00",
                "PromptFailed",
                json!({ "cloud": "lab", "peer": "a", "deployment": "d", "reason": "unreachable" }),
            ),
            fact(
                "05:00",
                "PeerLost",
                json!({ "cloud": "lab", "peer": "a", "reason": "unreachable" }),
            ),
        ]);
        assert_eq!(
            usage(&jobs, at("20:00"), None, at("20:00"))["jobs"][0]["seconds"].as_f64(),
            Some(60.0)
        );
    }

    #[test]
    fn a_member_lost_without_last_heard_is_billed_to_its_last_fact() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "03:00",
                "PromptAnswered",
                json!({ "cloud": "lab", "peer": "a", "deployment": "d" }),
            ),
            fact(
                "10:00",
                "PeerLost",
                json!({ "cloud": "lab", "peer": "a", "reason": "unreachable" }),
            ),
        ]);
        let u = usage(&jobs, at("20:00"), None, at("20:00"));
        assert_eq!(u["jobs"][0]["seconds"].as_f64(), Some(180.0));
        // An engine's end the member told is its word as well.
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "04:00",
                "OutOfMemory",
                json!({ "cloud": "lab", "peer": "a", "deployment": "d" }),
            ),
            fact(
                "10:00",
                "PeerLost",
                json!({ "cloud": "lab", "peer": "a", "reason": "unreachable" }),
            ),
        ]);
        let u = usage(&jobs, at("20:00"), None, at("20:00"));
        assert_eq!(u["jobs"][0]["seconds"].as_f64(), Some(240.0));
    }

    #[test]
    fn a_window_clips_each_job_to_it_and_leaves_out_what_ran_outside() {
        let jobs = fold(&[
            started("00:00", "j1", "a", 0.01),
            fact(
                "02:00",
                "JobFinished",
                json!({ "cloud": "lab", "job": "j1", "exit_code": 0 }),
            ),
            started("05:00", "j2", "a", 0.01),
            fact(
                "06:00",
                "JobFinished",
                json!({ "cloud": "lab", "job": "j2", "exit_code": 0 }),
            ),
        ]);
        let u = usage(&jobs, at("30:00"), Some(at("01:00")), at("03:00"));
        assert_eq!(u["jobs"].as_array().unwrap().len(), 1);
        assert_eq!(u["jobs"][0]["seconds"].as_f64(), Some(60.0));
    }

    #[test]
    fn an_order_by_memory_bytes_is_not_priced() {
        let jobs = fold(&[fact(
            "00:00",
            "JobStarted",
            json!({ "cloud": "lab", "peer": "a", "job": "j1", "order": "o1" }),
        )]);
        assert!(jobs.is_empty());
    }
}
