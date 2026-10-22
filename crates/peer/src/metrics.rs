//! The peer's series for `/metrics` (behavioralstate/spec#47): the devices, the workloads and their prompts, read
//! from the same two answers `get-hardware-state` and `get-workloads` give the credential, so a series shows
//! nothing the credential could not read there: a key held to the accelerators sees no CPU, and a key sees its own
//! workloads alone unless it was approved for all, or for the metrics scope, which reads every holder's and may do
//! nothing else.
//!
//! The labels are what the peer itself knows: `device`, `vendor`, `api` (the compute API a workload asks for:
//! `cuda`, `rocm`, `cpu`), and on a workload its id, its device and its holder. Where the peer sits (its
//! workspace and cloud) is the collector's to add, or the cloud door's that fronts it, since one machine may serve
//! the clouds of several workspaces.

use std::sync::Arc;

use best_peer_door::auth::Credential;
use best_peer_door::metrics::{Family, Kind, MetricsSource, METRICS_SCOPE};
use best_peer_gpu::DeviceId;
use serde_json::Value;

use crate::domain::Service;
use crate::lifecycle::Peer;

/// The series of `peer`, for `/metrics`.
pub fn source(peer: Arc<Peer>) -> MetricsSource {
    Arc::new(move |who: Credential| {
        let peer = peer.clone();
        Box::pin(async move { families(&peer, &reader(who)).await })
    })
}

/// Who the series are read as. A credential approved for the metrics scope reads every holder's workloads, as one
/// approved for all would, and that is all it gets: the reader exists only here, to ask the two queries.
fn reader(who: Credential) -> Credential {
    if who.grant.allows(METRICS_SCOPE) && !who.grant.is_all() {
        let mut every = who;
        every.grant.scopes = None;
        every
    } else {
        who
    }
}

/// `vendor` as the hardware answer writes it: a name, or `{"other": "host"}`.
fn vendor_of(d: &Value) -> String {
    match &d["vendor"] {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.values().next().and_then(Value::as_str).unwrap_or("other").to_string(),
        _ => "unknown".into(),
    }
}

/// The compute API a workload on the device asks for first: `cuda`, `rocm`, `cpu`, …
fn api_of(d: &Value) -> String {
    d["compute"][0]["api"].as_str().unwrap_or("none").to_string()
}

async fn families(peer: &Peer, who: &Credential) -> Vec<Family> {
    let mut info = Family::new(
        "best_peer",
        Kind::Info,
        "This peer: its version and the accelerator driver it reads.",
    );
    let mut readable = Family::new(
        "best_peer_hardware_readable",
        Kind::Gauge,
        "1 when the peer read its hardware for this scrape, 0 when the driver did not answer: the device series are then absent.",
    );
    let mut d_info = Family::new(
        "best_peer_device",
        Kind::Info,
        "What a device is: its name, every compute API it offers, and whether it is a whole card or a MIG instance.",
    );
    let mut total = Family::new("best_peer_device_memory_total_bytes", Kind::Gauge, "A device's memory.").unit("bytes");
    let mut free = Family::new(
        "best_peer_device_memory_free_bytes",
        Kind::Gauge,
        "A device's memory free now, as the driver reports it.",
    )
    .unit("bytes");
    let mut promised = Family::new(
        "best_peer_device_memory_promised_bytes",
        Kind::Gauge,
        "The memory on a device promised to what is admitted, starting or running there, every holder's; read by a credential approved for all or for metrics.",
    )
    .unit("bytes");
    let mut util = Family::new(
        "best_peer_device_utilisation_ratio",
        Kind::Gauge,
        "A device's compute utilisation, from 0 to 1, where the driver reports it.",
    );
    let mut temp = Family::new(
        "best_peer_device_temperature_celsius",
        Kind::Gauge,
        "A device's temperature, where the driver reports it.",
    )
    .unit("celsius");
    let mut power = Family::new(
        "best_peer_device_power_watts",
        Kind::Gauge,
        "The power a device draws now, where the driver reports it.",
    )
    .unit("watts");
    let mut energy = Family::new(
        "best_peer_device_energy_joules",
        Kind::Counter,
        "The energy a device has used since its driver loaded, where the driver reports it: what a stretch used is the difference, which sampled power misses.",
    )
    .unit("joules");
    let mut disk_free = Family::new(
        "best_peer_disk_free_bytes",
        Kind::Gauge,
        "The room for jobs' disks: free, less what is promised to jobs not given theirs yet.",
    )
    .unit("bytes");
    let mut disk_total = Family::new(
        "best_peer_disk_total_bytes",
        Kind::Gauge,
        "The room for jobs' disks in all.",
    )
    .unit("bytes");

    let version = env!("CARGO_PKG_VERSION");
    match peer.hardware_state(who).await {
        Ok(h) => {
            readable.sample(&[], 1.0);
            info.sample(
                &[("version", version), ("driver", h["driver"].as_str().unwrap_or(""))],
                1.0,
            );
            let every = who.grant.is_all();
            for d in h["devices"].as_array().into_iter().flatten() {
                let id = d["id"].as_str().unwrap_or_default();
                let (vendor, api) = (vendor_of(d), api_of(d));
                let labels = [("device", id), ("vendor", vendor.as_str()), ("api", api.as_str())];
                let apis: Vec<String> = d["compute"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|c| match c["version"].as_str() {
                        Some(v) => format!("{} {v}", c["api"].as_str().unwrap_or_default()),
                        None => c["api"].as_str().unwrap_or_default().to_string(),
                    })
                    .collect();
                d_info.sample(
                    &[
                        ("device", id),
                        ("vendor", &vendor),
                        ("api", &api),
                        ("name", d["name"].as_str().unwrap_or_default()),
                        // Joined with "; ": some readers of the format split a label value at a comma.
                        ("apis", &apis.join("; ")),
                        ("slicing", d["slicing"].as_str().unwrap_or("none")),
                    ],
                    1.0,
                );
                if let Some(v) = d["memory"]["total_bytes"].as_f64() {
                    total.sample(&labels, v);
                }
                if let Some(v) = d["memory"]["free_bytes"].as_f64() {
                    free.sample(&labels, v);
                }
                if every {
                    let p = peer.state.lock().unwrap().reserved_on(&DeviceId(id.to_string()));
                    promised.sample(&labels, p as f64);
                }
                if let Some(v) = d["utilisation_pct"].as_f64() {
                    util.sample(&labels, v / 100.0);
                }
                if let Some(v) = d["temperature_c"].as_f64() {
                    temp.sample(&labels, v);
                }
                if let Some(v) = d["power_w"].as_f64() {
                    // To the milliwatt the driver reads, not the float's last digits.
                    power.sample(&labels, (v * 1000.0).round() / 1000.0);
                }
                if let Some(v) = d["energy_j"].as_f64() {
                    energy.sample(&labels, v);
                }
            }
            if let Some(v) = h["disk"]["free_bytes"].as_f64() {
                disk_free.sample(&[], v);
            }
            if let Some(v) = h["disk"]["total_bytes"].as_f64() {
                disk_total.sample(&[], v);
            }
        }
        Err(e) => {
            readable.sample(&[], 0.0);
            info.sample(&[("version", version), ("driver", "")], 1.0);
            tracing::warn!(error = %e.message, "the hardware did not answer for a scrape");
        }
    }

    let mut dep_info = Family::new(
        "best_peer_deployment",
        Kind::Info,
        "What a deployment is: its model, engine, device and holder, while it lives.",
    );
    let mut dep_phase = Family::new(
        "best_peer_deployment_phase",
        Kind::Gauge,
        "A deployment's phase as a set: 1 for the phase it is in, 0 for the others; gone once it ended.",
    );
    let mut dep_memory = Family::new(
        "best_peer_deployment_memory_promised_bytes",
        Kind::Gauge,
        "The device memory promised to a deployment.",
    )
    .unit("bytes");
    let mut prompts = Family::new(
        "best_peer_prompts",
        Kind::Counter,
        "A deployment's prompts while it lives, by outcome (answered, failed).",
    );
    let mut tokens = Family::new(
        "best_peer_prompt_tokens",
        Kind::Counter,
        "The tokens the engine counted for a deployment's answered prompts, by kind (prompt, completion).",
    );
    let mut job_info = Family::new(
        "best_peer_job",
        Kind::Info,
        "What a job is: its device and holder, while it runs.",
    );
    let mut job_phase = Family::new(
        "best_peer_job_phase",
        Kind::Gauge,
        "A job's phase as a set: 1 for the phase it is in, 0 for the others; gone once it ended.",
    );
    let mut job_memory = Family::new(
        "best_peer_job_memory_promised_bytes",
        Kind::Gauge,
        "The device memory promised to a job; none for a job with no device.",
    )
    .unit("bytes");
    let mut queued = Family::new(
        "best_peer_orders_waiting",
        Kind::Gauge,
        "The orders of this peer's queue that wait for a device with their room, as the scraping credential reads them.",
    );
    if let Ok(w) = peer.workloads(who) {
        for d in w["deployments"].as_array().into_iter().flatten() {
            let id = d["deployment"].as_str().unwrap_or_default();
            let device = d["device"].as_str().unwrap_or_default();
            let holder = d["holder"].as_str().unwrap_or_default();
            dep_info.sample(
                &[
                    ("deployment", id),
                    ("device", device),
                    ("holder", holder),
                    ("model", d["model"].as_str().unwrap_or_default()),
                    ("engine", d["engine"].as_str().unwrap_or_default()),
                ],
                1.0,
            );
            // Every phase, each 1 or 0, so a phase change moves a value rather than ending one series and starting
            // another.
            let now = d["phase"].as_str().unwrap_or_default();
            for phase in crate::state::Phase::ALL.map(crate::state::Phase::name) {
                dep_phase.sample(
                    &[("deployment", id), ("phase", phase)],
                    f64::from(u8::from(phase == now)),
                );
            }
            if let Some(v) = d["memory_bytes"].as_f64() {
                dep_memory.sample(&[("deployment", id), ("device", device), ("holder", holder)], v);
            }
            let p = &d["prompts"];
            for outcome in ["answered", "failed"] {
                prompts.sample(
                    &[("deployment", id), ("outcome", outcome)],
                    p[outcome].as_f64().unwrap_or(0.0),
                );
            }
            for (kind, field) in [("prompt", "prompt_tokens"), ("completion", "completion_tokens")] {
                tokens.sample(&[("deployment", id), ("kind", kind)], p[field].as_f64().unwrap_or(0.0));
            }
        }
        for j in w["jobs"].as_array().into_iter().flatten() {
            let id = j["job"].as_str().unwrap_or_default();
            let device = j["device"].as_str().unwrap_or_default();
            let holder = j["holder"].as_str().unwrap_or_default();
            job_info.sample(&[("job", id), ("device", device), ("holder", holder)], 1.0);
            let now = j["phase"].as_str().unwrap_or_default();
            for phase in crate::state::JobPhase::ALL.map(crate::state::JobPhase::name) {
                job_phase.sample(&[("job", id), ("phase", phase)], f64::from(u8::from(phase == now)));
            }
            if let (true, Some(v)) = (j["device"].is_string(), j["memory_bytes"].as_f64()) {
                job_memory.sample(&[("job", id), ("device", device), ("holder", holder)], v);
            }
        }
        queued.sample(&[], w["queued"].as_array().map_or(0, Vec::len) as f64);
    }

    let mut out = vec![info, readable, d_info, total, free];
    if who.grant.is_all() {
        out.push(promised);
    }
    out.extend([
        util, temp, power, energy, disk_free, disk_total, dep_info, dep_phase, dep_memory, prompts, tokens, job_info,
        job_phase, job_memory, queued,
    ]);
    out
}
