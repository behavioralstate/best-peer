//! A cloud's menu: the sizes an order names instead of hardware. A size is a name, its floors and a price: the device
//! memory it reserves, the compute API and the least version its device offers, the host memory of the device's
//! machine, the share of the device's compute it guarantees, and what a second of it costs. Placement checks the
//! floors; people read the name. A size's memory is a slice of a device only where the device holds a job to its
//! slice ([`Slicing`]); elsewhere the size takes the whole device, since a share nothing enforces is a promise nothing
//! keeps (behavioralstate/spec#64, decision 3).

use std::collections::HashSet;

use best_peer_door::BestError;
use best_peer_gpu::{Compute, Device, DeviceId, Host, Slicing};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::domain;
use crate::state::State;

/// One size on a menu.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Size {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The device memory the size reserves for its job.
    pub memory_bytes: u64,
    /// The compute API its device offers, at this version or newer.
    pub compute: Compute,
    /// The least host memory of the machine its device is on, where the size names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_memory_bytes: Option<u64>,
    /// The share of the device's compute the size guarantees, above 0 and at most 1.
    pub share: f64,
    /// What a second of the size costs, in the menu's currency.
    pub price_per_second: f64,
}

/// A cloud's menu: its sizes, priced in one currency.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Menu {
    pub currency: String,
    pub sizes: Vec<Size>,
}

/// Where a size went, as its receipt says it: the device, how much of it was reserved, and whether the device may
/// hold other jobs beside it.
#[derive(Clone, Debug, PartialEq)]
pub struct Placed {
    pub device: DeviceId,
    pub compute: Compute,
    pub reserved: u64,
    pub shared: bool,
    pub gpu: String,
}

/// Why a size was not placed now: no device has its room free yet, or no device of the cloud meets its floors at all.
#[derive(Clone, Debug, PartialEq)]
pub enum NotPlaced {
    Busy,
    Never,
}

impl Menu {
    /// Refuses a menu that cannot be read the way placement reads it, naming the field and what to send instead.
    pub fn check(&self) -> Result<(), BestError> {
        let bad = |code: &'static str, field: &str, message: String| {
            Err(BestError::bad_request(code, message).with_details(json!({ "field": field })))
        };
        let c = &self.currency;
        if c.len() != 3 || !c.chars().all(|ch| ch.is_ascii_uppercase()) {
            return bad(
                "INVALID_MENU",
                "currency",
                format!("currency {c:?} is not an ISO 4217 code: three capital letters, such as EUR or USD"),
            );
        }
        let mut names = HashSet::new();
        for s in &self.sizes {
            if !domain::is_name(&s.name) {
                return bad(
                    "INVALID_NAME",
                    "sizes",
                    format!("size {:?} must be {}", s.name, domain::NAME_SHAPE),
                );
            }
            if !names.insert(s.name.as_str()) {
                return bad(
                    "INVALID_MENU",
                    "sizes",
                    format!("size {} is listed twice: give each size its own name", s.name),
                );
            }
            if !(s.share > 0.0 && s.share <= 1.0) {
                return bad(
                    "INVALID_MENU",
                    "sizes",
                    format!(
                        "size {}'s share {} is not above 0 and at most 1: a share is the part of a device's compute the size guarantees",
                        s.name, s.share
                    ),
                );
            }
            if !(s.price_per_second.is_finite() && s.price_per_second >= 0.0) {
                return bad(
                    "INVALID_MENU",
                    "sizes",
                    format!("size {}'s price_per_second must be a number of 0 or more", s.name),
                );
            }
            if !s.compute.version_reads() {
                return bad(
                    "INVALID_MENU",
                    "sizes",
                    format!(
                        "size {}'s compute version does not read as dotted numbers, such as 12 or 12.4: nothing would ever meet it",
                        s.name
                    ),
                );
            }
        }
        Ok(())
    }

    pub fn size(&self, name: &str) -> Option<&Size> {
        self.sizes.iter().find(|s| s.name == name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.sizes.iter().map(|s| s.name.as_str()).collect()
    }

    /// The menu as `get-menu` answers it for one cloud: each size with the devices of `whole` (every device of the
    /// cloud's members that answer) that meet its floors, and whether each has the size's room now.
    pub fn view(&self, cloud: &str, whole: &Host, state: &State, taken: &HashSet<String>) -> Value {
        let sizes: Vec<Value> = self
            .sizes
            .iter()
            .map(|s| {
                let sources: Vec<Value> = whole
                    .devices
                    .iter()
                    .filter(|d| s.meets(whole, d))
                    .map(|d| {
                        let now = s.room_on(d, state, taken);
                        json!({
                            "peer": peer_of(&d.id.0),
                            "device": d.id.0,
                            "gpu": d.name,
                            "whole_device": d.slicing == Slicing::None,
                            "free_now": now,
                        })
                    })
                    .collect();
                let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
                v["sources"] = json!(sources);
                v
            })
            .collect();
        json!({ "cloud": cloud, "currency": self.currency, "sizes": sizes })
    }
}

impl Size {
    /// Whether device `d` meets this size's floors: its memory, its compute API at the least version, and the host
    /// memory of its machine, read from that machine's CPU device in `whole`.
    pub fn meets(&self, whole: &Host, d: &Device) -> bool {
        d.memory.total_bytes >= self.memory_bytes
            && d.compute.iter().any(|c| c.satisfies(&self.compute))
            && self
                .host_memory_bytes
                .is_none_or(|floor| host_memory(whole, d).is_some_and(|m| m >= floor))
    }

    /// Whether `d` has this size's room now: a device that holds a job to its slice needs the slice free; any other
    /// is taken whole, so it must hold nothing of this cloud's and have the size's memory free.
    fn room_on(&self, d: &Device, state: &State, taken: &HashSet<String>) -> bool {
        if taken.contains(&d.id.0) {
            return false;
        }
        let reserved = state.reserved_on(&d.id);
        let room = d.memory.free_bytes.min(d.memory.total_bytes.saturating_sub(reserved));
        match d.slicing {
            Slicing::None => reserved == 0 && room >= self.memory_bytes,
            Slicing::Mps | Slicing::Mig => room >= self.memory_bytes,
        }
    }

    /// Where this size goes on `host` (the devices the credential may use), the floors read against `whole`: among
    /// the devices that meet them and have the room now, the one with the most room. `taken` are the devices a size
    /// already holds whole.
    pub fn place(
        &self,
        host: &Host,
        whole: &Host,
        state: &State,
        taken: &HashSet<String>,
    ) -> Result<Placed, NotPlaced> {
        let meeting: Vec<&Device> = host.devices.iter().filter(|d| self.meets(whole, d)).collect();
        if meeting.is_empty() {
            return Err(NotPlaced::Never);
        }
        let room = |d: &Device| {
            d.memory
                .free_bytes
                .min(d.memory.total_bytes.saturating_sub(state.reserved_on(&d.id)))
        };
        let best = meeting
            .into_iter()
            .filter(|d| self.room_on(d, state, taken))
            .max_by_key(|d| room(d))
            .ok_or(NotPlaced::Busy)?;
        let shared = best.slicing != Slicing::None;
        Ok(Placed {
            device: best.id.clone(),
            compute: self.compute.clone(),
            reserved: self.memory_bytes,
            shared,
            gpu: best.name.clone(),
        })
    }

    /// Its compute floor in words: "CUDA 12.6 or newer".
    pub fn compute_text(&self) -> String {
        match &self.compute {
            Compute::Cuda(v) => format!("CUDA {v} or newer"),
            Compute::Rocm(v) => format!("ROCm {v} or newer"),
            Compute::OneApi(v) => format!("oneAPI {v} or newer"),
            Compute::Metal => "Metal".into(),
            Compute::Vulkan => "Vulkan".into(),
            Compute::Cpu => "the CPU".into(),
        }
    }

    /// The receipt of this size placed as `p`, in `currency`: what the job got, as JobPlaced and JobStarted name it.
    pub fn receipt(&self, p: &Placed, currency: &str) -> Value {
        json!({
            "size": self.name,
            "gpu": p.gpu,
            "device": p.device.0,
            "shared": p.shared,
            "share": if p.shared { self.share } else { 1.0 },
            "price_per_second": self.price_per_second,
            "currency": currency,
        })
    }
}

/// The member peer a cloud device id names: `cloud/peer/device` → `peer`.
fn peer_of(id: &str) -> &str {
    id.split('/').nth(1).unwrap_or_default()
}

/// The machine a device id is on: `cloud/peer/device` → `cloud/peer/`.
fn machine_of(id: &str) -> &str {
    id.rfind('/').map(|i| &id[..=i]).unwrap_or_default()
}

/// The host memory of the machine `d` is on: the total of that machine's CPU device, where it lists one.
fn host_memory(whole: &Host, d: &Device) -> Option<u64> {
    let machine = machine_of(&d.id.0);
    whole
        .devices
        .iter()
        .filter(|x| machine_of(&x.id.0) == machine && x.compute.contains(&Compute::Cpu))
        .map(|x| x.memory.total_bytes)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use best_peer_gpu::Fake;
    use std::time::SystemTime;

    const GB: u64 = 1 << 30;

    fn dev(id: &str, gb: u64, cuda: &str, slicing: Slicing) -> Device {
        let mut d = Fake::cuda_card(id, &format!("Card {id}"), gb, cuda);
        d.slicing = slicing;
        d
    }

    fn host(devices: Vec<Device>) -> Host {
        Host {
            driver: None,
            devices,
            observed_at: SystemTime::now(),
        }
    }

    fn size(name: &str, gb: u64, cuda: &str) -> Size {
        Size {
            name: name.into(),
            description: None,
            memory_bytes: gb * GB,
            compute: Compute::Cuda(cuda.into()),
            host_memory_bytes: None,
            share: 0.5,
            price_per_second: 0.001,
        }
    }

    #[test]
    fn a_size_is_placed_only_where_its_floors_are_met_and_takes_a_device_whole_unless_the_device_holds_slices() {
        let cpu_a = Fake::host_cpu("lab/a/cpu-0", 64);
        let h = host(vec![
            dev("lab/a/gpu-0", 24, "12.4", Slicing::None),
            dev("lab/b/gpu-0", 48, "12.8", Slicing::Mps),
            cpu_a,
        ]);
        let state = State::default();
        let none = HashSet::new();
        // A floor of CUDA 12.6 rules the 12.4 card out; 40 GiB rules it out too.
        let big = size("large", 40, "12.6");
        let p = big.place(&h, &h, &state, &none).unwrap();
        assert_eq!(p.device.0, "lab/b/gpu-0");
        assert!(p.shared, "the device holds its jobs to their slices");
        // A small size fits both; the card that holds no slices is taken whole.
        let small = size("small", 8, "12");
        let on_a = small
            .place(&host(vec![h.devices[0].clone()]), &h, &state, &none)
            .unwrap();
        assert!(!on_a.shared);
        assert_eq!(
            small.receipt(&on_a, "EUR")["share"],
            1.0,
            "a whole device is all of its compute"
        );
        assert_eq!(small.receipt(&p_for(&small, &h, &state), "EUR")["share"], 0.5);
        // A host memory floor reads the machine's CPU: a has 64 GiB, b lists none.
        let mut needs_ram = size("ram", 8, "12");
        needs_ram.host_memory_bytes = Some(32 * GB);
        assert!(needs_ram.meets(&h, &h.devices[0]));
        assert!(!needs_ram.meets(&h, &h.devices[1]));
        // Nothing meets a size of 100 GiB, ever.
        assert_eq!(
            size("huge", 100, "12").place(&h, &h, &state, &none),
            Err(NotPlaced::Never)
        );
        // A device taken whole has no room for anything else; a free one meeting the floors is busy only.
        let taken: HashSet<String> = ["lab/a/gpu-0".to_string()].into();
        assert_eq!(
            small.place(&host(vec![h.devices[0].clone()]), &h, &state, &taken),
            Err(NotPlaced::Busy)
        );
    }

    fn p_for(s: &Size, h: &Host, state: &State) -> Placed {
        s.place(&host(vec![h.devices[1].clone()]), h, state, &HashSet::new())
            .unwrap()
    }

    #[test]
    fn a_menu_that_placement_could_not_read_is_refused_with_the_field() {
        let ok = Menu {
            currency: "EUR".into(),
            sizes: vec![size("small", 8, "12")],
        };
        assert!(ok.check().is_ok());
        let mut m = ok.clone();
        m.currency = "euro".into();
        assert_eq!(m.check().unwrap_err().details["field"], "currency");
        let mut m = ok.clone();
        m.sizes.push(size("small", 16, "12"));
        assert!(m.check().unwrap_err().message.contains("twice"));
        let mut m = ok.clone();
        m.sizes[0].share = 0.0;
        assert!(m.check().unwrap_err().message.contains("share"));
        let mut m = ok.clone();
        m.sizes[0].compute = Compute::Cuda("twelve".into());
        assert!(m.check().unwrap_err().message.contains("dotted numbers"));
        let mut m = ok;
        m.sizes[0].name = "Big One".into();
        assert_eq!(m.check().unwrap_err().code, "INVALID_NAME");
    }
}
