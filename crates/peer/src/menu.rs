//! A cloud's menu: the sizes an order names instead of hardware. A size is a name, its floors and a price: the device
//! memory it needs, the compute API and the least version its device offers, the host memory of the device's
//! machine, the share of compute it stands for, and what a second of it costs. Placement checks the floors; people
//! read the name. A size takes a device whole: a whole card, or one instance of a card MIG splits in hardware, which
//! the peer reports as a device of its own. Nothing a client reads of a size names the hardware that served it
//! (behavioralstate/spec#64, decisions 4, 12 and 13).

use std::collections::HashSet;

use best_peer_door::BestError;
use best_peer_gpu::{Compute, Device, DeviceId, Host};
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
    /// The share of a card's compute the size stands for, above 0 and at most 1, for the client to read: a MIG
    /// instance's fraction of its card, 1 for a whole card. Placement reads the floors, not this.
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

/// Where a size went: the device it takes whole, and how much of it was reserved. The cloud keeps it; the receipt a
/// client reads does not name it.
#[derive(Clone, Debug, PartialEq)]
pub struct Placed {
    pub device: DeviceId,
    pub compute: Compute,
    pub reserved: u64,
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
                        "size {}'s share {} is not above 0 and at most 1: a share is the part of a card's compute the size stands for",
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

    /// The menu as `get-menu` answers it for one cloud: each size, whether some device of `whole` (every device of
    /// the cloud's members that answer) could ever hold it, and whether one has its room now. The devices are not
    /// named: a client deals in sizes.
    pub fn view(&self, cloud: &str, whole: &Host, state: &State, taken: &HashSet<String>) -> Value {
        let sizes: Vec<Value> = self
            .sizes
            .iter()
            .map(|s| {
                let meeting: Vec<&Device> = whole.devices.iter().filter(|d| s.meets(whole, d)).collect();
                let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
                v["offered"] = json!(!meeting.is_empty());
                v["available_now"] = json!(meeting.iter().any(|d| s.room_on(d, state, taken)));
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

    /// Whether `d` has this size's room now. A size takes its device whole, a card or a MIG instance alike, so the
    /// device must hold nothing of this cloud's and have the size's memory free.
    fn room_on(&self, d: &Device, state: &State, taken: &HashSet<String>) -> bool {
        if taken.contains(&d.id.0) {
            return false;
        }
        let reserved = state.reserved_on(&d.id);
        let room = d.memory.free_bytes.min(d.memory.total_bytes.saturating_sub(reserved));
        reserved == 0 && room >= self.memory_bytes
    }

    /// Where this size goes on `host` (the devices the credential may use), the floors read against `whole`: among
    /// the devices that meet them and have the room now, the smallest, so a larger one stays free for a larger size (a
    /// small size takes a 10 GB MIG instance before a 40 GB one). `taken` are the devices a size
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
        let best = meeting
            .into_iter()
            .filter(|d| self.room_on(d, state, taken))
            .min_by_key(|d| d.memory.total_bytes)
            .ok_or(NotPlaced::Busy)?;
        Ok(Placed {
            device: best.id.clone(),
            compute: self.compute.clone(),
            reserved: self.memory_bytes,
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

    /// The receipt of this size, in `currency`: what the job got, in the client's terms, as JobPlaced and JobStarted
    /// name it. The hardware that served it is not on it (behavioralstate/spec#64, decision 4).
    pub fn receipt(&self, currency: &str) -> Value {
        json!({
            "size": self.name,
            "price_per_second": self.price_per_second,
            "currency": currency,
        })
    }
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

    fn dev(id: &str, gb: u64, cuda: &str) -> Device {
        Fake::cuda_card(id, &format!("Card {id}"), gb, cuda)
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
    fn a_size_is_placed_only_where_its_floors_are_met_and_takes_its_device_whole() {
        let cpu_a = Fake::host_cpu("lab/a/cpu-0", 64);
        let h = host(vec![
            dev("lab/a/gpu-0", 24, "12.4"),
            dev("lab/b/gpu-0", 48, "12.8"),
            cpu_a,
        ]);
        let state = State::default();
        let none = HashSet::new();
        // A floor of CUDA 12.6 rules the 12.4 card out; 40 GiB rules it out too.
        let big = size("large", 40, "12.6");
        assert_eq!(big.place(&h, &h, &state, &none).unwrap().device.0, "lab/b/gpu-0");
        // A small size fits both and takes the one it goes to whole: nothing else goes there while it runs.
        let small = size("small", 8, "12");
        let on_a = small
            .place(&host(vec![h.devices[0].clone()]), &h, &state, &none)
            .unwrap();
        assert_eq!(on_a.device.0, "lab/a/gpu-0");
        let taken: HashSet<String> = ["lab/a/gpu-0".to_string()].into();
        assert_eq!(
            small.place(&host(vec![h.devices[0].clone()]), &h, &state, &taken),
            Err(NotPlaced::Busy)
        );
        // The receipt is the size's terms alone: no card, device or share of a card.
        assert_eq!(
            small.receipt("EUR"),
            json!({ "size": "small", "price_per_second": 0.001, "currency": "EUR" })
        );
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
    }

    #[test]
    fn the_instances_of_a_card_split_by_mig_are_devices_each_taken_whole_by_one_size() {
        let h = host(vec![
            Fake::mig_instance("lab/a/MIG-1", "A100", "1g.10gb", 9, "13.0"),
            Fake::mig_instance("lab/a/MIG-2", "A100", "1g.10gb", 9, "13.0"),
            Fake::mig_instance("lab/a/MIG-3", "A100", "3g.40gb", 39, "13.0"),
        ]);
        let state = State::default();
        // A small size goes to a 10 GB instance, never the 40 GB one while a small one is free; the large only fits there.
        let small = size("small", 8, "12");
        let large = size("large", 30, "12");
        assert_eq!(
            large.place(&h, &h, &state, &HashSet::new()).unwrap().device.0,
            "lab/a/MIG-3"
        );
        let taken: HashSet<String> = ["lab/a/MIG-3".to_string()].into();
        let p = small.place(&h, &h, &state, &taken).unwrap();
        assert!(p.device.0 == "lab/a/MIG-1" || p.device.0 == "lab/a/MIG-2", "{p:?}");
        // With every instance taken, a size waits.
        let all: HashSet<String> = h.devices.iter().map(|d| d.id.0.clone()).collect();
        assert_eq!(small.place(&h, &h, &state, &all), Err(NotPlaced::Busy));
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
