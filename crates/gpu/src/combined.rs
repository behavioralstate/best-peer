//! Several adapters as one: a GPU host answers with its cards and with the host itself, so a CPU deploy is placed
//! there too. The devices are listed in the adapters' order; the driver is the first one any adapter names; an
//! adapter that fails fails the whole snapshot, loudly, because a host that cannot see part of itself must not
//! place anything on what it cannot see.

use std::time::SystemTime;

use crate::{Gpu, GpuError, Host};

pub struct Combined {
    adapters: Vec<Box<dyn Gpu>>,
}

impl Combined {
    pub fn new(adapters: Vec<Box<dyn Gpu>>) -> Self {
        Self { adapters }
    }
}

impl Gpu for Combined {
    fn snapshot(&self) -> Result<Host, GpuError> {
        let mut driver = None;
        let mut devices = Vec::new();
        for adapter in &self.adapters {
            let host = adapter.snapshot()?;
            if driver.is_none() {
                driver = host.driver;
            }
            devices.extend(host.devices);
        }
        Ok(Host {
            driver,
            devices,
            observed_at: SystemTime::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Compute, Device, DeviceId, Fake, Memory, Vendor};

    fn cpu() -> Device {
        Device {
            id: DeviceId("cpu-0".into()),
            vendor: Vendor::Other("host".into()),
            name: "CPU".into(),
            memory: Memory {
                total_bytes: 32 << 30,
                free_bytes: 16 << 30,
            },
            compute: vec![Compute::Cpu],
            temperature_c: None,
            power_w: None,
            utilisation_pct: Some(3),
            slicing: crate::Slicing::None,
        }
    }

    #[test]
    fn the_cards_come_first_and_the_host_after_them_under_the_cards_driver() {
        let cards = Fake::new()
            .with_driver("580.65")
            .with_device(Fake::cuda_card("GPU-1", "A", 24, "12.8"))
            .with_device(Fake::cuda_card("GPU-2", "B", 24, "12.8"));
        let host = Fake::new().with_device(cpu());
        let all = Combined::new(vec![Box::new(cards), Box::new(host)]).snapshot().unwrap();
        let ids: Vec<&str> = all.devices.iter().map(|d| d.id.0.as_str()).collect();
        assert_eq!(ids, ["GPU-1", "GPU-2", "cpu-0"]);
        assert_eq!(all.driver.as_deref(), Some("580.65"));
        assert_eq!(all.fit(&Compute::Cuda("12.4".into()), 1).len(), 2);
        assert_eq!(all.fit(&Compute::Cpu, 1).len(), 1);
    }

    #[test]
    fn an_adapter_that_fails_fails_the_snapshot() {
        struct Broken;
        impl Gpu for Broken {
            fn snapshot(&self) -> Result<Host, GpuError> {
                Err(GpuError::Library("lost the driver".into()))
            }
        }
        let host = Fake::new().with_device(cpu());
        let err = Combined::new(vec![Box::new(Broken), Box::new(host)])
            .snapshot()
            .unwrap_err();
        assert!(err.to_string().contains("lost the driver"));
    }
}
