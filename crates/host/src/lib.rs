//! The host as a device: a [`Gpu`] adapter that answers with the machine's CPU and its system memory, offering the
//! `cpu` compute API. It stands in where no accelerator adapter does, so a peer on a laptop serves the whole
//! lifecycle on CPU; an accelerator adapter (NVML, ROCm) is a separate crate and may be combined with it. Thin,
//! proven by hand, never unit-tested.

use std::sync::Mutex;
use std::time::SystemTime;

use best_peer_gpu::{Compute, Device, DeviceId, Gpu, GpuError, Host, Memory, Vendor};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

pub struct HostCpu {
    system: Mutex<System>,
}

impl Default for HostCpu {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCpu {
    pub fn new() -> Self {
        let system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_memory(MemoryRefreshKind::everything())
                .with_cpu(CpuRefreshKind::everything()),
        );
        Self {
            system: Mutex::new(system),
        }
    }
}

impl Gpu for HostCpu {
    fn snapshot(&self) -> Result<Host, GpuError> {
        let mut s = self.system.lock().unwrap();
        s.refresh_memory();
        s.refresh_cpu_usage();
        let name = s
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_string())
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "CPU".into());
        let utilisation = s.global_cpu_usage().round().clamp(0.0, 100.0) as u8;
        Ok(Host {
            driver: None,
            devices: vec![Device {
                id: DeviceId("cpu-0".into()),
                vendor: Vendor::Other("host".into()),
                name,
                memory: Memory {
                    total_bytes: s.total_memory(),
                    free_bytes: s.available_memory(),
                },
                compute: vec![Compute::Cpu],
                temperature_c: None,
                power_w: None,
                utilisation_pct: Some(utilisation),
                slicing: best_peer_gpu::Slicing::None,
            }],
            observed_at: SystemTime::now(),
        })
    }
}
