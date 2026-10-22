//! The [`Gpu`] adapter for NVIDIA devices, through NVML (the library every NVIDIA driver installs: `libnvidia-ml.so`
//! on Linux, `nvml.dll` on Windows). Loaded once at start; a host without it is told so and the peer refuses to
//! start, since a GPU host that cannot see its cards is misconfigured, not accelerator-less (`BEST_PEER_GPU=none`
//! says the latter). Every snapshot reads the cards live: memory, temperature, power, utilisation, and the CUDA
//! version the driver offers, which is what a workload asks for. A card the operator split with MIG is reported as
//! its instances, each a device of its own with its `MIG-…` UUID and its own memory, and not as the card: the card
//! runs nothing outside them. It also lists the processes on each whole card, with the memory and the share of its
//! compute each holds, so the peer can tell its owner's use of the card from its own. Thin; proven on a GPU host by
//! hand, never unit-tested.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use best_peer_gpu::{
    Availability, Compute, Device, DeviceId, Gpu, GpuError, Host, Memory, Process, Slicing, Usage, Vendor,
};
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
use nvml_wrapper::enums::device::UsedGpuMemory;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::{cuda_driver_version_major, cuda_driver_version_minor, Nvml};

pub struct NvmlGpu {
    nvml: Nvml,
}

impl NvmlGpu {
    /// Loads the library and the driver behind it. `NoDriver` when either is missing: the message names what.
    pub fn init() -> Result<Self, GpuError> {
        let nvml = Nvml::init().map_err(|e| match e {
            NvmlError::LibloadingError(inner) => GpuError::NoDriver(format!("the NVML library did not load: {inner}")),
            NvmlError::LibraryNotFound => GpuError::NoDriver("the NVML library is not on this host".into()),
            NvmlError::DriverNotLoaded => GpuError::NoDriver("the NVIDIA driver is not loaded".into()),
            other => GpuError::Library(other.to_string()),
        })?;
        Ok(Self { nvml })
    }
}

impl Gpu for NvmlGpu {
    fn snapshot(&self) -> Result<Host, GpuError> {
        let lib = |e: NvmlError| GpuError::Library(e.to_string());
        let driver = self.nvml.sys_driver_version().map_err(lib)?;
        // The CUDA version the driver offers, as "major.minor": what a workload's "needs CUDA 12.4" is matched
        // against. A driver that cannot say is an error here, not a card without CUDA: nothing is placed on a guess.
        let cuda = self
            .nvml
            .sys_cuda_driver_version()
            .map(|v| format!("{}.{}", cuda_driver_version_major(v), cuda_driver_version_minor(v)))
            .map_err(|e| GpuError::Library(format!("the driver did not say its CUDA version: {e}")))?;
        let count = self.nvml.device_count().map_err(lib)?;
        let mut devices = Vec::with_capacity(count as usize);
        for index in 0..count {
            let d = self.nvml.device_by_index(index).map_err(lib)?;
            // MIG on (NVML's current mode 1): the card's instances are what runs work, each taken whole by one job.
            // A card with MIG on and no instances made yet offers nothing until the operator makes them.
            if d.mig_mode().is_ok_and(|m| m.current == 1) {
                let slots = d.mig_device_count().unwrap_or(0);
                let card = d.name().unwrap_or_else(|_| format!("NVIDIA device {index}"));
                for slot in 0..slots {
                    // An empty slot is not an instance: it answers NotFound.
                    let Ok(m) = d.mig_device_by_index(slot) else {
                        continue;
                    };
                    let memory = m.memory_info().map_err(lib)?;
                    devices.push(Device {
                        id: DeviceId(m.uuid().map_err(lib)?),
                        vendor: Vendor::Nvidia,
                        name: m.name().unwrap_or_else(|_| format!("{card} MIG instance {slot}")),
                        memory: Memory {
                            total_bytes: memory.total,
                            free_bytes: memory.free,
                        },
                        compute: vec![Compute::Cuda(cuda.clone()), Compute::Vulkan],
                        // An instance has no readings of its own; the card's are not its.
                        temperature_c: None,
                        power_w: None,
                        utilisation_pct: None,
                        energy_j: None,
                        slicing: Slicing::Mig,
                        availability: Availability::Free,
                    });
                }
                continue;
            }
            // The UUID is stable across restarts and is what the container runtime is handed.
            let id = d.uuid().map_err(lib)?;
            let memory = d.memory_info().map_err(lib)?;
            devices.push(Device {
                id: DeviceId(id),
                vendor: Vendor::Nvidia,
                name: d.name().unwrap_or_else(|_| format!("NVIDIA device {index}")),
                memory: Memory {
                    total_bytes: memory.total,
                    free_bytes: memory.free,
                },
                compute: vec![Compute::Cuda(cuda.clone()), Compute::Vulkan],
                // Where a card does not report a reading, the field says so rather than guessing.
                temperature_c: d.temperature(TemperatureSensor::Gpu).ok().map(|t| t as f32),
                power_w: d.power_usage().ok().map(|mw| mw as f32 / 1000.0),
                utilisation_pct: d.utilization_rates().ok().map(|u| u.gpu.min(100) as u8),
                // Millijoules since the driver loaded, on Volta and later.
                energy_j: d.total_energy_consumption().ok().map(|mj| mj as f64 / 1000.0),
                slicing: Slicing::None,
                availability: Availability::Free,
            });
        }
        Ok(Host {
            driver: Some(driver),
            devices,
            observed_at: SystemTime::now(),
        })
    }

    /// The processes on each whole card. A card split with MIG is a data-centre card no owner sits at: it reports
    /// none, and its instances are never found in use. A card whose driver does not list its processes is left out,
    /// so it is read as unused and the other cards are still read.
    fn usage(&self) -> Result<Vec<Usage>, GpuError> {
        let lib = |e: NvmlError| GpuError::Library(e.to_string());
        let count = self.nvml.device_count().map_err(lib)?;
        let mut usage = Vec::with_capacity(count as usize);
        for index in 0..count {
            let d = self.nvml.device_by_index(index).map_err(lib)?;
            if d.mig_mode().is_ok_and(|m| m.current == 1) {
                continue;
            }
            let Ok(processes) = self.processes(&d) else {
                continue;
            };
            usage.push(Usage {
                device: DeviceId(d.uuid().map_err(lib)?),
                processes,
            });
        }
        Ok(usage)
    }
}

/// How far back a process's share of a card's compute is read: the driver keeps samples of the last seconds, and the
/// highest in this window is the process's share.
const UTILISATION_WINDOW: Duration = Duration::from_secs(5);

impl NvmlGpu {
    /// The processes on one whole card: those running compute and those drawing (a game, the desktop), each once,
    /// with the memory the driver says it holds and its highest share of the compute in the last seconds.
    fn processes(&self, d: &nvml_wrapper::Device) -> Result<Vec<Process>, NvmlError> {
        let mut memory: BTreeMap<u32, Option<u64>> = BTreeMap::new();
        for p in d
            .running_compute_processes()?
            .into_iter()
            .chain(d.running_graphics_processes()?)
        {
            let held = match p.used_gpu_memory {
                UsedGpuMemory::Used(bytes) => Some(bytes),
                UsedGpuMemory::Unavailable => None,
            };
            let entry = memory.entry(p.pid).or_insert(held);
            *entry = match (*entry, held) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        let since = SystemTime::now()
            .checked_sub(UTILISATION_WINDOW)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|t| t.as_micros() as u64)
            .unwrap_or(0);
        let mut share: BTreeMap<u32, u8> = BTreeMap::new();
        // No sample in the window is a card nobody computed on: NotFound, not a failure.
        if let Ok(samples) = d.process_utilization_stats(since) {
            for s in samples {
                let pct = s.sm_util.min(100) as u8;
                let entry = share.entry(s.pid).or_insert(0);
                *entry = (*entry).max(pct);
            }
        }
        Ok(memory
            .into_iter()
            .map(|(pid, memory_bytes)| Process {
                pid,
                memory_bytes,
                utilisation_pct: Some(share.get(&pid).copied().unwrap_or(0)),
            })
            .collect())
    }
}
