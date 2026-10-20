//! The [`Gpu`] adapter for NVIDIA devices, through NVML (the library every NVIDIA driver installs: `libnvidia-ml.so`
//! on Linux, `nvml.dll` on Windows). Loaded once at start; a host without it is told so and the peer refuses to
//! start, since a GPU host that cannot see its cards is misconfigured, not accelerator-less (`BEST_PEER_GPU=none`
//! says the latter). Every snapshot reads the cards live: memory, temperature, power, utilisation, and the CUDA
//! version the driver offers, which is what a workload asks for. Thin; proven on a GPU host by hand, never
//! unit-tested.

use std::time::SystemTime;

use best_peer_gpu::{Compute, Device, DeviceId, Gpu, GpuError, Host, Memory, Vendor};
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;
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
                // Neither MPS nor MIG is set up by this adapter: a share of the card is held to by nothing yet.
                slicing: best_peer_gpu::Slicing::None,
            });
        }
        Ok(Host {
            driver: Some(driver),
            devices,
            observed_at: SystemTime::now(),
        })
    }
}
