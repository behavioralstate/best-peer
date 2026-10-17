//! What a credential holds across the whole door. A credential's share (the most device memory its workloads may
//! hold together, set at the approval) is one number for the door, and the door has several surfaces that promise
//! memory: the machine's own hardware at the root, and every cloud of every workspace. Each registers here what it
//! has promised to a holder, and a share is measured against the sum, so a workload admitted in one workspace is
//! counted when another is asked for. So is how many deployments a credential with a share runs: one rule for the
//! door, every surface counted.

use std::sync::{Mutex, MutexGuard};

/// What a credential with a share may run at once, unless the operator says otherwise.
pub const DEPLOYMENTS_PER_HOLDER: usize = 1;

/// What one surface has promised a holder: device memory, admitted workloads included, and deployments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub memory_bytes: u64,
    pub deployments: usize,
}

type Source = Box<dyn Fn(&str) -> Held + Send + Sync>;

pub struct Holdings {
    sources: Mutex<Vec<Source>>,
    /// Held while a surface measures a share and reserves against it, so two admissions cannot both read the room
    /// before either takes it. Taken before any surface's state lock, never after one.
    admission: Mutex<()>,
    /// How many deployments a credential with a share may run at once, across the door.
    deployments_per_holder: usize,
}

impl Default for Holdings {
    fn default() -> Self {
        Self {
            sources: Mutex::default(),
            admission: Mutex::default(),
            deployments_per_holder: DEPLOYMENTS_PER_HOLDER,
        }
    }
}

impl Holdings {
    /// The same holdings, letting a credential with a share run `n` deployments at once.
    pub fn allowing_deployments(mut self, n: usize) -> Self {
        self.deployments_per_holder = n;
        self
    }

    /// How many deployments a credential with a share may run at once.
    pub fn deployments_per_holder(&self) -> usize {
        self.deployments_per_holder
    }

    /// One admission at a time across the door: the guard is held from the share's measure to the reservation.
    pub fn admitting(&self) -> MutexGuard<'_, ()> {
        self.admission.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a surface: `held` answers what it has promised to a holder, admitted workloads included.
    pub fn add(&self, held: impl Fn(&str) -> Held + Send + Sync + 'static) {
        self.sources.lock().unwrap().push(Box::new(held));
    }

    /// The device memory `holder`'s workloads hold together, on every surface of this door.
    pub fn held_by(&self, holder: &str) -> u64 {
        self.sources
            .lock()
            .unwrap()
            .iter()
            .map(|s| s(holder).memory_bytes)
            .fold(0u64, u64::saturating_add)
    }

    /// The deployments `holder` runs, admitted ones included, on every surface of this door.
    pub fn deployments_of(&self, holder: &str) -> usize {
        self.sources.lock().unwrap().iter().map(|s| s(holder).deployments).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_is_measured_against_every_surface_of_the_door() {
        let h = Holdings::default();
        assert_eq!(h.held_by("a"), 0);
        assert_eq!(h.deployments_of("a"), 0);
        h.add(|holder| Held {
            memory_bytes: if holder == "a" { 4 } else { 0 },
            deployments: usize::from(holder == "a"),
        });
        h.add(|_| Held {
            memory_bytes: 2,
            deployments: 1,
        });
        assert_eq!(h.held_by("a"), 6);
        assert_eq!(h.held_by("b"), 2);
        assert_eq!(h.deployments_of("a"), 2);
        assert_eq!(h.deployments_of("b"), 1);
        assert_eq!(h.deployments_per_holder(), DEPLOYMENTS_PER_HOLDER);
        assert_eq!(Holdings::default().allowing_deployments(3).deployments_per_holder(), 3);
    }
}
