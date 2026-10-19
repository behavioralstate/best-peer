//! What a credential holds across the whole door. A credential's share (the most device memory its workloads may
//! hold together, set at the approval) is one number for the door, and the door has several surfaces that promise
//! memory: the machine's own hardware at the root, and every cloud of every workspace. Each registers here what it
//! has promised to a holder, and a share is measured against the sum, so a workload admitted in one workspace is
//! counted when another is asked for. So are how many deployments and jobs a credential runs, for the counts its
//! approver may set: one count for the door, every surface included.

use std::sync::{Mutex, MutexGuard};

/// What one surface has promised a holder, admitted workloads included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub memory_bytes: u64,
    pub deployments: usize,
    pub jobs: usize,
}

type Source = Box<dyn Fn(&str) -> Held + Send + Sync>;

#[derive(Default)]
pub struct Holdings {
    sources: Mutex<Vec<Source>>,
    /// Held while a surface measures a share and reserves against it, so two admissions cannot both read the room
    /// before either takes it. Taken before any surface's state lock, never after one.
    admission: Mutex<()>,
}

impl Holdings {
    /// One admission at a time across the door: the guard is held from the share's measure to the reservation.
    pub fn admitting(&self) -> MutexGuard<'_, ()> {
        self.admission.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a surface: `held` answers what it has promised to a holder, admitted workloads included.
    pub fn add(&self, held: impl Fn(&str) -> Held + Send + Sync + 'static) {
        self.sources.lock().unwrap().push(Box::new(held));
    }

    /// What `holder` holds on every surface of this door.
    pub fn of(&self, holder: &str) -> Held {
        self.sources
            .lock()
            .unwrap()
            .iter()
            .map(|s| s(holder))
            .fold(Held::default(), |sum, h| Held {
                memory_bytes: sum.memory_bytes.saturating_add(h.memory_bytes),
                deployments: sum.deployments + h.deployments,
                jobs: sum.jobs + h.jobs,
            })
    }

    /// The device memory `holder`'s workloads hold together, on every surface of this door.
    pub fn held_by(&self, holder: &str) -> u64 {
        self.of(holder).memory_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_and_the_counts_are_measured_against_every_surface_of_the_door() {
        let h = Holdings::default();
        assert_eq!(h.of("a"), Held::default());
        h.add(|holder| Held {
            memory_bytes: if holder == "a" { 4 } else { 0 },
            deployments: usize::from(holder == "a"),
            jobs: 0,
        });
        h.add(|_| Held {
            memory_bytes: 2,
            deployments: 1,
            jobs: 1,
        });
        assert_eq!(h.held_by("a"), 6);
        assert_eq!(h.held_by("b"), 2);
        assert_eq!(
            h.of("a"),
            Held {
                memory_bytes: 6,
                deployments: 2,
                jobs: 1
            }
        );
    }
}
