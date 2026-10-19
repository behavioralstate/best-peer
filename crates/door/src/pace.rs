//! How many commands one credential with a share may send a minute (SPEC.md security, Input Limits: rate limits per
//! authenticated client for command submission). One pace may be shared by a root door and its tenants, so a
//! credential that opens several of them is counted once.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What one credential may send a minute, unless the operator says otherwise.
pub const COMMANDS_PER_MINUTE: u32 = 60;

const MINUTE: Duration = Duration::from_secs(60);

pub struct Pace {
    per_minute: u32,
    /// When each credential's commands of the last minute were taken, oldest first.
    taken: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Default for Pace {
    fn default() -> Self {
        Self::per_minute(COMMANDS_PER_MINUTE)
    }
}

impl Pace {
    pub fn per_minute(per_minute: u32) -> Self {
        Self {
            per_minute,
            taken: Mutex::new(HashMap::new()),
        }
    }

    pub fn limit(&self) -> u32 {
        self.per_minute
    }

    /// Takes one command from `sender` at `now`, answering when it was taken so a command refused after can give it
    /// back; or how many whole seconds until the oldest of the last minute's leaves it. The minute slides: at no
    /// moment has a credential sent more than the figure within the sixty seconds before.
    pub fn take(&self, sender: &str, now: Instant) -> Result<Instant, u64> {
        let mut taken = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        taken.retain(|_, at| {
            while at.front().is_some_and(|t| now.saturating_duration_since(*t) >= MINUTE) {
                at.pop_front();
            }
            !at.is_empty()
        });
        let at = taken.entry(sender.to_string()).or_default();
        if at.len() >= self.per_minute as usize {
            let oldest = at.front().copied().unwrap_or(now);
            let left = MINUTE.saturating_sub(now.saturating_duration_since(oldest));
            return Err(left.as_secs() + u64::from(left.subsec_nanos() > 0));
        }
        at.push_back(now);
        Ok(now)
    }

    /// Gives back what `take` answered, for a command refused after it was counted.
    pub fn give_back(&self, sender: &str, when: Instant) {
        let mut taken = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = taken.get_mut(sender) {
            if let Some(i) = at.iter().rposition(|t| *t == when) {
                at.remove(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_takes_its_minute_and_another_has_its_own() {
        let pace = Pace::per_minute(2);
        let start = Instant::now();
        let s = |secs: u64| start + Duration::from_secs(secs);
        assert!(pace.take("a", s(0)).is_ok());
        assert!(pace.take("a", s(10)).is_ok());
        assert_eq!(pace.take("a", s(20)), Err(40));
        assert_eq!(pace.take("a", start + Duration::from_millis(20_500)), Err(40));
        assert!(pace.take("b", s(20)).is_ok());
        assert!(pace.take("a", s(60)).is_ok(), "the first left the minute");
        assert_eq!(pace.take("a", s(65)), Err(5), "the second is still in it");
    }

    #[test]
    fn the_minute_slides_so_no_sixty_seconds_hold_more_than_the_figure() {
        let pace = Pace::per_minute(2);
        let start = Instant::now();
        let s = |secs: u64| start + Duration::from_secs(secs);
        assert!(pace.take("a", s(58)).is_ok());
        assert!(pace.take("a", s(59)).is_ok());
        assert_eq!(pace.take("a", s(61)), Err(57), "a fixed window would take it");
        assert!(pace.take("a", s(118)).is_ok());
    }

    #[test]
    fn a_command_given_back_costs_nothing() {
        let pace = Pace::per_minute(1);
        let start = Instant::now();
        let when = pace.take("a", start).unwrap();
        pace.give_back("a", when);
        assert!(pace.take("a", start + Duration::from_secs(1)).is_ok());
    }
}
