//! How many commands one credential may send a minute (SPEC.md security, Input Limits: rate limits per
//! authenticated client for command submission). One pace may be shared by a root door and its tenants, so a
//! credential that opens several of them is counted once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What one credential may send a minute, unless the operator says otherwise.
pub const COMMANDS_PER_MINUTE: u32 = 60;

const MINUTE: Duration = Duration::from_secs(60);

pub struct Pace {
    per_minute: u32,
    /// Each credential's minute: when it began, and how many commands were taken in it.
    minutes: Mutex<HashMap<String, (Instant, u32)>>,
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
            minutes: Mutex::new(HashMap::new()),
        }
    }

    pub fn limit(&self) -> u32 {
        self.per_minute
    }

    /// Takes one command from `sender` at `now`, or answers how many whole seconds remain of its full minute.
    pub fn take(&self, sender: &str, now: Instant) -> Result<(), u64> {
        let mut minutes = self.minutes.lock().unwrap_or_else(|e| e.into_inner());
        minutes.retain(|_, (since, _)| now.saturating_duration_since(*since) < MINUTE);
        let (since, count) = minutes.entry(sender.to_string()).or_insert((now, 0));
        if *count >= self.per_minute {
            let left = MINUTE.saturating_sub(now.saturating_duration_since(*since));
            return Err(left.as_secs() + u64::from(left.subsec_nanos() > 0));
        }
        *count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_takes_its_minute_and_another_has_its_own() {
        let pace = Pace::per_minute(2);
        let start = Instant::now();
        assert_eq!(pace.take("a", start), Ok(()));
        assert_eq!(pace.take("a", start + Duration::from_secs(10)), Ok(()));
        assert_eq!(pace.take("a", start + Duration::from_secs(20)), Err(40));
        assert_eq!(pace.take("a", start + Duration::from_millis(20_500)), Err(40));
        assert_eq!(pace.take("b", start + Duration::from_secs(20)), Ok(()));
        assert_eq!(pace.take("a", start + Duration::from_secs(60)), Ok(()));
    }
}
