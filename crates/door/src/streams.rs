//! How many event streams one credential may hold open at once. One count may be shared by a root door and its
//! tenants, so a credential that opens several of them is counted once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::json;

use crate::error::BestError;

/// How many event streams one credential may hold open at once.
pub const STREAMS_PER_CREDENTIAL: usize = 4;

#[derive(Default)]
pub struct Streams {
    open: Arc<Mutex<HashMap<String, usize>>>,
}

impl Streams {
    /// One more stream for `holder`, given back when the slot is dropped, or the refusal that it holds enough.
    pub fn take(&self, holder: &str) -> Result<Slot, BestError> {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(holder.to_string()).or_insert(0);
        if *count >= STREAMS_PER_CREDENTIAL {
            return Err(BestError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_STREAMS",
                format!(
                    "this credential holds {STREAMS_PER_CREDENTIAL} event streams open on this door, the most it may: close one, or follow several correlations on one stream (GET /events/stream without correlationId) instead of opening more"
                ),
            )
            .with_details(json!({ "streams": STREAMS_PER_CREDENTIAL })));
        }
        *count += 1;
        Ok(Slot {
            open: self.open.clone(),
            holder: holder.to_string(),
        })
    }
}

/// One of a credential's open event streams, counted while it lives.
pub struct Slot {
    open: Arc<Mutex<HashMap<String, usize>>>,
    holder: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.holder) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.holder);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_holds_so_many_streams_and_a_closed_one_gives_its_place_back() {
        let streams = Streams::default();
        let mut held: Vec<Slot> = (0..STREAMS_PER_CREDENTIAL)
            .map(|_| streams.take("a").unwrap())
            .collect();
        let refused = streams.take("a").err().unwrap();
        assert_eq!(refused.code, "TOO_MANY_STREAMS");
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(streams.take("b").is_ok(), "another credential's streams are its own");
        held.pop();
        assert!(streams.take("a").is_ok());
    }
}
