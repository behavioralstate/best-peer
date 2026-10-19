//! How many event streams one credential with a share may hold open at once. One count may be shared by a root door
//! and its tenants, so a credential that opens several of them is counted once. Past the figure, the credential's
//! oldest stream gives way to the new one rather than the new one being refused: a client whose connection died
//! without a close still holds its slot until a write to it fails, and its reconnect must not meet its own ghost.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

/// How many event streams one credential may hold open at once, unless the operator says otherwise.
pub const STREAMS_PER_CREDENTIAL: usize = 4;

type Open = Arc<Mutex<HashMap<String, VecDeque<(u64, oneshot::Sender<()>)>>>>;

pub struct Streams {
    per_credential: usize,
    open: Open,
    next: Mutex<u64>,
}

impl Default for Streams {
    fn default() -> Self {
        Self::per_credential(STREAMS_PER_CREDENTIAL)
    }
}

impl Streams {
    pub fn per_credential(per_credential: usize) -> Self {
        Self {
            per_credential,
            open: Arc::default(),
            next: Mutex::new(0),
        }
    }

    pub fn limit(&self) -> usize {
        self.per_credential
    }

    /// One more stream for `holder`: its slot, given back when dropped, and what resolves when the stream must end
    /// because a newer one of the same holder took its place.
    pub fn take(&self, holder: &str) -> (Slot, oneshot::Receiver<()>) {
        let id = {
            let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
            *next += 1;
            *next
        };
        let (tx, rx) = oneshot::channel();
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let held = open.entry(holder.to_string()).or_default();
        while held.len() >= self.per_credential {
            if let Some((_, oldest)) = held.pop_front() {
                let _ = oldest.send(());
            }
        }
        held.push_back((id, tx));
        let slot = Slot {
            open: self.open.clone(),
            holder: holder.to_string(),
            id,
        };
        (slot, rx)
    }

    /// How many streams `holder` holds open.
    pub fn held(&self, holder: &str) -> usize {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.get(holder).map_or(0, VecDeque::len)
    }
}

/// One of a credential's open event streams, counted while it lives.
pub struct Slot {
    open: Open,
    holder: String,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = open.get_mut(&self.holder) {
            held.retain(|(id, _)| *id != self.id);
            if held.is_empty() {
                open.remove(&self.holder);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_the_figure_the_oldest_stream_gives_way_and_a_closed_one_gives_its_place_back() {
        let streams = Streams::per_credential(2);
        let (first, mut first_ends) = streams.take("a");
        let (_second, mut second_ends) = streams.take("a");
        assert_eq!(streams.held("a"), 2);
        let (_third, _) = streams.take("a");
        assert_eq!(streams.held("a"), 2, "never more than the figure");
        assert!(first_ends.try_recv().is_ok(), "the oldest was told to end");
        assert!(second_ends.try_recv().is_err(), "the others stay");
        drop(first);
        assert_eq!(streams.held("a"), 2, "the one that gave way was no longer counted");
        let (_b, _) = streams.take("b");
        assert_eq!(streams.held("b"), 1, "another credential's streams are its own");
    }
}
