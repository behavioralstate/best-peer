//! What one credential with a share may do at once across a door, held once and shared by the root door and its
//! tenants: how many commands it sends a minute, and how many event streams it holds open. A credential without a
//! share, the owner's, is held to none of it.

use crate::pace::Pace;
use crate::streams::Streams;

#[derive(Default)]
pub struct Limits {
    pub pace: Pace,
    pub streams: Streams,
}

impl Limits {
    pub fn new(pace: Pace, streams: Streams) -> Self {
        Self { pace, streams }
    }
}
