//! What one credential with a share may do at once across a door, held once and shared by the root door and its
//! tenants: how many commands it sends a minute. A credential without a share, the owner's, is held to none of it.

use crate::pace::Pace;

#[derive(Default)]
pub struct Limits {
    pub pace: Pace,
}

impl Limits {
    pub fn new(pace: Pace) -> Self {
        Self { pace }
    }
}
