// SPDX-License-Identifier: Apache-2.0

/// Per-interface connection state machine.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Scanning,
    Connecting,
    Authenticating,
    Associating,
    FourWayHandshake,
    Connected,
    Failed,
    SaeCommitSent,
    SaeCompleted,
}

pub struct ConnectionSm {
    pub state: ConnectionState,
    pub if_index: u32,
    pub if_name: String,
}

impl ConnectionSm {
    pub fn new(if_index: u32, if_name: String) -> Self {
        Self {
            state: ConnectionState::Idle,
            if_index,
            if_name,
        }
    }

    pub fn transition(&mut self, new_state: ConnectionState) {
        log::info!(
            "{}: state transition {:?} -> {:?}",
            self.if_name,
            self.state,
            new_state
        );
        self.state = new_state;
    }
}
