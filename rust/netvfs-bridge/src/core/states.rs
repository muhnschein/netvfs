// SPDX-License-Identifier: LGPL-2.1-or-later
//! `LocationsChanged` for connection-state changes: at most every 250 ms, only when a state differs from what sessions were last told.
//! A pool state change wakes the core ([`StateSignal`](crate::locations::state::StateSignal)), which looks [`STATES_DELAY`] later:
//! bursts cost one look; a state that went and came back costs no signal unless a `ListLocations` showed it in between.

use crate::locations::state::ConnectionState;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;

/// From a change of a connection state to the look at the states.
pub const STATES_DELAY: Duration = Duration::from_millis(250);

/// The connection states of the visible locations, by id.
pub type States = BTreeMap<String, ConnectionState>;

/// What the sessions were told, and when to look again.
#[derive(Debug, Default)]
pub struct StateReport {
    announced: States,
    listed: bool,
    due: Option<Instant>,
}

impl StateReport {
    /// A connection state may have changed at `now`.
    pub fn changed(&mut self, now: Instant) {
        if self.due.is_none() {
            self.due = now.checked_add(STATES_DELAY);
        }
    }

    /// When the next look is due.
    #[must_use]
    pub const fn due(&self) -> Option<Instant> {
        self.due
    }

    /// `ListLocations` answered with `states` at `now`.
    pub fn listed(&mut self, states: &States, now: Instant) {
        if *states != self.announced {
            self.listed = true;
            self.changed(now);
        }
    }

    /// `LocationsChanged` was sent, or the location list set, with `states`.
    pub fn announced(&mut self, states: States) {
        self.announced = states;
        self.listed = false;
    }

    /// The look is due, and finds `states`.
    pub fn check(&mut self, states: States) -> bool {
        self.due = None;
        let tell = self.listed || states != self.announced;
        self.announced(states);
        tell
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    fn states(of: &[(&str, ConnectionState)]) -> States {
        of.iter().map(|(id, state)| ((*id).to_owned(), *state)).collect()
    }

    fn after(start: Instant, ms: u64) -> Instant {
        start.checked_add(Duration::from_millis(ms)).unwrap()
    }

    #[test]
    fn a_change_is_looked_at_once_after_the_delay() {
        let start = Instant::now();
        let mut report = StateReport::default();
        assert_eq!(report.due(), None);
        report.changed(start);
        assert_eq!(report.due(), start.checked_add(STATES_DELAY));
        report.changed(after(start, 100));
        assert_eq!(report.due(), start.checked_add(STATES_DELAY));
        assert!(report.check(states(&[("account:1", ConnectionState::Connected)])));
        assert_eq!(report.due(), None);
        report.changed(after(start, 1000));
        assert_eq!(report.due(), after(start, 1000).checked_add(STATES_DELAY));
        assert!(!report.check(states(&[("account:1", ConnectionState::Connected)])));
        let failed = |name| states(&[("account:1", ConnectionState::Failed(name))]);
        assert!(report.check(failed(ErrorName::Timeout)));
        assert!(!report.check(failed(ErrorName::Timeout)));
        assert!(report.check(failed(ErrorName::AuthFailed)));
        let two = states(&[
            ("account:1", ConnectionState::Disconnected),
            ("adhoc:x-1", ConnectionState::Connected),
        ]);
        assert!(report.check(two.clone()));
        assert!(!report.check(two));
        assert!(report.check(States::new()));
    }

    #[test]
    fn the_location_list_and_other_signals_are_announcements() {
        let start = Instant::now();
        let mut report = StateReport::default();
        let disconnected = states(&[("account:1", ConnectionState::Disconnected)]);
        report.announced(disconnected.clone());
        report.changed(start);
        assert!(!report.check(disconnected));
        let connected = states(&[("account:1", ConnectionState::Connected)]);
        report.changed(start);
        report.announced(connected.clone());
        assert!(!report.check(connected));
    }

    #[test]
    fn a_state_seen_by_list_locations_is_told_when_it_goes_back() {
        let start = Instant::now();
        let mut report = StateReport::default();
        let disconnected = states(&[("account:1", ConnectionState::Disconnected)]);
        let connecting = states(&[("account:1", ConnectionState::Connecting)]);
        report.announced(disconnected.clone());
        report.listed(&disconnected, start);
        assert_eq!(report.due(), None);
        // A session saw "connecting", then the attempt was canceled: the
        // states are as announced again, but that session must hear of it.
        report.listed(&connecting, start);
        assert_eq!(report.due(), start.checked_add(STATES_DELAY));
        assert!(report.check(disconnected.clone()));
        assert!(!report.check(disconnected.clone()));
        report.listed(&connecting, start);
        report.announced(connecting);
        assert!(report.check(disconnected));
    }
}
