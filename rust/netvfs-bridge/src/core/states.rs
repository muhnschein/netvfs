// SPDX-License-Identifier: LGPL-2.1-or-later
//! When the sessions hear that a location's connection state changed
//! (SPEC-v2 XB-10, XB-12): `LocationsChanged`, at most every 250 ms, and
//! only when a state differs from what the sessions were last told.
//!
//! `ListLocations` shows the states as they are; this keeps the ones the
//! last `LocationsChanged` stood for (or the location list, when it was
//! set). A change of a pool's state wakes the core
//! ([`StateSignal`](crate::locations::state::StateSignal)), which looks
//! [`STATES_DELAY`] later: a burst of changes (an attempt that connects or
//! fails at once, several connections of a pool) costs one look, and a
//! state that went and came back costs no signal, unless a `ListLocations`
//! in between showed it. Work on an established connection changes no
//! state, and `ListLocations` changes none, so neither causes a signal.

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
    /// The states the last `LocationsChanged` (or location list) stood for.
    announced: States,
    /// A `ListLocations` answer showed states that were not announced.
    listed: bool,
    due: Option<Instant>,
}

impl StateReport {
    /// A connection state may have changed at `now`: look
    /// [`STATES_DELAY`] later, unless a look is due already.
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

    /// `ListLocations` answered with `states` at `now`: if they were not
    /// announced, the next look tells every session, whatever it finds.
    pub fn listed(&mut self, states: &States, now: Instant) {
        if *states != self.announced {
            self.listed = true;
            self.changed(now);
        }
    }

    /// `LocationsChanged` was sent, or the location list set, with
    /// `states`.
    pub fn announced(&mut self, states: States) {
        self.announced = states;
        self.listed = false;
    }

    /// The look is due, and finds `states`: whether `LocationsChanged` must
    /// tell them. They count as announced from now on.
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
        // More changes in the meantime: the same look.
        report.changed(after(start, 100));
        assert_eq!(report.due(), start.checked_add(STATES_DELAY));
        assert!(report.check(states(&[("account:1", ConnectionState::Connected)])));
        assert_eq!(report.due(), None);
        // Nothing changed since: no signal.
        report.changed(after(start, 1000));
        assert_eq!(report.due(), after(start, 1000).checked_add(STATES_DELAY));
        assert!(!report.check(states(&[("account:1", ConnectionState::Connected)])));
        // Another state, or only another error.
        let failed = |name| states(&[("account:1", ConnectionState::Failed(name))]);
        assert!(report.check(failed(ErrorName::Timeout)));
        assert!(!report.check(failed(ErrorName::Timeout)));
        assert!(report.check(failed(ErrorName::AuthFailed)));
        // A location more or less.
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
        // The list as the bridge starts: nothing to tell.
        report.announced(disconnected.clone());
        report.changed(start);
        assert!(!report.check(disconnected));
        // A LocationsChanged of its own told the sessions already.
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
        // Listed as announced: nothing to do.
        report.listed(&disconnected, start);
        assert_eq!(report.due(), None);
        // A session saw "connecting", then the attempt was canceled: the
        // states are as announced again, but that session must hear of it.
        report.listed(&connecting, start);
        assert_eq!(report.due(), start.checked_add(STATES_DELAY));
        assert!(report.check(disconnected.clone()));
        assert!(!report.check(disconnected.clone()));
        // A LocationsChanged told every session of "connecting": going back
        // is a change for all of them.
        report.listed(&connecting, start);
        report.announced(connecting);
        assert!(report.check(disconnected));
    }
}
