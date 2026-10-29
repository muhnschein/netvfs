// SPDX-License-Identifier: LGPL-2.1-or-later
//! The connection state of a location (SPEC-v2 XB-12; `state` and
//! `stateError` of `ListLocations`, XB-10): what the connections of its
//! pool are doing now, as their workers report it.
//!
//! The pools live in the consumer's bridge process (XB-2: one per
//! consumer), shared by all of its sessions, so a state is the consumer's,
//! the same for each of its sessions. Each worker has a [`Phase`]; the
//! pool's [`StateTracker`], shared with its workers, holds the outcome of
//! the last attempt to connect and raises the [`StateSignal`] when either
//! changes. Only the pool's live connections count: one being closed
//! (`Disconnect`, idle, evicted) is not established any more, and its
//! failure would say nothing about the server. `CopyAcross` connects
//! outside the pools and is not counted.

use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::location_state;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// What `ListLocations` says of a location's connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// None is established or being established: never used yet, closed
    /// after [`CONNECTION_IDLE`](super::pool::CONNECTION_IDLE), dropped, or
    /// after `Disconnect`.
    #[default]
    Disconnected,
    /// None is established, at least one is being established (connect,
    /// identity, sign-in, a question to the consumer).
    Connecting,
    /// At least one is established (connected and authenticated).
    Connected,
    /// As `Disconnected`, but the last attempt to connect failed, with this
    /// error; the next attempt that succeeds, or `Disconnect`, clears it.
    Failed(ErrorName),
}

impl ConnectionState {
    /// The value of `state`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => location_state::DISCONNECTED,
            Self::Connecting => location_state::CONNECTING,
            Self::Connected => location_state::CONNECTED,
            Self::Failed(_) => location_state::FAILED,
        }
    }

    /// The value of `stateError`: the XC-21 name of a failed state.
    #[must_use]
    pub const fn error(self) -> Option<ErrorName> {
        match self {
            Self::Failed(name) => Some(name),
            Self::Disconnected | Self::Connecting | Self::Connected => None,
        }
    }
}

/// Where a worker's connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    /// No connection: none yet, or it was dropped or freed.
    #[default]
    Closed,
    /// Being created and established.
    Connecting,
    /// Established: connected and authenticated.
    Established,
}

struct Signal {
    raised: AtomicBool,
    wake: Box<dyn Fn() + Send + Sync>,
}

/// Tells the core that a connection state may have changed: the first
/// [`raise`](StateSignal::raise) calls the wake function, later ones only
/// once the core has looked ([`take`](StateSignal::take)), so a burst of
/// changes costs one wake-up. Any thread; cheap to clone.
#[derive(Clone)]
pub struct StateSignal(Arc<Signal>);

impl fmt::Debug for StateSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateSignal").field("raised", &self.0.raised.load(Ordering::Acquire)).finish()
    }
}

impl Default for StateSignal {
    /// A signal nobody listens to.
    fn default() -> Self {
        Self::new(|| {})
    }
}

impl StateSignal {
    /// Calls `wake` on a change; it must not block (it runs on worker
    /// threads and on the core's).
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(Signal { raised: AtomicBool::new(false), wake: Box::new(wake) }))
    }

    /// A state may have changed.
    pub fn raise(&self) {
        if !self.0.raised.swap(true, Ordering::AcqRel) {
            (self.0.wake)();
        }
    }

    /// The core looks at the states now: whether one may have changed
    /// since it last did. The next change wakes it again.
    #[must_use]
    pub fn take(&self) -> bool {
        self.0.raised.swap(false, Ordering::AcqRel)
    }
}

/// The outcome of a pool's last attempt to connect, shared by the pool and
/// its workers, and the signal of its changes and theirs.
#[derive(Debug, Default)]
pub struct StateTracker {
    failure: Mutex<Option<ErrorName>>,
    signal: StateSignal,
}

impl StateTracker {
    /// No attempt yet; changes raise `signal`.
    #[must_use]
    pub fn new(signal: StateSignal) -> Arc<Self> {
        Arc::new(Self { failure: Mutex::new(None), signal })
    }

    /// The error of the last attempt if it failed.
    #[must_use]
    pub fn failure(&self) -> Option<ErrorName> {
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_failure(&self, failure: Option<ErrorName>) {
        let before =
            std::mem::replace(&mut *self.failure.lock().unwrap_or_else(PoisonError::into_inner), failure);
        if before != failure {
            self.changed();
        }
    }

    /// An attempt failed with `name`.
    pub fn failed(&self, name: ErrorName) {
        self.set_failure(Some(name));
    }

    /// An attempt succeeded, or the user disconnected: no failure to show.
    pub fn clear(&self) {
        self.set_failure(None);
    }

    /// A connection of the pool changed its phase, or went.
    pub fn changed(&self) {
        self.signal.raise();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn counting() -> (Arc<AtomicUsize>, StateSignal) {
        let woken = Arc::new(AtomicUsize::new(0));
        let theirs = Arc::clone(&woken);
        let signal = StateSignal::new(move || {
            theirs.fetch_add(1, Ordering::AcqRel);
        });
        (woken, signal)
    }

    #[test]
    fn states_on_the_wire() {
        assert_eq!(ConnectionState::default(), ConnectionState::Disconnected);
        let all = [
            (ConnectionState::Disconnected, "disconnected", None),
            (ConnectionState::Connecting, "connecting", None),
            (ConnectionState::Connected, "connected", None),
            (ConnectionState::Failed(ErrorName::Timeout), "failed", Some(ErrorName::Timeout)),
        ];
        for (state, name, error) in all {
            assert_eq!((state.as_str(), state.error()), (name, error), "{state:?}");
        }
        assert_eq!(location_state::KEY, "state");
        assert_eq!(location_state::ERROR_KEY, "stateError");
        assert_eq!(Phase::default(), Phase::Closed);
    }

    #[test]
    fn a_burst_of_changes_wakes_once_until_taken() {
        let (woken, signal) = counting();
        assert!(!signal.take());
        signal.raise();
        // A clone is the same signal.
        let clone = signal.clone();
        clone.raise();
        assert_eq!(woken.load(Ordering::Acquire), 1);
        assert!(format!("{signal:?}").contains("raised: true"));
        assert!(signal.take());
        assert!(!signal.take());
        signal.raise();
        assert_eq!(woken.load(Ordering::Acquire), 2);
        // Nobody listens.
        StateSignal::default().raise();
    }

    #[test]
    fn the_tracker_raises_on_a_change_only() {
        let (woken, signal) = counting();
        let tracker = StateTracker::new(signal.clone());
        assert_eq!(tracker.failure(), None);
        tracker.clear();
        assert_eq!(woken.load(Ordering::Acquire), 0);
        tracker.failed(ErrorName::AuthFailed);
        assert_eq!(tracker.failure(), Some(ErrorName::AuthFailed));
        assert!(signal.take());
        tracker.failed(ErrorName::AuthFailed);
        assert!(!signal.take(), "the same failure again is no change");
        tracker.failed(ErrorName::Timeout);
        assert_eq!(tracker.failure(), Some(ErrorName::Timeout));
        assert!(signal.take());
        tracker.clear();
        assert_eq!(tracker.failure(), None);
        assert!(signal.take());
        tracker.changed();
        assert!(signal.take());
        assert_eq!(woken.load(Ordering::Acquire), 4);
    }
}
