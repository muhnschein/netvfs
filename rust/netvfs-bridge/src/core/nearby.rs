// SPDX-License-Identifier: LGPL-2.1-or-later
//! Nearby-server discovery runs only while a session asked (`Discover(true)`); results go to askers as `NearbyChanged`, at most every 250 ms.
//! In the bridge [`FfiNearby`] runs the C++ `Discovery` on the Qt thread; tests use a fake.

use super::CoreLink;
use crate::ffi::{Discovery, Ffi};
use crate::server::SessionId;
use netvfs_bridge_proto::WireNearby;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

/// From a change to its `NearbyChanged`.
pub const NEARBY_DELAY: Duration = Duration::from_millis(250);

/// Starts and stops the discovery of nearby servers.
pub trait NearbySource {
    /// Starts (`true`) or stops it.
    fn set_running(&mut self, on: bool);
}

/// Who discovers, what was found and when to tell them.
pub struct Nearby {
    source: Box<dyn NearbySource>,
    running: bool,
    discovering: BTreeSet<SessionId>,
    services: Vec<WireNearby>,
    due: Option<Instant>,
}

impl std::fmt::Debug for Nearby {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nearby")
            .field("running", &self.running)
            .field("discovering", &self.discovering)
            .field("services", &self.services.len())
            .field("due", &self.due)
            .finish_non_exhaustive()
    }
}

impl Nearby {
    /// Nothing discovering yet.
    #[must_use]
    pub fn new(source: Box<dyn NearbySource>) -> Self {
        Self { source, running: false, discovering: BTreeSet::new(), services: Vec::new(), due: None }
    }

    /// `Discover(on)` of `session` at `now`.
    pub fn set_discovering(&mut self, session: SessionId, on: bool, now: Instant) {
        if on {
            if !self.discovering.insert(session) {
                return;
            }
            if !self.running {
                self.running = true;
                self.source.set_running(true);
            }
            self.schedule(now);
        } else if self.discovering.remove(&session) && self.discovering.is_empty() && self.running {
            self.running = false;
            self.source.set_running(false);
        }
    }

    /// Whether the discovery runs.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Whether `session` asked for the discovery.
    #[must_use]
    pub fn is_discovering(&self, session: SessionId) -> bool {
        self.discovering.contains(&session)
    }

    /// The discovery's current list (after a found, updated or lost service), at `now`.
    pub fn changed(&mut self, services: Vec<WireNearby>, now: Instant) {
        self.services = services;
        self.schedule(now);
    }

    fn schedule(&mut self, now: Instant) {
        if self.due.is_none() {
            self.due = now.checked_add(NEARBY_DELAY);
        }
    }

    /// When the next report is due.
    #[must_use]
    pub const fn due(&self) -> Option<Instant> {
        self.due
    }

    /// The report is due.
    pub fn report(&mut self) -> (Vec<SessionId>, Vec<WireNearby>) {
        self.due = None;
        (self.discovering.iter().copied().collect(), self.services.clone())
    }
}

// On the Qt thread: `!Send`.
thread_local! {
    static DISCOVERIES: RefCell<HashMap<u64, Discovery>> = RefCell::new(HashMap::new());
}

/// The C++ discovery on the Qt thread, made on first start and freed when this goes.
#[derive(Debug)]
pub struct FfiNearby {
    ffi: Ffi,
    link: CoreLink,
    id: u64,
}

impl FfiNearby {
    /// Discovery through `ffi`, results to `link`.
    #[must_use]
    pub fn new(ffi: Ffi, link: CoreLink) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self { ffi, link, id: NEXT.fetch_add(1, Ordering::Relaxed) }
    }
}

impl NearbySource for FfiNearby {
    fn set_running(&mut self, on: bool) {
        let (ffi, link, id) = (self.ffi, self.link.clone(), self.id);
        if !self.ffi.post(move || set_running_on_qt_thread(ffi, id, link, on)) {
            crate::log::warning(format_args!("Cannot reach the discovery of nearby servers"));
        }
    }
}

impl Drop for FfiNearby {
    fn drop(&mut self) {
        let id = self.id;
        // Not queued: the application is gone, and its discoveries with it.
        let _queued = self.ffi.post(move || {
            DISCOVERIES.with_borrow_mut(|d| d.remove(&id));
        });
    }
}

fn set_running_on_qt_thread(ffi: Ffi, id: u64, link: CoreLink, on: bool) {
    DISCOVERIES.with_borrow_mut(|discoveries| {
        let discovery = match discoveries.entry(id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                if !on {
                    return;
                }
                let found = move |items| {
                    // False once the core has stopped: nobody to tell.
                    let _told = link.nearby(items);
                };
                match Discovery::new(ffi, found) {
                    Ok(discovery) => e.insert(discovery),
                    Err(status) => {
                        crate::log::warning(format_args!("Cannot discover nearby servers: {status}"));
                        return;
                    }
                }
            }
        };
        discovery.set_running(on);
    });
}

/// The discoveries alive on this thread (tests, on the Qt thread).
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn live_discoveries() -> usize {
    DISCOVERIES.with_borrow(HashMap::len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<bool>>>);

    impl NearbySource for Recorder {
        fn set_running(&mut self, on: bool) {
            self.0.lock().unwrap().push(on);
        }
    }

    fn nearby() -> (Nearby, Recorder) {
        let recorder = Recorder::default();
        (Nearby::new(Box::new(recorder.clone())), recorder)
    }

    fn server(name: &str) -> WireNearby {
        WireNearby { name: name.into(), provider: "smb".into(), host: "h".into(), port: 445 }
    }

    #[test]
    fn runs_while_a_session_discovers() {
        let (mut n, rec) = nearby();
        let now = Instant::now();
        let (a, b) = (SessionId(1), SessionId(2));
        assert!(!n.is_running() && n.due().is_none());
        n.set_discovering(a, false, now);
        assert!(rec.0.lock().unwrap().is_empty());
        n.set_discovering(a, true, now);
        assert!(n.is_running() && n.is_discovering(a) && !n.is_discovering(b));
        assert_eq!(n.due(), now.checked_add(NEARBY_DELAY));
        n.set_discovering(a, true, now);
        n.set_discovering(b, true, now);
        assert_eq!(*rec.0.lock().unwrap(), [true]);
        n.set_discovering(a, false, now);
        assert!(n.is_running());
        n.set_discovering(b, false, now);
        assert!(!n.is_running());
        n.set_discovering(b, false, now);
        assert_eq!(*rec.0.lock().unwrap(), [true, false]);
        n.set_discovering(b, true, now);
        assert_eq!(*rec.0.lock().unwrap(), [true, false, true]);
        assert!(format!("{n:?}").contains("running: true"));
    }

    #[test]
    fn reports_go_to_who_discovers_at_most_every_delay() {
        let (mut n, _rec) = nearby();
        let t0 = Instant::now();
        n.set_discovering(SessionId(3), true, t0);
        let (to, list) = n.report();
        assert_eq!((to, list.len()), (vec![SessionId(3)], 0));
        assert_eq!(n.due(), None);
        let t1 = t0.checked_add(Duration::from_millis(10)).unwrap();
        n.changed(vec![server("a")], t1);
        let t2 = t0.checked_add(Duration::from_millis(100)).unwrap();
        n.changed(vec![server("a"), server("b")], t2);
        // The first change sets the time; later ones join that report.
        assert_eq!(n.due(), t1.checked_add(NEARBY_DELAY));
        n.set_discovering(SessionId(4), true, t2);
        assert_eq!(n.due(), t1.checked_add(NEARBY_DELAY));
        let (to, list) = n.report();
        assert_eq!(to, [SessionId(3), SessionId(4)]);
        assert_eq!(list, [server("a"), server("b")]);
    }
}
