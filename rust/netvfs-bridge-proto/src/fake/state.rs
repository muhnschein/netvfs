// SPDX-License-Identifier: LGPL-2.1-or-later

use super::tree::Tree;
use crate::access::{self, After, Level, Own};
use crate::errors::ErrorName;
use crate::wire::{WireCapabilities, WireDrive, WireLocation, WireNearby, drive_info, location_state};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::time::Instant;
use zbus::zvariant::{OwnedValue, Value};

/// What the user decided for this app, for every account location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Not decided yet.
    Unknown,
    /// No account.
    Denied,
    /// Every account at this level.
    Allowed(Level),
}

impl Consent {
    /// The word of a contract sequence (as in `bridge.conf`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Denied => "denied",
            Self::Allowed(level) => level.as_str(),
        }
    }

    /// The consent of a word of [`Consent::as_str`].
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "unknown" => Some(Self::Unknown),
            "denied" => Some(Self::Denied),
            _ => Level::parse(word).map(Self::Allowed),
        }
    }

    /// What `GetConsent` and `ConsentChanged` say: `unknown` or `decided`.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Denied | Self::Allowed(_) => "decided",
        }
    }
}

/// A scripted call failure (`org.netvfs.Error.<name>`).
#[derive(Debug, Clone)]
pub struct Failure {
    /// Method name or `*`.
    pub method: String,
    /// Bare error name.
    pub name: String,
    /// Error message.
    pub message: String,
    /// `detail` of the error reply.
    pub detail: Option<String>,
    /// `retryAfterMs` of the error reply.
    pub retry_after_ms: Option<u64>,
    /// Calls that succeed before the failure starts.
    pub skip: u32,
    /// How many times it fails; `None` forever.
    pub remaining: Option<u32>,
}

impl Failure {
    /// Fails every call of `method` (or `*`) with `name` and `message`.
    #[must_use]
    pub fn new(method: &str, name: &str, message: &str) -> Self {
        Self {
            method: method.to_owned(),
            name: name.to_owned(),
            message: message.to_owned(),
            detail: None,
            retry_after_ms: None,
            skip: 0,
            remaining: None,
        }
    }

    /// Fails `n` times only.
    #[must_use]
    pub fn times(mut self, n: u32) -> Self {
        self.remaining = Some(n);
        self
    }

    /// Lets `calls` calls succeed first.
    #[must_use]
    pub fn after(mut self, calls: u32) -> Self {
        self.skip = calls;
        self
    }

    /// Adds `retryAfterMs`.
    #[must_use]
    pub fn retry_after(mut self, ms: u64) -> Self {
        self.retry_after_ms = Some(ms);
        self
    }

    /// Adds `detail`.
    #[must_use]
    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_owned());
        self
    }
}

/// A job that ends with an error in `JobFinished` once `after_bytes` moved.
#[derive(Debug, Clone)]
pub struct JobFailure {
    /// `Upload`, `Download`, `RemoveTree`, `Walk` or `CopyAcross`.
    pub method: String,
    /// Bytes that move before the job fails.
    pub after_bytes: u64,
    /// Bare error name.
    pub name: String,
    /// Error message.
    pub message: String,
    /// `detail` in `JobFinished.extra`.
    pub detail: Option<String>,
    /// `retryAfterMs` in `JobFinished.extra`.
    pub retry_after_ms: Option<u64>,
    /// How many jobs fail; `None` every one.
    pub remaining: Option<u32>,
}

impl JobFailure {
    /// The next job of `method` fails after `after_bytes`.
    #[must_use]
    pub fn new(method: &str, after_bytes: u64, name: &str, message: &str) -> Self {
        Self {
            method: method.to_owned(),
            after_bytes,
            name: name.to_owned(),
            message: message.to_owned(),
            detail: None,
            retry_after_ms: None,
            remaining: Some(1),
        }
    }

    /// Adds `detail` and `retryAfterMs`.
    #[must_use]
    pub fn detail(mut self, detail: &str, retry_after_ms: Option<u64>) -> Self {
        self.detail = Some(detail.to_owned());
        self.retry_after_ms = retry_after_ms;
        self
    }
}

/// A value of the `info` dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoValue {
    /// `s`
    Str(String),
    /// `i`
    Int(i32),
    /// `b`
    Bool(bool),
    /// `ay`
    Bytes(Vec<u8>),
    /// `as`
    Strings(Vec<String>),
}

impl InfoValue {
    /// The value as the bridge sends it.
    #[must_use]
    pub fn to_owned_value(&self) -> OwnedValue {
        let v = match self {
            Self::Str(s) => Value::from(s.clone()),
            Self::Int(n) => Value::from(*n),
            Self::Bool(b) => Value::from(*b),
            Self::Bytes(b) => Value::from(b.clone()),
            Self::Strings(s) => Value::from(s.clone()),
        };
        OwnedValue::try_from(v).unwrap_or_else(|_e| OwnedValue::from(0u8))
    }
}

/// A memory card or USB drive of the fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDrive {
    /// The drive id.
    pub id: String,
    /// The filesystem label.
    pub label: String,
    /// Where it is mounted, empty when it is not.
    pub mount_point: Vec<u8>,
    /// `sd` or `usb`.
    pub kind: String,
    /// Bytes.
    pub size: i64,
}

impl FakeDrive {
    /// An unmounted `vfat` drive.
    #[must_use]
    pub fn new(id: &str, label: &str, kind: &str, size: i64) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            mount_point: Vec::new(),
            kind: kind.to_owned(),
            size,
        }
    }

    /// The drive as `ListDrives` lists it.
    #[must_use]
    pub fn wire(&self) -> WireDrive {
        let info = [
            (drive_info::KIND, InfoValue::Str(self.kind.clone())),
            (drive_info::FS_TYPE, InfoValue::Str("vfat".to_owned())),
            (drive_info::READ_ONLY, InfoValue::Bool(false)),
        ];
        let mut info: HashMap<String, OwnedValue> =
            info.iter().map(|(k, v)| ((*k).to_owned(), v.to_owned_value())).collect();
        info.insert(drive_info::SIZE.to_owned(), OwnedValue::from(self.size));
        WireDrive {
            id: self.id.clone(),
            label: self.label.clone(),
            mount_point: self.mount_point.clone(),
            info,
        }
    }
}

/// A call the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// Member name.
    pub method: String,
    /// The lane the call ran in (hint or the method's default).
    pub lane: String,
    /// Location (and path) the call was about, for debugging.
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct LocationRec {
    pub provider: String,
    pub name: String,
    pub info: Vec<(String, InfoValue)>,
}

pub struct State {
    pub consent: Consent,
    pub access: HashMap<String, Option<Level>>,
    pub own: HashMap<(String, Vec<u8>), Own>,
    pub consent_requests: u32,
    pub auto_consent: Option<Consent>,
    pub bridge_version: String,
    pub locations: BTreeMap<String, LocationRec>,
    pub trees: HashMap<String, Tree>,
    pub caps: HashMap<String, WireCapabilities>,
    pub space_total: HashMap<String, i64>,
    pub latency: Duration,
    pub chunk: usize,
    pub failures: Vec<Failure>,
    pub job_failures: Vec<JobFailure>,
    pub calls: Vec<CallRecord>,
    pub handoffs: Vec<String>,
    pub features: Vec<String>,
    pub network: String,
    pub drives: Vec<FakeDrive>,
    pub nearby: Vec<WireNearby>,
    pub sessions: Vec<Arc<Session>>,
    pub accepting: bool,
    pub accepts: Vec<Instant>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            consent: Consent::Allowed(Level::Full),
            access: HashMap::new(),
            own: HashMap::new(),
            consent_requests: 0,
            auto_consent: None,
            bridge_version: "0.2.0-fake".to_owned(),
            locations: BTreeMap::new(),
            trees: HashMap::new(),
            caps: HashMap::new(),
            space_total: HashMap::new(),
            latency: Duration::ZERO,
            chunk: 64 * 1024,
            failures: Vec::new(),
            job_failures: Vec::new(),
            calls: Vec::new(),
            handoffs: Vec::new(),
            features: vec![
                crate::methods::FEATURE_STORAGE_SETTINGS.to_owned(),
                crate::methods::FEATURE_DRIVES.to_owned(),
                crate::methods::FEATURE_NETWORK.to_owned(),
                crate::methods::FEATURE_CHECK.to_owned(),
            ],
            network: "wifi".to_owned(),
            drives: Vec::new(),
            nearby: Vec::new(),
            sessions: Vec::new(),
            accepting: true,
            accepts: Vec::new(),
        }
    }
}

impl State {
    pub fn mount(&mut self, drive: &str, mount: bool) -> Option<(Vec<u8>, bool)> {
        let d = self.drives.iter_mut().find(|d| d.id == drive)?;
        let wanted = if mount && d.mount_point.is_empty() {
            let name = if d.label.is_empty() { &d.id } else { &d.label };
            format!("/run/media/user/{name}").into_bytes()
        } else if mount {
            d.mount_point.clone()
        } else {
            Vec::new()
        };
        let changed = wanted != d.mount_point;
        d.mount_point.clone_from(&wanted);
        Some((wanted, changed))
    }

    pub fn add_location(&mut self, id: &str, provider: &str, name: &str, mut info: Vec<(String, InfoValue)>) {
        if !info.iter().any(|(k, _)| k == location_state::KEY) {
            info.push((location_state::KEY.to_owned(), InfoValue::Str(location_state::DISCONNECTED.into())));
        }
        self.locations.insert(
            id.to_owned(),
            LocationRec { provider: provider.to_owned(), name: name.to_owned(), info },
        );
        self.trees.entry(id.to_owned()).or_default();
    }

    pub fn set_state(&mut self, id: &str, state: &str, error: Option<&str>) -> bool {
        let Some(rec) = self.locations.get_mut(id) else { return false };
        let value = |key: &str| rec.info.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        let error = error.map(|e| InfoValue::Str(e.to_owned()));
        if value(location_state::KEY) == Some(InfoValue::Str(state.to_owned()))
            && value(location_state::ERROR_KEY) == error
        {
            return false;
        }
        rec.info.retain(|(k, _)| k != location_state::KEY && k != location_state::ERROR_KEY);
        rec.info.push((location_state::KEY.to_owned(), InfoValue::Str(state.to_owned())));
        if let Some(error) = error {
            rec.info.push((location_state::ERROR_KEY.to_owned(), error));
        }
        true
    }

    pub fn remove_location(&mut self, id: &str) {
        self.locations.remove(id);
        self.trees.remove(id);
    }

    pub fn tree_mut(&mut self, loc: &str) -> &mut Tree {
        self.trees.entry(loc.to_owned()).or_default()
    }

    pub fn wire_locations(&self) -> Vec<WireLocation> {
        self.locations
            .iter()
            .filter_map(|(id, rec)| {
                let level = self.level(id)?;
                let mut info: HashMap<String, OwnedValue> =
                    rec.info.iter().map(|(k, v)| (k.clone(), v.to_owned_value())).collect();
                info.insert(
                    access::KEY.to_owned(),
                    InfoValue::Str(level.as_str().to_owned()).to_owned_value(),
                );
                Some(WireLocation {
                    id: id.clone(),
                    provider: rec.provider.clone(),
                    name: rec.name.clone(),
                    info,
                })
            })
            .collect()
    }

    pub fn level(&self, id: &str) -> Option<Level> {
        let default = match self.consent {
            Consent::Unknown => return None,
            Consent::Denied => None,
            Consent::Allowed(level) => Some(level),
        };
        self.access.get(id).copied().unwrap_or(default)
    }

    pub fn own(&self, loc: &str, path: &[u8]) -> Own {
        self.own.get(&(loc.to_owned(), path.to_vec())).copied().unwrap_or(Own::No)
    }

    pub fn after_call(&mut self, loc: &str, path: &[u8], call: After, error: Option<&str>) {
        if self.level(loc).is_none_or(Level::changes) {
            return;
        }
        let error = error.map(|bare| ErrorName::parse(bare).unwrap_or(ErrorName::Internal));
        let own = access::after(self.own(loc, path), call, error);
        self.set_own(loc, path, own);
    }

    pub fn set_own(&mut self, loc: &str, path: &[u8], own: Own) {
        let key = (loc.to_owned(), path.to_vec());
        if own == Own::No {
            self.own.remove(&key);
        } else {
            self.own.insert(key, own);
        }
    }

    pub fn due_failure(&mut self, method: &str) -> Option<Failure> {
        let f = self
            .failures
            .iter_mut()
            .find(|f| (f.method == method || f.method == "*") && f.remaining != Some(0))?;
        if f.skip > 0 {
            f.skip = f.skip.saturating_sub(1);
            return None;
        }
        if let Some(n) = f.remaining.as_mut() {
            *n = n.saturating_sub(1);
        }
        Some(f.clone())
    }

    pub fn due_job_failure(&mut self, method: &str) -> Option<JobFailure> {
        let f = self.job_failures.iter_mut().find(|f| f.method == method && f.remaining != Some(0))?;
        if let Some(n) = f.remaining.as_mut() {
            *n = n.saturating_sub(1);
        }
        Some(f.clone())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Canceled,
    Finished,
    Unknown,
}

pub struct SessionState {
    pub hello: bool,
    next_id: u32,
    next_handle: u32,
    pub handles: HashMap<u32, (String, Vec<u8>)>,
    jobs: HashMap<u32, Arc<AtomicBool>>,
    pub discovering: bool,
}

pub struct Session {
    conn: Mutex<Option<zbus::Connection>>,
    st: Mutex<SessionState>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Session {
    pub fn new() -> Self {
        Self {
            conn: Mutex::new(None),
            st: Mutex::new(SessionState {
                hello: false,
                next_id: 1,
                next_handle: 1,
                handles: HashMap::new(),
                jobs: HashMap::new(),
                discovering: false,
            }),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut SessionState) -> R) -> R {
        f(&mut lock(&self.st))
    }

    pub fn set_conn(&self, conn: zbus::Connection) {
        *lock(&self.conn) = Some(conn);
    }

    pub fn conn(&self) -> Option<zbus::Connection> {
        lock(&self.conn).clone()
    }

    pub fn take_conn(&self) -> Option<zbus::Connection> {
        lock(&self.conn).take()
    }

    pub fn open_handles(&self) -> usize {
        self.with(|s| s.handles.len())
    }

    pub fn next_id(&self) -> u32 {
        self.with(|s| {
            let id = s.next_id;
            s.next_id = s.next_id.wrapping_add(1).max(1);
            id
        })
    }

    pub fn add_handle(&self, loc: &str, path: &[u8]) -> u32 {
        self.with(|s| {
            let id = s.next_handle;
            s.next_handle = s.next_handle.wrapping_add(1).max(1);
            s.handles.insert(id, (loc.to_owned(), path.to_vec()));
            id
        })
    }

    pub fn register_job(&self, id: u32) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        self.with(|s| s.jobs.insert(id, Arc::clone(&flag)));
        flag
    }

    pub fn finish_job(&self, id: u32) {
        self.with(|s| s.jobs.remove(&id));
    }

    pub fn cancel(&self, id: u32) -> CancelOutcome {
        self.with(|s| match s.jobs.get(&id) {
            Some(flag) => {
                flag.store(true, Ordering::SeqCst);
                CancelOutcome::Canceled
            }
            None if id != 0 && id < s.next_id => CancelOutcome::Finished,
            None => CancelOutcome::Unknown,
        })
    }

    pub fn shut(&self) {
        self.with(|s| {
            for flag in s.jobs.values() {
                flag.store(true, Ordering::SeqCst);
            }
            s.handles.clear();
        });
    }
}

pub struct Shared {
    pub(super) state: Mutex<State>,
}

impl Shared {
    pub fn new(state: State) -> Self {
        Self { state: Mutex::new(state) }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut lock(&self.state))
    }

    pub fn new_session(&self) -> Arc<Session> {
        let session = Arc::new(Session::new());
        self.with(|s| s.sessions.push(Arc::clone(&session)));
        session
    }

    pub fn take_sessions(&self) -> Vec<Arc<Session>> {
        self.with(|s| std::mem::take(&mut s.sessions))
    }

    pub fn sessions_snapshot(&self) -> Vec<Arc<Session>> {
        self.with(|s| s.sessions.clone())
    }

    pub fn any_discovering(&self) -> bool {
        self.sessions_snapshot().iter().any(|s| s.with(|s| s.discovering))
    }

    pub fn record_accept(&self) {
        self.with(|s| s.accepts.push(Instant::now()));
    }

    pub fn accepting(&self) -> bool {
        self.with(|s| s.accepting)
    }

    pub fn record_call(&self, method: &str, lane: &str, target: &str) {
        self.with(|s| {
            s.calls.push(CallRecord {
                method: method.to_owned(),
                lane: lane.to_owned(),
                target: target.to_owned(),
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_skip_then_count_down() {
        let mut st = State::default();
        st.failures.push(Failure::new("Stat", "NotFound", "x").after(1).times(2));
        assert!(st.due_failure("Stat").is_none());
        assert!(st.due_failure("List").is_none());
        assert_eq!(st.due_failure("Stat").unwrap().name, "NotFound");
        assert!(st.due_failure("Stat").is_some());
        assert!(st.due_failure("Stat").is_none());
        st.failures.push(Failure::new("*", "Locked", "").retry_after(5).detail("d"));
        let f = st.due_failure("Anything").unwrap();
        assert_eq!((f.retry_after_ms, f.detail.as_deref()), (Some(5), Some("d")));
    }

    #[test]
    fn job_failures_are_consumed() {
        let mut st = State::default();
        st.job_failures.push(JobFailure::new("Upload", 3, "ConnectionLost", "x").detail("d", Some(9)));
        assert!(st.due_job_failure("Download").is_none());
        let f = st.due_job_failure("Upload").unwrap();
        assert_eq!((f.after_bytes, f.retry_after_ms), (3, Some(9)));
        assert!(st.due_job_failure("Upload").is_none());
    }

    #[test]
    fn session_ids_handles_and_cancel() {
        let s = Session::new();
        assert_eq!(s.next_id(), 1);
        let flag = s.register_job(2);
        assert_eq!(s.cancel(2), CancelOutcome::Canceled);
        assert!(flag.load(Ordering::SeqCst));
        s.finish_job(2);
        assert_eq!(s.cancel(1), CancelOutcome::Finished);
        assert_eq!(s.cancel(0), CancelOutcome::Unknown);
        assert_eq!(s.cancel(77), CancelOutcome::Unknown);
        let h = s.add_handle("account:1", b"f");
        assert_eq!(s.open_handles(), 1);
        assert!(s.with(|st| st.handles.contains_key(&h)));
    }

    #[test]
    fn locations_carry_info() {
        let mut st = State::default();
        st.add_location("account:1", "fake", "Fake 1", vec![("host".into(), InfoValue::Str("h".into()))]);
        let w = st.wire_locations();
        assert_eq!(w.len(), 1);
        assert_eq!(crate::wire::value_str(&w[0].info["host"]).as_deref(), Some("h"));
        let state = |st: &State, key: &str| {
            st.wire_locations()[0].info.get(key).and_then(|v| crate::wire::value_str(v))
        };
        assert_eq!(state(&st, "state").as_deref(), Some("disconnected"));
        assert!(st.set_state("account:1", "failed", Some("Timeout")));
        assert!(!st.set_state("account:1", "failed", Some("Timeout")));
        assert_eq!(state(&st, "stateError").as_deref(), Some("Timeout"));
        assert!(st.set_state("account:1", "failed", Some("AuthFailed")));
        assert!(st.set_state("account:1", "connected", None));
        assert_eq!((state(&st, "state").as_deref(), state(&st, "stateError")), (Some("connected"), None));
        assert_eq!(state(&st, "host").as_deref(), Some("h"));
        assert!(!st.set_state("account:9", "connected", None));
        st.remove_location("account:1");
        assert!(st.wire_locations().is_empty());
        assert_eq!(Consent::Denied.as_str(), "denied");
        assert_eq!(Consent::Denied.wire(), "decided");
    }

    #[test]
    fn shutting_a_session_cancels_everything_of_it() {
        let s = Session::new();
        let flag = s.register_job(1);
        s.add_handle("a", b"f");
        s.shut();
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(s.open_handles(), 0);
    }
}
