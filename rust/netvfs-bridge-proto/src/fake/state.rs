// SPDX-License-Identifier: LGPL-2.1-or-later
//! Shared state of the fake bridge and of one client session.

use super::tree::Tree;
use crate::wire::{WireCapabilities, WireLocation, WireNearby, location_state};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;
use zbus::zvariant::{OwnedValue, Value};

/// The user's answer to this app using network locations (XB-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Not asked yet.
    Unknown,
    /// Allowed.
    Granted,
    /// Refused.
    Denied,
}

impl Consent {
    /// The name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Granted => "granted",
            Self::Denied => "denied",
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

/// A value of the `info` dictionary or of question details.
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
        // Plain values never contain file descriptors, the only failing case.
        OwnedValue::try_from(v).unwrap_or_else(|_e| OwnedValue::from(0u8))
    }
}

/// A question `ConnectAdHoc` asks before it connects.
#[derive(Debug, Clone)]
pub struct ScriptedQuestion {
    /// `identity-unknown`, `keyboard-interactive`, `insecure-consent`, …
    pub kind: String,
    /// The details of the `Question` signal.
    pub details: Vec<(String, InfoValue)>,
}

/// An `Answer` the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAnswer {
    /// Question id.
    pub id: String,
    /// `accept`.
    pub accept: bool,
    /// Keyboard-interactive answers.
    pub answers: Vec<Vec<u8>>,
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
    pub adhoc_questions: Vec<ScriptedQuestion>,
    pub received_secrets: Vec<Vec<u8>>,
    pub answers: Vec<RecordedAnswer>,
    pub calls: Vec<CallRecord>,
    pub handoffs: Vec<String>,
    /// What `GetFeatures` answers (XB-19).
    pub features: Vec<String>,
    pub nearby: Vec<WireNearby>,
    pub next_adhoc: u32,
    pub next_question: u32,
    pub sessions: Vec<Arc<Session>>,
    pub accepting: bool,
    pub accepts: Vec<Instant>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            consent: Consent::Granted,
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
            adhoc_questions: Vec::new(),
            received_secrets: Vec::new(),
            answers: Vec::new(),
            calls: Vec::new(),
            handoffs: Vec::new(),
            features: vec![crate::methods::FEATURE_STORAGE_SETTINGS.to_owned()],
            nearby: Vec::new(),
            next_adhoc: 1,
            next_question: 1,
            sessions: Vec::new(),
            accepting: true,
            accepts: Vec::new(),
        }
    }
}

impl State {
    /// Adds a location; without a `state` in `info` it is disconnected.
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

    /// Sets the connection state of location `id` (`state`, and
    /// `stateError` for `failed`); whether that changed anything.
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
            .map(|(id, rec)| WireLocation {
                id: id.clone(),
                provider: rec.provider.clone(),
                name: rec.name.clone(),
                info: rec.info.iter().map(|(k, v)| (k.clone(), v.to_owned_value())).collect(),
            })
            .collect()
    }

    /// Takes the first scripted failure matching `method`, if it is due.
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

    /// Takes a job failure for `method`.
    pub fn due_job_failure(&mut self, method: &str) -> Option<JobFailure> {
        let f = self.job_failures.iter_mut().find(|f| f.method == method && f.remaining != Some(0))?;
        if let Some(n) = f.remaining.as_mut() {
            *n = n.saturating_sub(1);
        }
        Some(f.clone())
    }
}

/// What `Cancel` found.
#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Canceled,
    /// The id was valid once and has finished.
    Finished,
    Unknown,
}

pub struct SessionState {
    pub hello: bool,
    next_id: u32,
    next_handle: u32,
    pub handles: HashMap<u32, (String, Vec<u8>)>,
    jobs: HashMap<u32, Arc<AtomicBool>>,
    questions: HashMap<String, oneshot::Sender<RecordedAnswer>>,
    pub discovering: bool,
}

pub struct Session {
    conn: Mutex<Option<zbus::Connection>>,
    st: Mutex<SessionState>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock cannot leave the data inconsistent here.
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
                questions: HashMap::new(),
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

    /// Next id of the shared request and job numbering.
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

    /// The client is gone: its jobs are canceled, its questions unanswerable
    /// and its handles closed, as the real bridge does (netvfs XB-13).
    pub fn shut(&self) {
        self.with(|s| {
            for flag in s.jobs.values() {
                flag.store(true, Ordering::SeqCst);
            }
            s.questions.clear();
            s.handles.clear();
        });
    }

    pub fn add_question(&self, id: &str) -> oneshot::Receiver<RecordedAnswer> {
        let (tx, rx) = oneshot::channel();
        self.with(|s| s.questions.insert(id.to_owned(), tx));
        rx
    }

    pub fn take_question(&self, id: &str) -> Option<oneshot::Sender<RecordedAnswer>> {
        self.with(|s| s.questions.remove(id))
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

    /// True while any client looks for servers nearby.
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
        // Disconnected until it is used.
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
    }

    #[test]
    fn shutting_a_session_cancels_everything_of_it() {
        let s = Session::new();
        let flag = s.register_job(1);
        s.add_handle("a", b"f");
        let mut rx = s.add_question("q1");
        s.shut();
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(s.open_handles(), 0);
        assert!(matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
    }

    #[test]
    fn question_round_trip() {
        let s = Session::new();
        let mut rx = s.add_question("q1");
        rx.try_recv().unwrap_err();
        let tx = s.take_question("q1").unwrap();
        tx.send(RecordedAnswer { id: "q1".into(), accept: true, answers: vec![] }).unwrap();
        assert!(rx.try_recv().unwrap().accept);
        assert!(s.take_question("q1").is_none());
    }
}
