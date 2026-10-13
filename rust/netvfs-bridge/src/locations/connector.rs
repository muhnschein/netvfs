// SPDX-License-Identifier: LGPL-2.1-or-later
//! How the bridge opens a connection (XB-12, XB-14, C-7; port of
//! `connector.cpp`, design §3.3). The order connect → identity verdict →
//! credentials → authenticate is kept by one `conn_establish` call in C++;
//! this module decides the verdicts and where the credentials come from.
//!
//! - Accounts: the connection data comes from the helper's `files` answer
//!   (asked through the core, [`WorkerEvent::FetchAccount`]); the identity
//!   is checked against the account's `host_key` pin and the secret is
//!   fetched from signond in C++ only after that. An identity or
//!   authentication failure is returned as an error and sets the account's
//!   attention state as Buteo does ([`WorkerEvent::Attention`]);
//!   resolution happens in Settings, never through a question.
//! - Ad hoc: the identity is checked against this consumer's known_hosts
//!   ([`PinStore`]). An unknown identity becomes `Question(identity-unknown)`
//!   with the full server identity; an accepted one is pinned. A changed
//!   identity is `ServerIdentityChanged` (re-pinning needs `ForgetAdHoc`).
//!   Only then the secret the consumer gave is used.
//! - Keyboard-interactive prompts are relayed as
//!   `Question(keyboard-interactive)` to the session whose request opened
//!   the connection; canceling the request ends the wait.
//!
//! A question waits in 100 ms slices, looking at the request's cancel flag,
//! for at most the question timeout (10 min); when it stops waiting it
//! withdraws the question ([`WorkerEvent::CancelQuestion`]).

use super::spec::{Attention, LocationKind, LocationSpec};
use super::worker::Backend;
use super::{Answer, AskId, TaskContext, WorkerEvent, WorkerEvents};
use crate::Status;
use crate::ffi::{
    CancelHandle, Conn, EstablishError, EstablishHooks, Ffi, Handle, Identity, IdentityKind, Params, Phase,
    PromptRequest, Reply, Secret, Value, Verdict,
};
use netvfs_bridge_proto::ErrorName;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use zbus::zvariant::{self, OwnedValue, Str};
use zeroize::Zeroizing;

/// `Question` kind of an unknown server identity of an ad-hoc location.
pub const IDENTITY_UNKNOWN: &str = "identity-unknown";
/// `Question` kind of a keyboard-interactive prompt (XC-15).
pub const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";
/// How long a question waits for its answer (`questionTimeoutMs`).
pub const QUESTION_TIMEOUT: Duration = Duration::from_mins(10);
/// How long an account's connection data may take (`FetchTimeoutMs`).
pub const FETCH_TIMEOUT: Duration = Duration::from_mins(1);
/// How often a waiting worker looks at its cancel flag.
pub const WAIT_SLICE: Duration = Duration::from_millis(100);

/// The pins of identities the user accepted for ad-hoc locations (XB-14),
/// by host key. The consumer's known_hosts file
/// (`locations::knownhosts::KnownHosts` of the platform part) implements
/// it; thread-safe, as workers read and write pins.
pub trait PinStore: Send + Sync {
    /// The pin of `key`; empty when none is stored.
    fn pin(&self, key: &str) -> String;
    /// Stores `pin` for `key`; false when it cannot be saved.
    fn set_pin(&self, key: &str, pin: &str) -> bool;
    /// Forgets the pin of `key`; false when it cannot be saved.
    fn remove(&self, key: &str) -> bool;
}

/// What a connection to an account needs (the helper's `files` answer,
/// XA-4): the parameters (with the `host_key` pin among the options) and
/// where signond keeps the secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountAccess {
    /// `paramsForService(Files)`.
    pub params: Params,
    /// The signond identity holding the secret.
    pub credentials_id: u32,
    /// A connection may go on without a secret (XA-7).
    pub secret_optional: bool,
}

/// How a wait for the core ended.
#[derive(Debug, PartialEq, Eq)]
enum Waited<T> {
    Got(T),
    Canceled,
    TimedOut,
    /// The core dropped the sender without an answer.
    Gone,
}

/// Waits for one value from the core in [`WAIT_SLICE`]s (the C++
/// `Rendezvous`): a value already there wins over a cancel.
fn wait_for<T>(rx: &mpsc::Receiver<T>, cancel: &AtomicBool, timeout: Duration) -> Waited<T> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match rx.try_recv() {
            Ok(value) => return Waited::Got(value),
            Err(mpsc::TryRecvError::Disconnected) => return Waited::Gone,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if cancel.load(Ordering::Acquire) {
            return Waited::Canceled;
        }
        let now = Instant::now();
        let left = deadline.map_or(WAIT_SLICE, |d| d.saturating_duration_since(now));
        if left.is_zero() {
            return Waited::TimedOut;
        }
        match rx.recv_timeout(left.min(WAIT_SLICE)) {
            Ok(value) => return Waited::Got(value),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Waited::Gone,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Asks questions through the core (`BridgeConnector::ask`).
#[derive(Debug, Clone)]
pub struct Asker {
    events: WorkerEvents,
    timeout: Duration,
}

impl Asker {
    /// Questions go through `events` and wait at most `timeout`.
    #[must_use]
    pub const fn new(events: WorkerEvents, timeout: Duration) -> Self {
        Self { events, timeout }
    }

    /// Asks `task`'s session and waits for the answer; `None` when there is
    /// none (canceled, timed out, no session). A question the worker stops
    /// waiting for is withdrawn.
    #[must_use]
    pub fn ask(
        &self,
        task: &TaskContext,
        kind: &'static str,
        details: HashMap<String, OwnedValue>,
    ) -> Option<Answer> {
        let (tx, rx) = mpsc::channel();
        let ask = AskId::next();
        self.events.send(WorkerEvent::Ask { ask, session: task.session, kind, details, answer: tx });
        match wait_for(&rx, &task.cancel, self.timeout) {
            Waited::Got(answer) => answer,
            Waited::Gone => None,
            Waited::Canceled | Waited::TimedOut => {
                self.events.send(WorkerEvent::CancelQuestion(ask));
                None
            }
        }
    }
}

fn text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

/// An `a{sv}` value of `v`, if the wire can carry it.
fn owned(v: zvariant::Value<'_>) -> Option<OwnedValue> {
    OwnedValue::try_from(v).ok()
}

/// A typed value of the C ABI as a variant: `s`, `b`, `x`, `ay`, `as`.
fn value(v: &Value) -> Option<OwnedValue> {
    match v {
        Value::Str(s) => Some(text(s)),
        Value::Bool(b) => Some(OwnedValue::from(*b)),
        Value::Int(i) => Some(OwnedValue::from(*i)),
        Value::Bytes(b) => owned(zvariant::Value::from(b.clone())),
        Value::StrList(l) => owned(zvariant::Value::from(l.clone())),
    }
}

/// The details of `Question(identity-unknown)` (`identityDetails`).
#[must_use]
pub fn identity_details(identity: &Identity, spec: &LocationSpec) -> HashMap<String, OwnedValue> {
    let mut d = HashMap::new();
    d.insert("location".to_owned(), text(&spec.id));
    d.insert("host".to_owned(), text(&spec.params.host));
    d.insert("port".to_owned(), OwnedValue::from(spec.params.port));
    d.insert("provider".to_owned(), text(&spec.provider));
    d.insert("kind".to_owned(), text(if identity.kind == IdentityKind::Tls { "tls" } else { "ssh" }));
    d.insert("algorithm".to_owned(), text(&identity.algorithm));
    d.insert("fingerprint".to_owned(), text(&identity.fingerprint));
    if let Some(key) = owned(zvariant::Value::from(identity.public_key.clone())) {
        d.insert("publicKey".to_owned(), key);
    }
    d.insert("systemTrusted".to_owned(), OwnedValue::from(identity.system_trusted));
    d.insert("problems".to_owned(), OwnedValue::from(identity.problems));
    for (key, v) in &identity.details {
        if let Some(v) = value(v) {
            d.insert(key.clone(), v);
        }
    }
    d
}

/// The details of `Question(keyboard-interactive)`: `name`, `instruction`,
/// `prompts` (`as`) and `echo` (`av` of `b`).
#[must_use]
pub fn prompt_details(request: &PromptRequest) -> HashMap<String, OwnedValue> {
    let mut d = HashMap::new();
    d.insert("name".to_owned(), text(&request.name));
    d.insert("instruction".to_owned(), text(&request.instruction));
    let texts: Vec<String> = request.prompts.iter().map(|p| p.text.clone()).collect();
    if let Some(prompts) = owned(zvariant::Value::from(texts)) {
        d.insert("prompts".to_owned(), prompts);
    }
    let echo: Vec<zvariant::Value<'_>> =
        request.prompts.iter().map(|p| zvariant::Value::new(zvariant::Value::from(p.echo))).collect();
    if let Some(echo) = owned(zvariant::Value::from(echo)) {
        d.insert("echo".to_owned(), echo);
    }
    d
}

/// The answers to give for `request` (`QuestionPrompter::answer`): `None`
/// to decline (no answer, not accepted, or a count other than the
/// prompts', whose answers are then wiped).
#[must_use]
pub fn prompt_answers(
    asker: &Asker,
    task: &TaskContext,
    request: &PromptRequest,
) -> Option<Vec<Zeroizing<Vec<u8>>>> {
    let answer = asker.ask(task, KEYBOARD_INTERACTIVE, prompt_details(request))?;
    (answer.accept && answer.answers.len() == request.prompts.len()).then_some(answer.answers)
}

/// The attention state a failed account connection leaves, with the pin
/// to record (the one seen, for an identity problem); `None` when it
/// leaves none (failures before the identity check, credentials lookups,
/// other errors).
#[must_use]
pub fn attention_for(failure: &EstablishError, seen_pin: &str) -> Option<(Attention, String)> {
    if !matches!(failure.phase, Phase::Identity | Phase::Authenticate) {
        return None;
    }
    match Attention::for_error(failure.status.name) {
        Attention::None => None,
        Attention::AuthFailed => Some((Attention::AuthFailed, String::new())),
        Attention::ServerIdentityChanged => Some((Attention::ServerIdentityChanged, seen_pin.to_owned())),
    }
}

/// The `host_key` option of an account's parameters: the pin its identity
/// is checked against.
#[must_use]
pub fn account_pin(params: &Params) -> String {
    match params.options.get("host_key") {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

/// The identity verdict for an ad-hoc location (`checkAdHocIdentity`).
struct AdHocIdentity<'a> {
    asker: &'a Asker,
    pins: &'a dyn PinStore,
    events: &'a WorkerEvents,
    task: &'a TaskContext,
    spec: &'a LocationSpec,
    /// The user declined the unknown identity.
    declined: bool,
}

impl AdHocIdentity<'_> {
    fn verdict(&mut self, seen: &Identity, check: Option<&Status>) -> Verdict {
        if check.is_none_or(|s| s.name != ErrorName::ServerIdentityUnknown) {
            return Verdict::UseCheck;
        }
        let accepted = self.asker.ask(self.task, IDENTITY_UNKNOWN, identity_details(seen, self.spec));
        if !accepted.is_some_and(|a| a.accept) {
            if self.task.canceled() {
                return Verdict::Cancel;
            }
            self.declined = true;
            return Verdict::UseCheck;
        }
        if !self.pins.set_pin(&self.spec.host_key(), &seen.pin) {
            self.events.send(WorkerEvent::Warning("Cannot store an accepted server identity".to_owned()));
        }
        Verdict::AcceptUnknown
    }
}

/// The production [`Backend`]: connections through the C ABI, with the
/// policy above (`BridgeConnector`).
pub struct Connector {
    ffi: Ffi,
    pins: Arc<dyn PinStore>,
    events: WorkerEvents,
    asker: Asker,
    fetch_timeout: Duration,
}

impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector").field("asker", &self.asker).finish_non_exhaustive()
    }
}

impl Connector {
    /// Connections through `ffi`, ad-hoc pins in `pins`, questions, account
    /// data and attention through `events`; questions wait at most
    /// `question_timeout`.
    #[must_use]
    pub fn new(ffi: Ffi, pins: Arc<dyn PinStore>, events: WorkerEvents, question_timeout: Duration) -> Self {
        let asker = Asker::new(events.clone(), question_timeout);
        Self { ffi, pins, events, asker, fetch_timeout: FETCH_TIMEOUT }
    }

    /// The same with another wait for account data (tests).
    #[must_use]
    pub const fn with_fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// The account's connection data, from the core.
    fn fetch(&self, account_id: i32, task: &TaskContext) -> Result<AccountAccess, Status> {
        let (tx, rx) = mpsc::channel();
        self.events.send(WorkerEvent::FetchAccount { account_id, reply: tx });
        if let Waited::Got(access) = wait_for(&rx, &task.cancel, self.fetch_timeout) {
            return access;
        }
        let name = if task.canceled() { ErrorName::Canceled } else { ErrorName::Timeout };
        Err(Status::new(name, "No account data"))
    }

    fn prompt(&self, task: &TaskContext, request: &PromptRequest, reply: &mut Reply<'_>) -> bool {
        prompt_answers(&self.asker, task, request).is_some_and(|answers| {
            reply.set(&answers);
            true
        })
    }

    fn establish_account(&self, conn: &mut Conn, account_id: i32, task: &TaskContext) -> Result<(), Status> {
        let access = self.fetch(account_id, task)?;
        let pin = account_pin(&access.params);
        let secret = Secret::Signon {
            user: access.params.username.clone(),
            credentials_id: access.credentials_id,
            secret_optional: access.secret_optional,
        };
        let mut seen_pin = String::new();
        let result = {
            // XB-14: the account's pin decides; the pin seen is kept for
            // the attention record.
            let mut identity = |seen: &Identity, _check: Option<&Status>| {
                seen_pin.clone_from(&seen.pin);
                Verdict::UseCheck
            };
            let mut prompt =
                |request: &PromptRequest, reply: &mut Reply<'_>| self.prompt(task, request, reply);
            let mut hooks = EstablishHooks { identity: Some(&mut identity), prompt: Some(&mut prompt) };
            conn.establish(&access.params, &pin, &secret, &mut hooks)
        };
        result.map_err(|failure| {
            if let Some((attention, pin)) = attention_for(&failure, &seen_pin) {
                self.events.send(WorkerEvent::Attention { account_id, attention, pin });
            }
            failure.status
        })
    }

    fn establish_ad_hoc(
        &self,
        conn: &mut Conn,
        spec: &LocationSpec,
        task: &TaskContext,
    ) -> Result<(), Status> {
        let pin = self.pins.pin(&spec.host_key());
        let secret = spec.ad_hoc_secret.as_ref().map_or_else(
            || Secret::None { user: String::new() },
            |s| Secret::Bytes { user: s.user().to_owned(), secret: s.secret() },
        );
        let mut judge = AdHocIdentity {
            asker: &self.asker,
            pins: &*self.pins,
            events: &self.events,
            task,
            spec,
            declined: false,
        };
        let result = {
            let mut identity = |seen: &Identity, check: Option<&Status>| judge.verdict(seen, check);
            let mut prompt =
                |request: &PromptRequest, reply: &mut Reply<'_>| self.prompt(task, request, reply);
            let mut hooks = EstablishHooks { identity: Some(&mut identity), prompt: Some(&mut prompt) };
            conn.establish(&spec.params, &pin, &secret, &mut hooks)
        };
        result.map_err(|failure| {
            if judge.declined && failure.status.name == ErrorName::ServerIdentityUnknown {
                Status::new(ErrorName::ServerIdentityUnknown, "The server identity was not accepted")
            } else {
                failure.status
            }
        })
    }
}

impl Backend for Connector {
    type Conn = Conn;
    type Handle = Handle;
    type Cancel = CancelHandle;

    fn create(&self, spec: &LocationSpec) -> Result<Conn, Status> {
        self.ffi.conn_new(&spec.provider)
    }

    fn cancel_handle(&self, conn: &Conn) -> CancelHandle {
        conn.cancel_handle()
    }

    fn cancel(&self, handle: &CancelHandle) {
        // False only when the connection is gone: nothing left to cancel.
        let _live = handle.cancel();
    }

    fn establish(&self, conn: &mut Conn, spec: &LocationSpec, task: &TaskContext) -> Result<(), Status> {
        match spec.kind {
            LocationKind::Account { account_id } => self.establish_account(conn, account_id, task),
            LocationKind::AdHoc => self.establish_ad_hoc(conn, spec, task),
        }
    }

    fn reset_cancel(&self, conn: &mut Conn) {
        // Refused only inside a callback, which a worker never is here.
        drop(conn.reset_cancel());
    }
}

#[cfg(test)]
#[path = "connector_tests.rs"]
mod tests;
