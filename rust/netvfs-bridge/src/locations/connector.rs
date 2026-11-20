// SPDX-License-Identifier: LGPL-2.1-or-later
//! How the bridge opens a connection: `conn_establish` keeps the order connect → identity verdict → credentials → authenticate; this module decides where the connection data and the secret come from.
//!
//! Every location is an account: connection data comes from the helper's `files` answer (asked through the core, [`WorkerEvent::FetchAccount`]); identity is checked against the account's `host_key` pin and only then the secret is fetched from signond.
//! An identity or authentication failure is returned as an error and sets the account's attention state ([`WorkerEvent::Attention`]); resolution happens in Settings. No prompt hook: consumers are never asked for a secret.

use super::spec::{Attention, LocationSpec};
use super::worker::Backend;
use super::{TaskContext, WorkerEvent, WorkerEvents};
use crate::Status;
use crate::ffi::{
    CancelHandle, Conn, EstablishError, EstablishHooks, Ffi, Handle, Identity, Params, Phase, Secret, Value,
    Verdict,
};
use netvfs_bridge_proto::ErrorName;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long an account's connection data may take.
pub const FETCH_TIMEOUT: Duration = Duration::from_mins(1);
/// How often a worker waiting for account data looks at its cancel flag.
pub const WAIT_SLICE: Duration = Duration::from_millis(100);

/// What a connection to an account needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountAccess {
    /// The account's parameters, for Files.
    pub params: Params,
    /// The signond identity holding the secret.
    pub credentials_id: u32,
    /// A connection may go on without a secret.
    pub secret_optional: bool,
}

impl From<crate::accounts::FilesAccess> for AccountAccess {
    fn from(access: crate::accounts::FilesAccess) -> Self {
        Self {
            params: access.params.to_ffi(),
            credentials_id: access.credentials_id,
            secret_optional: access.secret_optional,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Waited<T> {
    Got(T),
    Canceled,
    TimedOut,
    Gone,
}

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

/// The attention state a failed account connection leaves, with the pin to record (the one seen, for an identity problem).
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

/// The `host_key` option of an account's parameters.
#[must_use]
pub fn account_pin(params: &Params) -> String {
    match params.options.get("host_key") {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

/// The production [`Backend`].
pub struct Connector {
    ffi: Ffi,
    events: WorkerEvents,
    fetch_timeout: Duration,
}

impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector").field("fetch_timeout", &self.fetch_timeout).finish_non_exhaustive()
    }
}

impl Connector {
    /// Connections through `ffi`, account data and attention through `events`.
    #[must_use]
    pub const fn new(ffi: Ffi, events: WorkerEvents) -> Self {
        Self { ffi, events, fetch_timeout: FETCH_TIMEOUT }
    }

    /// The same with another wait for account data (tests).
    #[must_use]
    pub const fn with_fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    fn fetch(&self, account_id: i32, task: &TaskContext) -> Result<AccountAccess, Status> {
        let (tx, rx) = mpsc::channel();
        self.events.send(WorkerEvent::FetchAccount { account_id, reply: tx });
        if let Waited::Got(access) = wait_for(&rx, &task.cancel, self.fetch_timeout) {
            return access;
        }
        let name = if task.canceled() { ErrorName::Canceled } else { ErrorName::Timeout };
        Err(Status::new(name, "No account data"))
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
            // The account's pin decides; the pin seen is kept for the attention record.
            let mut identity = |seen: &Identity, _check: Option<&Status>| {
                seen_pin.clone_from(&seen.pin);
                Verdict::UseCheck
            };
            let mut hooks = EstablishHooks { identity: Some(&mut identity), prompt: None };
            conn.establish(&access.params, &pin, &secret, &mut hooks)
        };
        result.map_err(|failure| {
            if let Some((attention, pin)) = attention_for(&failure, &seen_pin) {
                self.events.send(WorkerEvent::Attention { account_id, attention, pin });
            }
            failure.status
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
        self.establish_account(conn, spec.account_id, task)
    }

    fn reset_cancel(&self, conn: &mut Conn) {
        // Refused only inside a callback, which a worker never is here.
        drop(conn.reset_cancel());
    }
}

#[cfg(test)]
#[path = "connector_tests.rs"]
mod tests;
