// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a consumer may reach and how: location specs ([`spec`]), connection pools with lanes and the per-host limit ([`pool`]), connection state ([`state`]), one std thread per backend connection ([`worker`]), copy jobs on threads of their own ([`copyjobs`]), connection policy for accounts and ad-hoc locations ([`connector`]), the book holding them for the core ([`book`]) and pins of ad-hoc identities ([`knownhosts`]).
//!
//! # Threads
//!
//! Book, pools and copy jobs belong to the core actor (no locks). Each worker is a std thread `nvb-w` owning its [`ffi::Conn`](crate::ffi::Conn); each copy job a thread `nvb-copy` with two.
//! Shared across threads: per-operation [`CancelToken`]s, each worker's queue (mutex with its connection's cancel handle and phase), each pool's [`StateTracker`](state::StateTracker) with the [`StateSignal`](state::StateSignal) that wakes the core.
//!
//! # Worker → core
//!
//! Workers and copy jobs report through [`WorkerEvents`] ([`WorkerEvent`]): questions and their withdrawal, account connection data, account attention state, finished copy jobs, log warnings.
//! The core folds `WorkerEvent` into `core::Event`; results of ordinary work items come from the closures the core builds.

pub mod book;
pub mod connector;
pub mod copyjobs;
pub mod knownhosts;
#[cfg(test)]
mod mock;
pub mod pool;
pub mod spec;
pub mod state;
pub mod worker;

use crate::Status;
use crate::server::SessionId;
use connector::AccountAccess;
use copyjobs::CopyId;
use spec::Attention;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use zbus::zvariant::OwnedValue;
use zeroize::Zeroizing;

/// The cancel flag of one request or job: set by the core, polled by workers, descriptor devices and question waits.
pub type CancelToken = Arc<AtomicBool>;

/// Who a piece of work is for: the session (for questions) and the request's cancel flag.
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// The session whose request this is (questions go there).
    pub session: SessionId,
    /// Set when the request is canceled.
    pub cancel: CancelToken,
}

impl TaskContext {
    /// The context of a request of `session`.
    #[must_use]
    pub const fn new(session: SessionId, cancel: CancelToken) -> Self {
        Self { session, cancel }
    }

    /// Work for no session that nobody cancels (closing a handle).
    #[must_use]
    pub fn detached() -> Self {
        Self { session: SessionId(0), cancel: Arc::new(AtomicBool::new(false)) }
    }

    /// Whether the request was canceled.
    #[must_use]
    pub fn canceled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

/// `Canceled` without a message, as a canceled request ends.
#[must_use]
pub fn canceled() -> Status {
    Status::new(netvfs_bridge_proto::ErrorName::Canceled, "")
}

/// One question a worker asks (identity-unknown, keyboard-interactive),
/// unique in the process; [`WorkerEvent::CancelQuestion`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AskId(pub u64);

impl AskId {
    /// A new id.
    #[must_use]
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A consumer's answer to a question (`Answer` call).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Answer {
    /// Whether the consumer accepted.
    pub accept: bool,
    /// Keyboard-interactive answers, one per prompt; wiped on drop.
    pub answers: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer").field("accept", &self.accept).field("answers", &self.answers.len()).finish()
    }
}

/// What a worker or copy job needs from the core.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Ask `session` a question (`Question` signal); the answer (`None`: none) goes through `answer`, once.
    /// The worker waits at most the question timeout, then sends [`WorkerEvent::CancelQuestion`].
    Ask {
        /// The question's id on the worker side.
        ask: AskId,
        /// The session whose request opened the connection.
        session: SessionId,
        /// `identity-unknown` or `keyboard-interactive`.
        kind: &'static str,
        /// The `a{sv}` of the `Question` signal.
        details: HashMap<String, OwnedValue>,
        /// Where the answer goes.
        answer: mpsc::Sender<Option<Answer>>,
    },
    /// The worker stopped waiting (canceled, timed out): withdraw the
    /// question if it is still pending.
    CancelQuestion(AskId),
    /// What a connection to the account needs (the helper's `files` answer), sent through `reply`, once.
    FetchAccount {
        /// The account.
        account_id: i32,
        /// Where the answer goes.
        reply: mpsc::Sender<Result<AccountAccess, Status>>,
    },
    /// An account's connection failed at the identity check or authentication: record the state (the helper's `attention`) and relist the accounts.
    Attention {
        /// The account.
        account_id: i32,
        /// The new state.
        attention: Attention,
        /// The identity pin seen, for review in Settings; may be empty.
        pin: String,
    },
    /// A copy job's thread ended: call [`CopyJobs::finish`](copyjobs::CopyJobs::finish) and report the result.
    CopyDone {
        /// The job.
        id: CopyId,
        /// How it ended.
        result: Result<(), Status>,
    },
    /// Something for the warning log.
    Warning(String),
}

/// Where workers send [`WorkerEvent`]s. Called from std threads; must not block.
#[derive(Clone)]
pub struct WorkerEvents(Arc<dyn Fn(WorkerEvent) + Send + Sync>);

impl WorkerEvents {
    /// Events go to `deliver`.
    pub fn new(deliver: impl Fn(WorkerEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(deliver))
    }

    /// Events go into an unbounded channel (and are dropped once its
    /// receiver is gone).
    #[must_use]
    pub fn channel(tx: tokio::sync::mpsc::UnboundedSender<WorkerEvent>) -> Self {
        Self::new(move |event| {
            // A closed channel means the core has stopped: nothing to do.
            drop(tx.send(event));
        })
    }

    /// Sends `event`.
    pub fn send(&self, event: WorkerEvent) {
        (self.0)(event);
    }
}

impl fmt::Debug for WorkerEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WorkerEvents")
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    #[test]
    fn task_context_and_canceled() {
        let token = Arc::new(AtomicBool::new(false));
        let task = TaskContext::new(SessionId(4), Arc::clone(&token));
        assert_eq!(task.session, SessionId(4));
        assert!(!task.canceled());
        token.store(true, Ordering::Release);
        assert!(task.canceled());
        let detached = TaskContext::detached();
        assert_eq!(detached.session, SessionId(0));
        assert!(!detached.canceled());
        let c = canceled();
        assert_eq!((c.name, c.message.as_str()), (ErrorName::Canceled, ""));
    }

    #[test]
    fn ask_ids_are_unique_and_answers_hide_secrets() {
        let (a, b) = (AskId::next(), AskId::next());
        assert!(b > a);
        let answer = Answer { accept: true, answers: vec![Zeroizing::new(b"123456".to_vec())] };
        let text = format!("{answer:?}");
        assert!(text.contains("accept: true") && text.contains("answers: 1"), "{text}");
        assert!(!text.contains("49"), "{text}");
    }

    #[test]
    fn events_reach_the_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let events = WorkerEvents::channel(tx);
        assert_eq!(format!("{events:?}"), "WorkerEvents");
        events.send(WorkerEvent::Warning("w".into()));
        assert!(matches!(rx.try_recv(), Ok(WorkerEvent::Warning(w)) if w == "w"));
        drop(rx);
        // A gone core: dropped quietly.
        events.send(WorkerEvent::CancelQuestion(AskId(1)));
    }
}
