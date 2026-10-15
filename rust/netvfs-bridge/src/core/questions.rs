// SPDX-License-Identifier: LGPL-2.1-or-later
//! SPEC-v2 XB-10 questions (`QuestionBroker` of questions.cpp):
//! `Question(s id, s kind, a{sv})` goes to the session whose request needs
//! the answer; `Answer(s id, a{sv})` resolves it. Kinds:
//!
//! - `identity-unknown`: ad-hoc first contact (XB-14); answer `{accept: b}`;
//! - `keyboard-interactive`: a prompt of the server (XC-15); answer
//!   `{accept: b, answers: aay}`;
//! - `insecure-consent`: an ad-hoc SMB location with the `guest` profile
//!   (XM-1); answer `{accept: b}`.
//!
//! A question ends unanswered when its session goes away, its request is
//! canceled or the worker that asked stops waiting (the question timeout).
//!
//! The broker only keeps the books: each pending question holds a waiter
//! `W` that the core resolves with the answer, or without one, from what
//! the broker hands back. Core actor only.

use crate::server::SessionId;
use std::collections::BTreeMap;
use std::fmt;

/// `Question` kind of an unknown server identity of an ad-hoc location.
pub use crate::locations::connector::IDENTITY_UNKNOWN;
/// `Question` kind of a keyboard-interactive prompt.
pub use crate::locations::connector::KEYBOARD_INTERACTIVE;
/// `Question` kind of an ad-hoc SMB location with an insecure profile.
pub const INSECURE_CONSENT: &str = "insecure-consent";

/// The pending questions, by id (`q1`, `q2`, …).
pub struct QuestionBroker<W> {
    pending: BTreeMap<String, (SessionId, W)>,
    next: u64,
}

impl<W> fmt::Debug for QuestionBroker<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionBroker")
            .field("pending", &self.pending.keys().collect::<Vec<_>>())
            .field("next", &self.next)
            .finish()
    }
}

impl<W> Default for QuestionBroker<W> {
    fn default() -> Self {
        Self { pending: BTreeMap::new(), next: 1 }
    }
}

impl<W> QuestionBroker<W> {
    /// Records a question to `session` resolved through `waiter`; its new
    /// id, for the `Question` signal. If the signal cannot be sent the
    /// caller withdraws it with [`QuestionBroker::cancel`].
    pub fn ask(&mut self, session: SessionId, waiter: W) -> String {
        let id = format!("q{}", self.next);
        self.next = self.next.saturating_add(1);
        self.pending.insert(id.clone(), (session, waiter));
        id
    }

    /// `Answer` from `session`: the waiter of its pending question `id`;
    /// `None` when there is none (answers to other sessions' questions are
    /// refused and leave them pending).
    pub fn answer(&mut self, session: SessionId, id: &str) -> Option<W> {
        if self.pending.get(id).is_none_or(|(owner, _)| *owner != session) {
            return None;
        }
        self.pending.remove(id).map(|(_, waiter)| waiter)
    }

    /// Withdraws question `id`: its waiter, to be resolved without an
    /// answer; `None` if it is not pending.
    pub fn cancel(&mut self, id: &str) -> Option<W> {
        self.pending.remove(id).map(|(_, waiter)| waiter)
    }

    /// The session went away: the waiters of its questions, to be resolved
    /// without an answer.
    pub fn drop_session(&mut self, session: SessionId) -> Vec<W> {
        let ids: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, (owner, _))| *owner == session)
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter_map(|id| self.cancel(id)).collect()
    }

    /// Questions waiting for an answer.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port of `tst_BridgeUnits::questions`.
    #[test]
    fn broker() {
        let mut b: QuestionBroker<&str> = QuestionBroker::default();
        assert_eq!(b.pending(), 0);
        let (s1, s2) = (SessionId(1), SessionId(2));
        let q1 = b.ask(s1, "first");
        let q2 = b.ask(s1, "second");
        let q3 = b.ask(s2, "third");
        assert_eq!((q1.as_str(), q2.as_str(), q3.as_str()), ("q1", "q2", "q3"));
        assert_eq!(b.pending(), 3);
        assert!(format!("{b:?}").contains("q2"));
        // Another session's question is refused and stays pending.
        assert_eq!(b.answer(s2, &q1), None);
        assert_eq!(b.answer(s1, "q99"), None);
        assert_eq!(b.pending(), 3);
        assert_eq!(b.answer(s1, &q1), Some("first"));
        assert_eq!(b.answer(s1, &q1), None);
        assert_eq!(b.pending(), 2);
        // Withdrawn once.
        assert_eq!(b.cancel(&q3), Some("third"));
        assert_eq!(b.cancel(&q3), None);
        // A session going away ends its questions only.
        let q4 = b.ask(s2, "fourth");
        assert_eq!(q4, "q4");
        assert_eq!(b.drop_session(s1), ["second"]);
        assert_eq!(b.drop_session(s1), Vec::<&str>::new());
        assert_eq!(b.pending(), 1);
        assert_eq!(b.answer(s2, &q4), Some("fourth"));
        assert_eq!(b.pending(), 0);
    }

    #[test]
    fn dropping_a_session_ends_all_its_questions() {
        let mut b = QuestionBroker::default();
        let s = SessionId(5);
        for n in 0..3 {
            b.ask(s, n);
        }
        b.ask(SessionId(6), 9);
        assert_eq!(b.drop_session(s), [0, 1, 2]);
        assert_eq!(b.pending(), 1);
        assert_eq!(
            (IDENTITY_UNKNOWN, KEYBOARD_INTERACTIVE, INSECURE_CONSENT),
            ("identity-unknown", "keyboard-interactive", "insecure-consent")
        );
    }
}
