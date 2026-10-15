// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`CancelToken`]: `Backend::cancel` (C-9) for async code. One token
//! stands for one connection between two `resetCancel`s: the C ABI trips it
//! from any thread, every call of the connection sees it, and
//! `resetCancel` gives the connection a fresh token, so that a call that
//! saw the old one stays canceled.

use crate::status::Status;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use tokio::sync::Notify;

/// A cancel flag that async code can wait for. Clones share the flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    canceled: AtomicBool,
    notify: Notify,
}

impl CancelToken {
    /// A token that is not canceled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trips the token and wakes every waiter; from any thread, also more
    /// than once.
    pub fn cancel(&self) {
        self.inner.canceled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Whether [`cancel`](Self::cancel) was called.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.inner.canceled.load(Ordering::SeqCst)
    }

    /// `Err(Canceled)` once the token is tripped.
    ///
    /// # Errors
    /// `Canceled` when it is.
    pub fn check(&self) -> Result<(), Status> {
        if self.is_canceled() { Err(Status::canceled()) } else { Ok(()) }
    }

    /// Resolves once the token is tripped (at once if it is).
    pub async fn canceled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            let mut notified = pin!(notified);
            // Registered before the flag is read: a cancel in between
            // still wakes this waiter.
            notified.as_mut().enable();
            if self.is_canceled() {
                return;
            }
            notified.await;
        }
    }

    /// Runs `work` until it ends or the token is tripped, whichever comes
    /// first; a tripped token drops `work` and gives `Canceled`. A token
    /// tripped before the start gives `Canceled` without polling `work`.
    ///
    /// # Errors
    /// What `work` returns, or `Canceled`.
    pub async fn guard<T>(&self, work: impl Future<Output = Result<T, Status>>) -> Result<T, Status> {
        self.check()?;
        let mut work = pin!(work);
        let mut canceled = pin!(self.canceled());
        poll_fn(|cx| {
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            if canceled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Status::canceled()));
            }
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::ErrorName;
    use std::time::Duration;

    #[test]
    fn flag_and_check() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(!token.is_canceled());
        assert_eq!(token.check(), Ok(()));
        clone.cancel();
        assert!(token.is_canceled());
        assert_eq!(token.check(), Err(Status::canceled()));
        clone.cancel();
        assert!(token.is_canceled());
        // A fresh token is a new flag (resetCancel).
        assert!(!CancelToken::new().is_canceled());
    }

    #[tokio::test]
    async fn canceled_resolves_at_once_when_tripped() {
        let token = CancelToken::new();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), token.canceled()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_wakes_waiters_from_another_thread() {
        let token = CancelToken::new();
        let waiter = {
            let token = token.clone();
            tokio::spawn(async move { token.canceled().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished());
        let other = token.clone();
        std::thread::spawn(move || other.cancel()).join().unwrap();
        tokio::time::timeout(Duration::from_secs(5), waiter).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn canceled_waits_while_not_tripped() {
        let token = CancelToken::new();
        assert!(tokio::time::timeout(Duration::from_millis(50), token.canceled()).await.is_err());
    }

    #[tokio::test]
    async fn guard_passes_results_through() {
        let token = CancelToken::new();
        assert_eq!(token.guard(async { Ok::<_, Status>(7) }).await, Ok(7));
        let failed = token.guard(async { Err::<(), _>(Status::new(ErrorName::NotFound, "x")) }).await;
        assert_eq!(failed.map_err(|s| s.name), Err(ErrorName::NotFound));
    }

    #[tokio::test]
    async fn guard_refuses_to_start_when_tripped() {
        let token = CancelToken::new();
        token.cancel();
        let mut started = false;
        let r = token
            .guard(async {
                started = true;
                Ok(())
            })
            .await;
        assert_eq!(r, Err(Status::canceled()));
        assert!(!started);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guard_ends_a_stalled_call() {
        let token = CancelToken::new();
        let canceler = token.clone();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            canceler.cancel();
        });
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            token.guard(std::future::pending::<Result<(), Status>>()),
        )
        .await
        .unwrap();
        assert_eq!(r, Err(Status::canceled()));
        timer.await.unwrap();
    }

    #[tokio::test]
    async fn guard_prefers_a_finished_call() {
        // Both are ready at the first poll: the result wins.
        let token = CancelToken::new();
        let inner = token.clone();
        let r = token
            .guard(async move {
                inner.cancel();
                Ok(5)
            })
            .await;
        assert_eq!(r, Ok(5));
    }
}
