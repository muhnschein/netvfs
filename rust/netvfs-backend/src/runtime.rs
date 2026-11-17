// SPDX-License-Identifier: LGPL-2.1-or-later
//! One tokio runtime per process, made on first use, never shut down. Workers `nvr-io-<n>`; every C ABI call
//! runs its future with `block_on` on the caller's thread, so callbacks run there too.
//!
//! A canceled call is dropped [`GRACE`] after the cancel and reports `Canceled`, so one backend await that misses
//! the token cannot break the 2 s bound.

use netvfs_vfs::{CancelToken, Status};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

/// Worker threads.
pub const WORKERS: usize = 2;
/// Worker thread name prefix.
pub const THREAD_PREFIX: &str = "nvr-io-";
/// Time a call may run on after its token tripped.
pub const GRACE: Duration = Duration::from_secs(1);

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

fn build() -> Result<Runtime, String> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .thread_name_fn(|| format!("{THREAD_PREFIX}{}", NEXT.fetch_add(1, Ordering::Relaxed)))
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn runtime() -> Result<&'static Runtime, Status> {
    RUNTIME
        .get_or_init(build)
        .as_ref()
        .map_err(|e| Status::internal(format!("Cannot start the Rust backend runtime: {e}")))
}

fn drive<T>(cancel: &CancelToken, work: impl Future<Output = T>) -> Result<Option<T>, Status> {
    Ok(runtime()?.block_on(async {
        let mut work = pin!(work);
        let mut cut = pin!(async {
            cancel.canceled().await;
            tokio::time::sleep(GRACE).await;
        });
        poll_fn(|cx| {
            if let Poll::Ready(value) = work.as_mut().poll(cx) {
                return Poll::Ready(Some(value));
            }
            if cut.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await
    }))
}

/// `Canceled` at once if `cancel` is tripped, else `work`'s result, or `Canceled` if it runs [`GRACE`] past a cancel.
///
/// # Errors
/// `work`'s error, `Canceled`, or `Internal` without a runtime.
pub fn run<T>(cancel: &CancelToken, work: impl Future<Output = Result<T, Status>>) -> Result<T, Status> {
    cancel.check()?;
    drive(cancel, work)?.unwrap_or_else(|| Err(Status::canceled()))
}

/// Teardown: runs even when `cancel` is tripped; dropped [`GRACE`] after a cancel, not run without a runtime.
pub fn finish(cancel: &CancelToken, work: impl Future<Output = ()>) {
    drop(drive(cancel, work));
}

#[cfg(test)]
mod tests {
    use super::*;
    use netvfs_vfs::ErrorName;
    use std::time::Instant;

    #[test]
    fn run_passes_results_and_refuses_when_tripped() {
        let token = CancelToken::new();
        assert_eq!(run(&token, async { Ok(4) }), Ok(4));
        let failed = run(&token, async { Err::<(), _>(Status::new(ErrorName::NotFound, "x")) });
        assert_eq!(failed.map_err(|s| s.name), Err(ErrorName::NotFound));
        token.cancel();
        let mut started = false;
        let r = run(&token, async {
            started = true;
            Ok(())
        });
        assert_eq!(r, Err(Status::canceled()));
        assert!(!started);
    }

    #[test]
    fn a_call_that_ignores_the_token_is_cut_after_the_grace() {
        let token = CancelToken::new();
        let canceler = token.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            canceler.cancel();
            Instant::now()
        });
        let r = run(&token, std::future::pending::<Result<(), Status>>());
        let returned = Instant::now();
        let canceled = t.join().unwrap();
        assert_eq!(r, Err(Status::canceled()));
        let after = returned.duration_since(canceled);
        assert!(after >= GRACE, "{after:?}");
        assert!(after < Duration::from_secs(2), "{after:?}");
    }

    #[test]
    fn finish_runs_when_tripped_and_is_cut_after_the_grace() {
        let token = CancelToken::new();
        token.cancel();
        let mut ran = false;
        finish(&token, async { ran = true });
        assert!(ran);
        let started = Instant::now();
        finish(&token, std::future::pending::<()>());
        let took = started.elapsed();
        assert!(took >= GRACE && took < Duration::from_secs(2), "{took:?}");
    }

    #[test]
    fn calls_run_on_the_callers_thread_and_the_workers_have_names() {
        let caller = std::thread::current().id();
        let token = CancelToken::new();
        let (on_caller, worker) = run(&token, async {
            let here = std::thread::current().id() == caller;
            let worker = tokio::spawn(async { std::thread::current().name().map(str::to_owned) })
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            Ok((here, worker))
        })
        .unwrap();
        assert!(on_caller);
        let name = worker.unwrap();
        assert!(name.starts_with(THREAD_PREFIX), "{name}");
    }
}
