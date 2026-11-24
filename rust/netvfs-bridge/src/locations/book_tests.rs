// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Arc, Duration, ErrorName, Instant, Lane, LocationBook, LocationSpec, PoolSet, Turn, WorkerId, no_backend,
    no_consent, no_such_location, not_allowed,
};
use crate::ffi::{Params, Value};
use crate::locations::mock::{Mock, MockHandle, Seen, blocking, recv, reporting, task};
use crate::locations::spec::Attention;
use crate::locations::state::ConnectionState;
use std::sync::mpsc;

fn book() -> (Arc<Mock>, LocationBook<Mock>) {
    let mock = Mock::new();
    (Arc::clone(&mock), LocationBook::new(PoolSet::new(mock, 4)))
}

fn params(host: &str) -> Params {
    Params { provider: "fake".into(), host: host.into(), port: 22, username: "u".into(), ..Params::default() }
}

fn account(n: i32, host: &str) -> LocationSpec {
    LocationSpec::account(n, "fake", format!("Acc {n}"), params(host), b"/root".to_vec(), Attention::None)
}

type Change = fn(&mut Params);

fn available(_: &str) -> bool {
    true
}

fn ids(book: &LocationBook<Mock>) -> Vec<String> {
    book.visible().map(|s| s.id.clone()).collect()
}

fn pool_ids(book: &LocationBook<Mock>) -> Vec<String> {
    book.pools().iter().map(|p| p.spec().id.clone()).collect()
}

#[test]
fn errors_name_the_problem() {
    assert_eq!(no_consent().name, ErrorName::PermissionDenied);
    assert_eq!(no_consent().message, "The user has not decided yet what this app may do");
    assert_eq!(
        (not_allowed().name, not_allowed().message.as_str(), not_allowed().detail.as_str()),
        (ErrorName::PermissionDenied, "The user has not allowed this app to use this account", "denied")
    );
    assert_eq!(
        (no_such_location().name, no_such_location().message.as_str()),
        (ErrorName::NotFound, "No such location")
    );
    assert_eq!(no_backend("smb").name, ErrorName::Unsupported);
    assert_eq!(no_backend("smb").message, "No backend for smb is installed");
}

#[test]
fn pools_need_consent_a_visible_location_and_a_backend() {
    let (_mock, mut book) = book();
    book.set_accounts(vec![account(1, "a"), account(2, "b")]);
    assert_eq!(ids(&book), ["account:1", "account:2"]);
    assert_eq!(book.find("account:2").unwrap().name, "Acc 2");
    assert!(book.find("account:3").is_none());

    assert_eq!(
        book.ensure_pool("account:1", false, available).unwrap_err().name,
        ErrorName::PermissionDenied
    );
    assert_eq!(book.ensure_pool("account:3", true, available).unwrap_err().name, ErrorName::NotFound);
    let missing = book.ensure_pool("account:1", true, |p| {
        assert_eq!(p, "fake");
        false
    });
    assert_eq!(missing.unwrap_err().name, ErrorName::Unsupported);
    assert!(!book.has_pool("account:1"));
    assert_eq!(book.ensure_pool("account:1", true, available).unwrap().id, "account:1");
    assert!(book.has_pool("account:1"));
    assert!(book.ensure_pool("account:1", true, |_| panic!("asked again")).is_ok());
    assert_eq!(
        book.ensure_pool("account:1", false, available).unwrap_err().name,
        ErrorName::PermissionDenied
    );
    assert_eq!(pool_ids(&book), ["account:1"]);
    assert!(format!("{book:?}").contains("accounts: 2"));
}

#[test]
fn changed_and_removed_accounts_lose_their_pools() {
    let (_mock, mut book) = book();
    book.set_accounts(vec![account(1, "a"), account(2, "b"), account(3, "c"), account(4, "d")]);
    for id in ["account:1", "account:2", "account:3", "account:4"] {
        assert!(book.ensure_pool(id, true, available).is_ok());
    }
    let mut renamed = account(1, "a");
    renamed.name = "Renamed".into();
    let mut optioned = account(3, "c");
    optioned.params.options.insert("x".into(), Value::Bool(true));
    let mut timeouts = account(4, "d");
    timeouts.params.connect_timeout_ms = 5;
    book.set_accounts(vec![renamed, optioned, timeouts, account(5, "e")]);
    assert_eq!(pool_ids(&book), ["account:1", "account:4"]);
    assert_eq!(book.find("account:1").unwrap().name, "Renamed");
    assert_eq!(ids(&book), ["account:1", "account:3", "account:4", "account:5"]);
    let changes: [(&str, Change); 4] = [
        ("provider", |p| p.provider = "x".into()),
        ("host", |p| p.host = "other".into()),
        ("port", |p| p.port = 23),
        ("user", |p| p.username = "v".into()),
    ];
    for (field, change) in changes {
        assert!(book.ensure_pool("account:1", true, available).is_ok());
        let mut changed = account(1, "a");
        change(&mut changed.params);
        book.set_accounts(vec![changed]);
        assert!(!book.has_pool("account:1"), "{field} changed");
        book.set_accounts(vec![account(1, "a")]);
    }
}

#[test]
fn identity_attention_keeps_the_pool_and_its_work() {
    let (mock, mut book) = book();
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    let (tx, rx) = mpsc::channel();
    mock.hold_establish(true);
    book.submit("account:1", Lane::Interactive, task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 1", 1);
    let mut flagged = account(1, "a");
    flagged.attention = Attention::ServerIdentityChanged;
    flagged.params.options.insert("host_key_seen".into(), Value::Str("ssh-ed25519 new".into()));
    book.set_accounts(vec![flagged]);
    assert_eq!(pool_ids(&book), ["account:1"]);
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
}

#[test]
fn revoking_forgets_everything() {
    let (_mock, mut book) = book();
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    book.revoke();
    assert!(book.pools().iter().next().is_none());
    assert_eq!(ids(&book), ["account:1"], "accounts stay; the consumer cannot use them without consent");
}

#[test]
fn work_runs_on_the_locations_connections() {
    let (mock, mut book) = book();
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    let (tx, rx) = mpsc::channel();
    book.submit("account:1", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    book.submit("account:9", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::NotFound));

    let (wtx, wrx) = mpsc::channel();
    let handle_mock = Arc::clone(&mock);
    book.submit(
        "account:1",
        Lane::Interactive,
        task(),
        Box::new(move |turn: Turn<'_, Mock>| {
            let id = turn.handles.unwrap().add(MockHandle::new(&handle_mock, "h1"));
            wtx.send((turn.worker.unwrap(), id)).unwrap();
            Ok(())
        }),
    );
    let (worker, handle) = wrx.recv().unwrap();
    book.close_worker_handle("account:2", worker, handle);
    book.close_worker_handle("account:1", WorkerId(u64::MAX), handle);
    book.close_worker_handle("account:1", worker, handle + 1);
    book.submit_to("account:1", worker, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    assert_eq!(mock.count("close"), 0);
    book.close_worker_handle("account:1", worker, handle);
    mock.wait_for("close h1", 1);
    book.submit_to("account:1", WorkerId(u64::MAX), task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::ConnectionLost));

    book.disconnect("account:9");
    assert_eq!(mock.count("free"), 0);
    book.disconnect("account:1");
    mock.wait_for("free 1", 1);
    book.kick();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut changed = false;
    while book.pools().closing() > 0 {
        assert!(Instant::now() < deadline);
        changed |= book.maintain(Instant::now(), Duration::from_mins(1));
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(changed, "the stopped connection was freed");
}

#[test]
fn kick_cancels_running_work_whose_flag_is_set() {
    let (mock, mut book) = book();
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    let (tx, rx) = mpsc::channel();
    let (_go, wait) = mpsc::channel();
    let flagged = task();
    book.submit("account:1", Lane::Interactive, flagged.clone(), blocking(&tx, wait, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    flagged.cancel.store(true, std::sync::atomic::Ordering::Release);
    book.kick();
    mock.wait_for("cancel 1", 1);
    mock.wait_for("free 1", 1);
}

#[test]
fn states_of_what_list_locations_shows() {
    use ConnectionState::{Connected, Disconnected};
    let (mock, mut book) = book();
    book.set_accounts(vec![account(1, "a"), account(2, "b")]);
    let states =
        |book: &LocationBook<Mock>| -> Vec<(String, ConnectionState)> { book.states().into_iter().collect() };
    let of = |list: &[(&str, ConnectionState)]| -> Vec<(String, ConnectionState)> {
        list.iter().map(|(id, state)| ((*id).to_owned(), *state)).collect()
    };
    assert!(book.ensure_pool("account:2", true, available).is_ok());
    assert_eq!(states(&book), of(&[("account:1", Disconnected), ("account:2", Disconnected)]));
    let (tx, rx) = mpsc::channel();
    mock.hold_establish(true);
    book.submit("account:2", Lane::Interactive, task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 1", 1);
    assert_eq!(book.state("account:2"), ConnectionState::Connecting);
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
    assert_eq!(states(&book), of(&[("account:1", Disconnected), ("account:2", Connected)]));
    book.disconnect("account:2");
    assert_eq!(book.state("account:2"), Disconnected);
    assert_eq!(book.state("account:9"), Disconnected);
}
