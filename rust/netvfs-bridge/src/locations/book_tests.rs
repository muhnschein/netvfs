// SPDX-License-Identifier: LGPL-2.1-or-later
// The location book (locationbook.cpp): accounts, ad-hoc locations, pools.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Arc, Duration, ErrorName, Instant, Lane, LocationBook, LocationSpec, PinStore, PoolSet, Turn, WorkerId,
    no_backend, no_consent, no_such_location,
};
use crate::ffi::{Params, Value};
use crate::locations::mock::{Mock, MockHandle, Seen, blocking, recv, reporting, task};
use crate::locations::spec::{AdHocSecret, Attention};
use std::sync::{Mutex, mpsc};
use zeroize::Zeroizing;

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

fn ad_hoc(book: &mut LocationBook<Mock>, host: &str, secret: &[u8]) -> (String, Arc<AdHocSecret>) {
    let id = book.reserve_ad_hoc_id();
    let secret = AdHocSecret::new("u", Zeroizing::new(secret.to_vec()));
    let spec = LocationSpec::ad_hoc(&id, host, params(host), Vec::new(), Some(Arc::clone(&secret)));
    assert!(book.start_ad_hoc(spec));
    (id, secret)
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

#[derive(Default)]
struct Pins(Mutex<Vec<String>>);

impl PinStore for Pins {
    fn pin(&self, _key: &str) -> String {
        String::new()
    }
    fn set_pin(&self, _key: &str, _pin: &str) -> bool {
        true
    }
    fn remove(&self, key: &str) -> bool {
        self.0.lock().unwrap().push(key.to_owned());
        true
    }
}

#[test]
fn errors_name_the_problem() {
    assert_eq!(no_consent().name, ErrorName::PermissionDenied);
    assert_eq!(no_consent().message, "The user has not allowed this app to use network locations");
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
    // An existing pool needs no backend check, but still consent.
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
    let (adhoc, _) = ad_hoc(&mut book, "a", b"s");
    assert!(book.add_ad_hoc(&adhoc));
    let mut renamed = account(1, "a");
    renamed.name = "Renamed".into();
    let mut optioned = account(3, "c");
    optioned.params.options.insert("x".into(), Value::Bool(true));
    let mut timeouts = account(4, "d");
    timeouts.params.connect_timeout_ms = 5;
    book.set_accounts(vec![renamed, optioned, timeouts, account(5, "e")]);
    // 1: same connection, kept; 2: removed; 3: other options; 4: only the
    // timeouts differ, kept; the ad-hoc pool stays.
    assert_eq!(pool_ids(&book), ["account:1", "account:4", &adhoc]);
    assert_eq!(book.find("account:1").unwrap().name, "Renamed");
    assert_eq!(ids(&book), ["account:1", "account:3", "account:4", "account:5", &adhoc]);
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
fn ad_hoc_locations_appear_once_connected() {
    let (_mock, mut book) = book();
    let (first, secret) = ad_hoc(&mut book, "h", b"pw");
    // `adhoc:<run>-<n>`: 16 hex digits of this run, then the count from 1.
    let run = first.strip_prefix("adhoc:").and_then(|id| id.strip_suffix("-1")).unwrap();
    assert!(
        run.len() == 16 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{first}"
    );
    // Connecting: the pool exists, nobody sees it.
    assert_eq!(pool_ids(&book), [first.as_str()]);
    assert_eq!(ids(&book).len(), 0);
    assert!(book.find(&first).is_none());
    assert!(!book.has_pool(&first));
    assert_eq!(book.ensure_pool(&first, true, available).unwrap_err().name, ErrorName::NotFound);
    assert!(format!("{book:?}").contains("connecting: 1"));
    // Taken ids and accounts cannot start.
    let again = LocationSpec::ad_hoc(&first, "h", params("h"), Vec::new(), None);
    assert!(!book.start_ad_hoc(again));
    assert!(!book.start_ad_hoc(account(9, "h")));
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    let mut clash = LocationSpec::ad_hoc("account:1", "h", params("h"), Vec::new(), None);
    assert!(!book.start_ad_hoc(clash.clone()));
    clash.id = "adhoc:99".into();
    assert!(book.pools_mut().add(Arc::new(account(7, "x"))));
    clash.id = "account:7".into();
    assert!(!book.start_ad_hoc(clash), "a pool with that id exists");

    assert!(book.add_ad_hoc(&first));
    assert!(!book.add_ad_hoc(&first), "only once");
    assert_eq!(ids(&book), ["account:1", first.as_str()]);
    assert!(book.has_pool(&first));
    assert_eq!(&*secret.secret(), b"pw");

    let (second, secret2) = ad_hoc(&mut book, "h2", b"pw2");
    assert_eq!(second, format!("adhoc:{run}-2"));
    book.abandon_ad_hoc(&second);
    assert!(secret2.secret().is_empty(), "wiped");
    assert!(book.pools().get(&second).is_none());
    assert!(!book.add_ad_hoc(&second));
    book.abandon_ad_hoc(&first);
    assert!(book.has_pool(&first), "only connecting ones are abandoned");
    assert_eq!(book.reserve_ad_hoc_id(), format!("adhoc:{run}-3"));
}

#[test]
fn a_restarted_bridge_never_gives_an_earlier_ad_hoc_id_again() {
    // The bridge forgets its ad-hoc locations when it exits (XB-2), but a
    // consumer may still hold their ids (URIs on its clipboard): a new run
    // must not hand them out again, or they would name another server.
    let (_mock, mut earlier) = book();
    let old: Vec<String> = (0..3).map(|_| earlier.reserve_ad_hoc_id()).collect();
    drop(earlier);
    let (_mock, mut restarted) = book();
    for _ in 0..3 {
        let id = restarted.reserve_ad_hoc_id();
        assert!(!old.contains(&id), "{id} was given out by the earlier run");
    }
}

#[test]
fn a_location_revoked_while_connecting_is_not_added() {
    let (_mock, mut book) = book();
    let (id, secret) = ad_hoc(&mut book, "h", b"pw");
    book.revoke();
    assert!(secret.secret().is_empty());
    assert!(!book.add_ad_hoc(&id));
    // Gone from the pools but still connecting: not added either.
    let (id, _) = ad_hoc(&mut book, "h", b"pw");
    assert!(book.pools_mut().remove(&id));
    assert!(!book.add_ad_hoc(&id));
    assert_eq!(ids(&book).len(), 0);
}

#[test]
fn forgetting_drops_the_pin_the_secret_and_the_pool() {
    let (_mock, mut book) = book();
    let pins = Pins::default();
    let (id, secret) = ad_hoc(&mut book, "Host", b"pw");
    assert!(!book.forget_ad_hoc(&id, &pins), "not visible yet");
    assert!(book.add_ad_hoc(&id));
    let (other, other_secret) = ad_hoc(&mut book, "o", b"x");
    assert!(book.add_ad_hoc(&other));
    assert!(book.forget_ad_hoc(&id, &pins));
    assert_eq!(*pins.0.lock().unwrap(), ["fake://host:22"]);
    assert!(secret.secret().is_empty());
    assert!(book.pools().get(&id).is_none());
    assert_eq!(ids(&book), [other.as_str()]);
    assert!(!book.forget_ad_hoc(&id, &pins));
    assert_eq!(&*other_secret.secret(), b"x");
    drop(book);
    assert!(other_secret.secret().is_empty(), "dropping the book wipes the secrets");
}

#[test]
fn revoking_forgets_everything() {
    let (_mock, mut book) = book();
    book.set_accounts(vec![account(1, "a")]);
    assert!(book.ensure_pool("account:1", true, available).is_ok());
    let (id, secret) = ad_hoc(&mut book, "h", b"pw");
    assert!(book.add_ad_hoc(&id));
    book.revoke();
    assert!(book.pools().iter().next().is_none());
    assert!(secret.secret().is_empty());
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

    // A read handle opened on a connection, then closed through the book.
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

    // Disconnect stops the connections; an unknown id does nothing.
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
    // The item ended canceled: its connection goes.
    mock.wait_for("free 1", 1);
}

#[test]
fn a_connecting_ad_hoc_location_takes_no_disconnect_or_handle_close() {
    let (mock, mut book) = book();
    let (id, _) = ad_hoc(&mut book, "h", b"pw");
    let (tx, rx) = mpsc::channel();
    let handle_mock = Arc::clone(&mock);
    book.submit(
        &id,
        Lane::Interactive,
        task(),
        Box::new(move |turn: Turn<'_, Mock>| {
            let n = turn.handles.unwrap().add(MockHandle::new(&handle_mock, "h"));
            tx.send((turn.worker.unwrap(), n)).unwrap();
            Ok(())
        }),
    );
    let (worker, handle) = rx.recv().unwrap();
    book.disconnect(&id);
    book.close_worker_handle(&id, worker, handle);
    assert!(book.pools().owns(&id, worker));
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(mock.count("close"), 0);
    assert_eq!(mock.count("free"), 0);
}
