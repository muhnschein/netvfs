// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    AccountAccess, AtomicBool, Attention, Duration, ErrorName, EstablishError, Instant, Ordering, Params,
    Phase, Status, Value, WAIT_SLICE, Waited, account_pin, attention_for, mpsc, wait_for,
};
use std::sync::Arc;
use std::thread;

#[test]
fn waits_end_with_a_value_a_cancel_a_timeout_or_a_gone_core() {
    let flag = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel();
    tx.send(1).unwrap();
    flag.store(true, Ordering::Release);
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::Got(1));
    assert_eq!(wait_for(&rx, &flag, Duration::from_secs(5)), Waited::Canceled);
    flag.store(false, Ordering::Release);
    let start = Instant::now();
    assert_eq!(wait_for(&rx, &flag, Duration::from_millis(250)), Waited::TimedOut);
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(250) && waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(wait_for(&rx, &flag, Duration::ZERO), Waited::TimedOut);
    let later = tx.clone();
    let sender = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        later.send(2).unwrap();
    });
    assert_eq!(wait_for(&rx, &flag, Duration::MAX), Waited::Got(2));
    sender.join().unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    let canceler = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        setter.store(true, Ordering::Release);
    });
    let start = Instant::now();
    assert_eq!(wait_for(&rx, &flag, Duration::from_secs(10)), Waited::Canceled);
    assert!(start.elapsed() < WAIT_SLICE * 4, "{:?}", start.elapsed());
    canceler.join().unwrap();
    drop(tx);
    assert_eq!(wait_for(&rx, &AtomicBool::new(false), Duration::from_secs(10)), Waited::Gone);
    let (tx, rx) = mpsc::channel::<u8>();
    let dropper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        drop(tx);
    });
    assert_eq!(wait_for(&rx, &AtomicBool::new(false), Duration::from_secs(10)), Waited::Gone);
    dropper.join().unwrap();
}

#[test]
fn attention_after_a_failed_account_connection() {
    let failed = |phase, name| EstablishError { phase, status: Status::new(name, "x") };
    for phase in [Phase::Identity, Phase::Authenticate] {
        assert_eq!(
            attention_for(&failed(phase, ErrorName::AuthFailed), "pin"),
            Some((Attention::AuthFailed, String::new()))
        );
        assert_eq!(
            attention_for(&failed(phase, ErrorName::ServerIdentityChanged), "pin"),
            Some((Attention::ServerIdentityChanged, "pin".to_owned()))
        );
        assert_eq!(
            attention_for(&failed(phase, ErrorName::ServerIdentityUnknown), "pin"),
            Some((Attention::ServerIdentityChanged, "pin".to_owned()))
        );
        assert_eq!(attention_for(&failed(phase, ErrorName::Timeout), "pin"), None);
    }
    for phase in [Phase::Connect, Phase::Credentials, Phase::Done] {
        assert_eq!(attention_for(&failed(phase, ErrorName::AuthFailed), "pin"), None);
        assert_eq!(attention_for(&failed(phase, ErrorName::ServerIdentityChanged), "pin"), None);
    }
}

#[test]
fn account_pins_come_from_host_key() {
    let mut params = Params::default();
    assert_eq!(account_pin(&params), "");
    params.options.insert("host_key".into(), Value::Str("ssh-ed25519 AAAA".into()));
    assert_eq!(account_pin(&params), "ssh-ed25519 AAAA");
    params.options.insert("host_key".into(), Value::Bytes(b"ssh-rsa BBBB".to_vec()));
    assert_eq!(account_pin(&params), "ssh-rsa BBBB");
    params.options.insert("host_key".into(), Value::Int(1));
    assert_eq!(account_pin(&params), "");
}

#[test]
fn files_answers_become_account_access() {
    use crate::accounts::{ConnectionParams, FilesAccess, Value as Helper};
    let access = AccountAccess::from(FilesAccess {
        params: ConnectionParams {
            provider: "sftp".into(),
            host: "h".into(),
            options: vec![("host_key".into(), Helper::String("pin".into()))],
            ..ConnectionParams::default()
        },
        credentials_id: 9,
        secret_optional: true,
    });
    assert_eq!((access.credentials_id, access.secret_optional), (9, true));
    assert_eq!((access.params.provider.as_str(), access.params.host.as_str()), ("sftp", "h"));
    assert_eq!(account_pin(&access.params), "pin");
}
