// SPDX-License-Identifier: LGPL-2.1-or-later
//! The shared contract (SPEC-v2 XT-7; C++ `tst_contract` introspection and
//! goldenSequences) against the `netvfs-bridge` binary with the C ABI and
//! the fake backend (design §4.2): the introspection it serves is the
//! contract's XML byte for byte, and every golden sequence of
//! `tests/bridge/contract` replays, each on a bridge of its own with the
//! fake accounts helper (account 1) and the sequence's files seeded through
//! `NETVFS_FAKE_SEED`. Without the C ABI (the variables of `tests/ffi.rs`)
//! the tests say they are skipped.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

use netvfs_bridge::consent::Consent;
use netvfs_bridge::testing::BridgeRun;
use netvfs_bridge::testutil::TestChild;
use netvfs_bridge_proto::OBJECT_PATH;
use netvfs_bridge_proto::fake::Consent as SeqConsent;
use netvfs_bridge_proto::fake::replay::{self, Sequence};
use std::path::{Path, PathBuf};

const BRIDGE: &str = env!("CARGO_BIN_EXE_netvfs-bridge");
const HELPER: &str = env!("CARGO_BIN_EXE_netvfs-accounts-fake");
const FFI_VARIABLES: [&str; 2] = ["NETVFS_BRIDGE_FFI", "NETVFS_BACKEND_PATH"];
const CONSUMER: &str = "contract";

/// Whether the C ABI is there; says the test is skipped when not.
fn have_ffi() -> bool {
    let missing = FFI_VARIABLES.iter().any(|v| std::env::var_os(v).is_none());
    if missing {
        println!("skipped: {} not set (make check-rust-ffi sets them)", FFI_VARIABLES.join(", "));
    }
    !missing
}

fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/bridge/contract")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

/// A bridge with the fake accounts helper and `consent`.
fn bridge(consent: Consent) -> BridgeRun {
    let mut run = BridgeRun::new(Path::new(BRIDGE), CONSUMER);
    run.with_consent(consent).with_fake_accounts(Path::new(HELPER));
    run
}

// tst_contract introspection.
#[test]
fn introspection_verbatim_and_ping() {
    if !have_ffi() {
        return;
    }
    let contract = std::fs::read(contract_dir().join("org.netvfs.Bridge1.xml")).unwrap();
    let mut run = bridge(Consent::Unknown);
    let _child = run.spawn();
    runtime().block_on(async {
        let c = run.client().await;
        let z = c.zbus();
        // Before Hello, and without consent: introspection is no protocol
        // call.
        for interface in [Some("org.freedesktop.DBus.Introspectable"), None] {
            let reply = z.call_method(None::<&str>, OBJECT_PATH, interface, "Introspect", &()).await.unwrap();
            let served: String = reply.body().deserialize().unwrap();
            assert!(served.as_bytes() == contract.as_slice(), "the served XML differs from the contract");
        }
        // Peer on any path.
        for path in [OBJECT_PATH, "/", "/other"] {
            let reply =
                z.call_method(None::<&str>, path, Some("org.freedesktop.DBus.Peer"), "Ping", &()).await;
            assert!(reply.unwrap().body().is_empty(), "{path}");
        }
        // Introspection of another object is no contract of ours.
        let other = z.call_method(None::<&str>, "/other", None::<&str>, "Introspect", &()).await;
        match other {
            Err(zbus::Error::MethodError(name, _, _)) => {
                assert_eq!(name.as_str(), "org.freedesktop.DBus.Error.UnknownMethod");
            }
            other => panic!("{other:?}"),
        }
        c.close().await;
    });
}

fn consent_of(seq: &Sequence) -> Consent {
    match seq.consent {
        SeqConsent::Unknown => Consent::Unknown,
        SeqConsent::Granted => Consent::Granted,
        SeqConsent::Denied => Consent::Denied,
    }
}

/// Replays `seq` on a bridge of its own: the consent and the files of the
/// sequence, on the server of account 1.
async fn replay_on_the_binary(seq: &Sequence) -> Result<(), String> {
    let mut run = BridgeRun::new(Path::new(BRIDGE), CONSUMER);
    let socket = run.socket.clone();
    let mut child: Option<TestChild> = None;
    let outcome = replay::replay_sequence(
        seq,
        async |seq: &Sequence| {
            let files: Vec<(Vec<u8>, &[u8])> = seq
                .files
                .iter()
                .map(|(path, content)| (format!("/{path}").into_bytes(), content.as_bytes()))
                .collect();
            let files: Vec<(&[u8], &[u8])> =
                files.iter().map(|(path, content)| (path.as_slice(), *content)).collect();
            run.with_consent(consent_of(seq)).with_fake_accounts(Path::new(HELPER)).with_files(&files);
            child = Some(run.spawn());
            Ok(())
        },
        async || netvfs_bridge_proto::connect(&socket).await.map_err(|e| e.to_string()),
    )
    .await;
    drop(child);
    outcome.map_err(|e| format!("{e}\n--- netvfs-bridge's stderr:\n{}", run.log()))
}

// tst_contract goldenSequences.
#[test]
fn golden_sequences() {
    if !have_ffi() {
        return;
    }
    let sequences = replay::load_dir(&contract_dir()).unwrap();
    let on_disk = std::fs::read_dir(contract_dir())
        .unwrap()
        .filter(|e| e.as_ref().is_ok_and(|e| e.path().extension().is_some_and(|x| x == "json")))
        .count();
    assert_eq!(sequences.len(), on_disk);
    assert!(sequences.len() >= 6, "{}", sequences.len());
    let rt = runtime();
    for (name, seq) in &sequences {
        if let Err(e) = rt.block_on(replay_on_the_binary(seq)) {
            panic!("{name}: {} ({e})", seq.description);
        }
    }
}
