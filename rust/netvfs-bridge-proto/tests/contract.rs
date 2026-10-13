// SPDX-License-Identifier: LGPL-2.1-or-later
//! The shared contract (SPEC-v2 XT-7, C++ `tst_contract`): the crate's copy
//! of the introspection XML equals the contract copy and the C++ bridge's,
//! the method table and the signals match the XML, and the golden sequences
//! replay against the fake bridge.
// Test helpers outside #[test] functions: a failing test is the point.
#![allow(clippy::unwrap_used, clippy::panic)]

use netvfs_bridge_proto::methods::{ENTRY_SIGNATURE, INTROSPECTION_XML};
use netvfs_bridge_proto::{INTERFACE, METHODS, SIGNALS};
use std::path::{Path, PathBuf};

fn source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn contract_dir() -> PathBuf {
    source_dir().join("tests/bridge/contract")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A method or signal of the XML: name, input (or signal) signature, output signature.
#[derive(Debug, PartialEq, Eq)]
struct Member {
    name: String,
    input: String,
    output: String,
}

/// The methods and the signals of `org.netvfs.Bridge1`, in document order.
/// One element per line, as in the contract file.
fn members(xml: &str) -> (Vec<Member>, Vec<Member>) {
    fn attr<'a>(line: &'a str, name: &str) -> Option<&'a str> {
        let (_, rest) = line.split_once(&format!(" {name}=\""))?;
        rest.split_once('"').map(|(value, _)| value)
    }
    let (mut methods, mut signals) = (Vec::new(), Vec::<Member>::new());
    let mut in_bridge = false;
    // Some(true): inside a method, Some(false): inside a signal.
    let mut current: Option<bool> = None;
    for line in xml.lines().map(str::trim) {
        if line.starts_with("<interface") {
            in_bridge = attr(line, "name") == Some(INTERFACE);
        } else if in_bridge && (line.starts_with("<method") || line.starts_with("<signal")) {
            let is_method = line.starts_with("<method");
            let member = Member {
                name: attr(line, "name").unwrap().to_owned(),
                input: String::new(),
                output: String::new(),
            };
            if is_method {
                methods.push(member);
            } else {
                signals.push(member);
            }
            current = (!line.ends_with("/>")).then_some(is_method);
        } else if line.starts_with("</method") || line.starts_with("</signal") {
            current = None;
        } else if in_bridge && line.starts_with("<arg") {
            let ty = attr(line, "type").unwrap();
            let target = match current {
                Some(true) => methods.last_mut().unwrap(),
                Some(false) => signals.last_mut().unwrap(),
                None => panic!("an arg outside a method or signal: {line}"),
            };
            match attr(line, "direction") {
                Some("out") => target.output.push_str(ty),
                _ => target.input.push_str(ty),
            }
        }
    }
    (methods, signals)
}

// tst_contract contractCopyIsCurrent: the XML the bridge serves, the contract
// copy and the C++ bridge's copy must not drift.
#[test]
fn xml_copy_is_current() {
    let contract = read(&contract_dir().join("org.netvfs.Bridge1.xml"));
    assert!(
        INTROSPECTION_XML == contract,
        "rust/netvfs-bridge-proto/org.netvfs.Bridge1.xml differs from the contract"
    );
    let cpp = read(&source_dir().join("src/bridge/lib/org.netvfs.Bridge1.xml"));
    assert!(cpp == contract, "src/bridge/lib/org.netvfs.Bridge1.xml differs from the contract");
}

// tst_contract methodTableMatchesXml, and the order of args.cpp, which is the
// order of the XML.
#[test]
fn method_table_matches_xml() {
    let (xml, _) = members(INTROSPECTION_XML);
    let table: Vec<Member> = METHODS
        .iter()
        .map(|m| Member { name: m.name.to_owned(), input: m.input.to_owned(), output: m.output.to_owned() })
        .collect();
    assert_eq!(table, xml);
    assert_eq!(table.len(), 35);
}

#[test]
fn signals_match_xml() {
    let (_, xml) = members(INTROSPECTION_XML);
    let xml: Vec<(&str, &str)> = xml
        .iter()
        .map(|s| {
            assert!(s.output.is_empty(), "signal {} has an out argument", s.name);
            (s.name.as_str(), s.input.as_str())
        })
        .collect();
    assert_eq!(xml, SIGNALS);
    let list_batch = SIGNALS.iter().find(|(name, _)| *name == "ListBatch").unwrap().1;
    assert_eq!(list_batch, format!("ua{ENTRY_SIGNATURE}"));
}

#[test]
fn the_xml_reader_follows_methods_and_signals_of_the_interface_only() {
    let xml = r#"
        <interface name="org.netvfs.Bridge1">
          <method name="A">
            <arg name="x" type="s" direction="in"/>
            <arg name="y" type="u" direction="out"/>
            <arg name="z" type="ay" direction="in"/>
          </method>
          <method name="B"/>
          <signal name="S">
            <arg name="q" type="s"/>
          </signal>
        </interface>
        <interface name="org.other">
          <method name="C">
            <arg type="s" direction="in"/>
          </method>
        </interface>"#;
    let (methods, signals) = members(xml);
    let m = |name: &str, input: &str, output: &str| Member {
        name: name.to_owned(),
        input: input.to_owned(),
        output: output.to_owned(),
    };
    assert_eq!(methods, [m("A", "say", "u"), m("B", "", "")]);
    assert_eq!(signals, [m("S", "s", "")]);
}

#[cfg(feature = "fake")]
mod fake {
    use super::{contract_dir, members, read};
    use netvfs_bridge_proto::fake::{FakeBridge, replay};

    // tst_contract goldenSequences, against the fake (as lautta runs them).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fake_replays() {
        let ran = replay::replay_dir(&contract_dir()).await.unwrap();
        let on_disk = std::fs::read_dir(contract_dir())
            .unwrap()
            .filter(|e| e.as_ref().is_ok_and(|e| e.path().extension().is_some_and(|x| x == "json")))
            .count();
        assert_eq!(ran.len(), on_disk);
        assert!(ran.len() >= 6, "{ran:?}");
    }

    // The fake's generated introspection has the members of the contract.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_fake_serves_the_contract_interface() {
        let fake = FakeBridge::new();
        let conn = fake.connect().await.unwrap();
        let reply = conn
            .zbus()
            .call_method(
                None::<&str>,
                "/org/netvfs/Bridge",
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .unwrap();
        let served: String = reply.body().deserialize().unwrap();
        // zbus orders the members its own way.
        let sorted = |xml: &str| {
            let (mut methods, mut signals) = members(xml);
            methods.sort_by(|a, b| a.name.cmp(&b.name));
            signals.sort_by(|a, b| a.name.cmp(&b.name));
            (methods, signals)
        };
        let want = sorted(&read(&contract_dir().join("org.netvfs.Bridge1.xml")));
        assert_eq!(want.0.len(), 35);
        assert_eq!(sorted(&served), want);
    }
}
