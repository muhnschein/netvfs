// SPDX-License-Identifier: LGPL-2.1-or-later
// Client against a fake UDisks2 on a private bus, describing the phone of `sample`; mounts below /run/media/user.
#![allow(clippy::arithmetic_side_effects)]

use super::{Bus, CALL_TIMEOUT, DEBOUNCE, ERROR_PREFIX, MANAGER, SERVICE, UDisks, error_name};
use crate::drives::DriveSource;
use crate::drives::classify::{BLOCK_DEVICES, Drive, FILESYSTEM, ManagedObjects};
use crate::drives::sample::{CARD, device, luks, owned, phone, set, unlock};
use crate::testutil::TestBus;
use futures_lite::StreamExt;
use netvfs_bridge_proto::{ErrorName, value_bool};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};
use zbus::message::{Message, Type as MessageType};
use zbus::names::BusName;
use zbus::zvariant::{OwnedValue, Value};
use zbus::{Connection, MessageStream};

const QUIET: Duration = Duration::from_millis(600);

#[derive(Debug, Default)]
struct State {
    mounted: HashMap<String, String>,
    gone: Vec<String>,
    calls: Vec<(String, String, bool)>,
    error: Option<(String, String)>,
    silent: bool,
    luks: Option<bool>,
}

struct FakeUDisks {
    conn: Connection,
    state: Rc<RefCell<State>>,
}

impl FakeUDisks {
    async fn start(bus: &TestBus) -> Self {
        let conn = bus.connect().await;
        let mut calls = MessageStream::from(&conn);
        conn.request_name(SERVICE).await.unwrap();
        let state = Rc::new(RefCell::new(State::default()));
        let (served, replies) = (Rc::clone(&state), conn.clone());
        tokio::task::spawn_local(async move {
            while let Some(Ok(msg)) = calls.next().await {
                if msg.message_type() == MessageType::MethodCall {
                    answer(&replies, &served, &msg).await;
                }
            }
        });
        Self { conn, state }
    }

    fn calls(&self) -> Vec<(String, String, bool)> {
        self.state.borrow().calls.clone()
    }

    async fn emit(&self, id: &str) {
        let changed: HashMap<&str, Value<'_>> = HashMap::new();
        let path = format!("{BLOCK_DEVICES}{id}");
        let body = (FILESYSTEM, changed, Vec::<&str>::new());
        let interface = "org.freedesktop.DBus.Properties";
        self.conn
            .emit_signal(None::<BusName<'_>>, path.as_str(), interface, "PropertiesChanged", &body)
            .await
            .unwrap();
    }
}

fn objects(state: &State) -> ManagedObjects {
    let mut objects = phone();
    if let Some(unlocked) = state.luks {
        objects.insert(device("mmcblk1p2"), luks(CARD, "VAULT"));
        if unlocked {
            unlock(&mut objects, "mmcblk1p2", "dm_2d0", "SECRET");
        }
    }
    for id in &state.gone {
        objects.remove(&device(id));
    }
    for (id, point) in &state.mounted {
        if let Some(ifaces) = objects.get_mut(&device(id)) {
            let mut nul_terminated = point.clone().into_bytes();
            nul_terminated.push(0);
            set(ifaces, FILESYSTEM, "MountPoints", owned(vec![nul_terminated]));
        }
    }
    objects
}

async fn answer(conn: &Connection, state: &RefCell<State>, msg: &Message) {
    if state.borrow().silent {
        return;
    }
    let header = msg.header();
    let member = header.member().map(|m| m.as_str().to_owned()).unwrap_or_default();
    let path = header.path().map(|p| p.as_str().to_owned()).unwrap_or_default();
    if (path.as_str(), member.as_str()) == (MANAGER, "GetManagedObjects") {
        let objects = objects(&state.borrow());
        conn.reply(&header, &objects).await.unwrap();
        return;
    }
    let Some(id) = path.strip_prefix(BLOCK_DEVICES).map(str::to_owned) else {
        conn.reply_error(&header, "org.freedesktop.DBus.Error.UnknownObject", &("no",)).await.unwrap();
        return;
    };
    let (options,): (HashMap<String, OwnedValue>,) = msg.body().deserialize().unwrap();
    let quiet = options.get("auth.no_user_interaction").and_then(|v| value_bool(v)) == Some(true);
    state.borrow_mut().calls.push((member.clone(), id.clone(), quiet));
    let error = state.borrow_mut().error.take();
    if let Some((name, message)) = error {
        conn.reply_error(&header, name.as_str(), &(message,)).await.unwrap();
    } else if member == "Mount" {
        let point = format!("/run/media/user/{id}");
        state.borrow_mut().mounted.insert(id, point.clone());
        conn.reply(&header, &(point,)).await.unwrap();
    } else {
        state.borrow_mut().mounted.remove(&id);
        conn.reply(&header, &()).await.unwrap();
    }
}

fn run<F: Future>(test: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

fn client(bus: &TestBus, timeout: Duration, changes: &Rc<Cell<usize>>) -> UDisks {
    let changes = Rc::clone(changes);
    UDisks::new(Bus::Address(bus.address().to_owned()), timeout, move || {
        changes.set(changes.get() + 1);
        true
    })
}

fn ids(drives: &[Drive]) -> Vec<&str> {
    drives.iter().map(|d| d.id.as_str()).collect()
}

fn call(member: &str, id: &str) -> (String, String, bool) {
    (member.to_owned(), id.to_owned(), true)
}

async fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while !done() {
        if Instant::now() > end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

#[test]
fn listed_drives_are_mounted_and_unmounted_without_a_question() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let udisks = client(&bus, CALL_TIMEOUT, &Rc::default());
        let listed = udisks.list().await;
        assert_eq!(ids(&listed), ["mmcblk1p1", "sda1"]);
        assert!(listed.iter().all(|d| d.mount_point.is_empty()));
        assert_eq!(udisks.mount("sda1").await.unwrap(), b"/run/media/user/sda1");
        assert_eq!(udisks.mount("sda1").await.unwrap(), b"/run/media/user/sda1");
        assert_eq!(udisks.list().await[1].mount_point, b"/run/media/user/sda1");
        udisks.unmount("mmcblk1p1").await.unwrap();
        udisks.unmount("sda1").await.unwrap();
        assert_eq!(fake.calls(), [call("Mount", "sda1"), call("Unmount", "sda1")]);
        assert!(udisks.list().await.iter().all(|d| d.mount_point.is_empty()));
    });
}

#[test]
fn only_listed_drives_are_acted_on() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let udisks = client(&bus, CALL_TIMEOUT, &Rc::default());
        for id in ["mmcblk0p20", "sdz1"] {
            assert_eq!(udisks.mount(id).await.unwrap_err().name, ErrorName::NotFound, "{id}");
        }
        fake.state.borrow_mut().mounted.insert("mmcblk0p20".to_owned(), "/persist".to_owned());
        assert_eq!(udisks.unmount("mmcblk0p20").await.unwrap_err().name, ErrorName::NotFound);
        fake.state.borrow_mut().gone.push("sda1".to_owned());
        assert_eq!(udisks.mount("sda1").await.unwrap_err().name, ErrorName::NotFound);
        assert!(fake.calls().is_empty());
    });
}

#[test]
fn errors_of_udisks_keep_their_name_as_the_detail() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let udisks = client(&bus, CALL_TIMEOUT, &Rc::default());
        let cases = [
            ("org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain", ErrorName::PermissionDenied),
            ("org.freedesktop.UDisks2.Error.DeviceBusy", ErrorName::Locked),
            ("org.freedesktop.UDisks2.Error.Failed", ErrorName::Internal),
        ];
        for (name, expected) in cases {
            fake.state.borrow_mut().error = Some((name.to_owned(), "refused".to_owned()));
            let status = udisks.mount("mmcblk1p1").await.unwrap_err();
            assert_eq!((status.name, status.detail), (expected, format!("{name}: refused")));
        }
        assert!(udisks.list().await[0].mount_point.is_empty());
    });
}

#[test]
fn the_error_names() {
    let cases = [
        ("NotAuthorized", ErrorName::PermissionDenied),
        ("NotAuthorizedCanObtain", ErrorName::PermissionDenied),
        ("NotAuthorizedDismissed", ErrorName::PermissionDenied),
        ("OptionNotPermitted", ErrorName::PermissionDenied),
        ("DeviceBusy", ErrorName::Locked),
        ("Cancelled", ErrorName::Canceled),
        ("Timedout", ErrorName::Timeout),
        ("NotSupported", ErrorName::Unsupported),
        ("AlreadyMounted", ErrorName::AlreadyExists),
        ("NotMounted", ErrorName::NotFound),
        ("Failed", ErrorName::Internal),
    ];
    for (name, expected) in cases {
        assert_eq!(error_name(&format!("{ERROR_PREFIX}{name}")), expected, "{name}");
    }
    let bus = [
        ("ServiceUnknown", ErrorName::Unsupported),
        ("NameHasNoOwner", ErrorName::Unsupported),
        ("UnknownObject", ErrorName::NotFound),
        ("UnknownMethod", ErrorName::NotFound),
        ("UnknownInterface", ErrorName::NotFound),
        ("NoReply", ErrorName::Timeout),
        ("Timeout", ErrorName::Timeout),
        ("AccessDenied", ErrorName::PermissionDenied),
        ("Failed", ErrorName::Internal),
    ];
    for (name, expected) in bus {
        assert_eq!(error_name(&format!("org.freedesktop.DBus.Error.{name}")), expected, "{name}");
    }
    assert_eq!(error_name("org.example.NotMounted"), ErrorName::Internal);
}

#[test]
fn changes_are_told_once_drives_were_listed() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let changes = Rc::new(Cell::new(0));
        let udisks = client(&bus, CALL_TIMEOUT, &changes);
        udisks.mount("sda1").await.unwrap();
        fake.emit("sda1").await;
        tokio::time::sleep(QUIET).await;
        assert_eq!(changes.get(), 0);

        assert_eq!(udisks.list().await[1].mount_point, b"/run/media/user/sda1");
        fake.emit("mmcblk0p20").await;
        tokio::time::sleep(QUIET).await;
        assert_eq!(changes.get(), 0);

        udisks.unmount("sda1").await.unwrap();
        let first = Instant::now();
        for _ in 0..3 {
            fake.emit("sda1").await;
        }
        assert!(wait_for(|| changes.get() == 1).await);
        assert!(first.elapsed() >= DEBOUNCE);
        tokio::time::sleep(QUIET).await;
        assert_eq!(changes.get(), 1);

        fake.state.borrow_mut().gone.push("sda1".to_owned());
        fake.emit("sda1").await;
        assert!(wait_for(|| changes.get() == 2).await);

        fake.state.borrow_mut().gone.clear();
        assert_eq!(ids(&udisks.list().await), ["mmcblk1p1", "sda1"]);
        fake.emit("sda1").await;
        tokio::time::sleep(QUIET).await;
        assert_eq!(changes.get(), 2);
    });
}

#[test]
fn a_locked_drive_is_never_mounted_and_its_unlocking_is_told() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        fake.state.borrow_mut().luks = Some(false);
        let changes = Rc::new(Cell::new(0));
        let udisks = client(&bus, CALL_TIMEOUT, &changes);
        let listed = udisks.list().await;
        assert_eq!(ids(&listed), ["mmcblk1p1", "mmcblk1p2", "sda1"]);
        assert!(listed[1].locked && !listed[0].locked);
        let status = udisks.mount("mmcblk1p2").await.unwrap_err();
        assert_eq!(status.name, ErrorName::Unsupported);
        udisks.unmount("mmcblk1p2").await.unwrap();
        assert!(fake.calls().is_empty());

        fake.state.borrow_mut().luks = Some(true);
        fake.emit("mmcblk1p2").await;
        assert!(wait_for(|| changes.get() == 1).await);
        let listed = udisks.list().await;
        assert_eq!(ids(&listed), ["dm_2d0", "mmcblk1p1", "sda1"]);
        assert!(!listed[0].locked);

        fake.state.borrow_mut().luks = Some(false);
        fake.emit("dm_2d0").await;
        assert!(wait_for(|| changes.get() == 2).await);
        assert_eq!(ids(&udisks.list().await), ["mmcblk1p1", "mmcblk1p2", "sda1"]);
    });
}

#[test]
fn the_watch_ends_with_its_listener() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let told = Rc::new(Cell::new(0));
        let counted = Rc::clone(&told);
        let udisks = UDisks::new(Bus::Address(bus.address().to_owned()), CALL_TIMEOUT, move || {
            counted.set(counted.get() + 1);
            false
        });
        assert_eq!(udisks.list().await.len(), 2);
        for gone in ["sda1", "mmcblk1p1"] {
            fake.state.borrow_mut().gone.push(gone.to_owned());
            fake.emit(gone).await;
            tokio::time::sleep(QUIET).await;
        }
        assert_eq!(told.get(), 1);
    });
}

#[test]
fn without_udisks_nothing_is_listed() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let udisks = client(&bus, CALL_TIMEOUT, &Rc::default());
        assert!(udisks.list().await.is_empty());
        assert_eq!(udisks.mount("sda1").await.unwrap_err().name, ErrorName::Unsupported);
        let none = UDisks::new(Bus::Address("unix:path=/nonexistent/bus".to_owned()), CALL_TIMEOUT, || true);
        assert!(none.list().await.is_empty());
        assert_eq!(none.unmount("sda1").await.unwrap_err().name, ErrorName::Unsupported);
    });
}

#[test]
fn a_udisks_that_does_not_answer() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeUDisks::start(&bus).await;
        let udisks = client(&bus, Duration::from_millis(300), &Rc::default());
        fake.state.borrow_mut().silent = true;
        assert!(udisks.list().await.is_empty());
        assert_eq!(udisks.mount("sda1").await.unwrap_err().name, ErrorName::Timeout);
        fake.state.borrow_mut().silent = false;
        assert_eq!(udisks.list().await.len(), 2);
    });
}

#[test]
fn its_debug_output_names_the_bus_and_the_watch() {
    let udisks = UDisks::new(Bus::Address("unix:path=/nonexistent/bus".to_owned()), CALL_TIMEOUT, || true);
    let text = format!("{udisks:?}");
    assert!(text.starts_with("UDisks {"), "{text}");
    assert!(text.contains("/nonexistent/bus") && text.contains("watching: Cell { value: false }"), "{text}");
}
