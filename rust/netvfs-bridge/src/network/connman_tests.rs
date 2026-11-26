// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects)]

use super::{Bus, CALL_TIMEOUT, Connman, MANAGER, MANAGER_INTERFACE, SERVICE};
use crate::network::NetworkSource;
use crate::network::classify::{NONE, UNKNOWN};
use crate::testutil::TestBus;
use futures_lite::StreamExt;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};
use zbus::message::{Message, Type as MessageType};
use zbus::names::BusName;
use zbus::zvariant::{ObjectPath, Value};
use zbus::{Connection, MessageStream};

#[derive(Debug, Default)]
struct State {
    services: Vec<(String, String, String)>,
    asked: usize,
    silent: bool,
}

struct FakeConnman {
    conn: Connection,
    state: Rc<RefCell<State>>,
}

impl FakeConnman {
    async fn start(bus: &TestBus, services: &[(&str, &str, &str)]) -> Self {
        let conn = bus.connect().await;
        let mut calls = MessageStream::from(&conn);
        conn.request_name(SERVICE).await.unwrap();
        let state = Rc::new(RefCell::new(State::default()));
        let fake = Self { conn: conn.clone(), state: Rc::clone(&state) };
        fake.set(services);
        tokio::task::spawn_local(async move {
            while let Some(Ok(msg)) = calls.next().await {
                if msg.message_type() == MessageType::MethodCall {
                    answer(&conn, &state, &msg).await;
                }
            }
        });
        fake
    }

    fn set(&self, services: &[(&str, &str, &str)]) {
        self.state.borrow_mut().services =
            services.iter().map(|(p, t, s)| ((*p).to_owned(), (*t).to_owned(), (*s).to_owned())).collect();
    }

    fn asked(&self) -> usize {
        self.state.borrow().asked
    }

    async fn emit(&self) {
        let path = "/net/connman/service/wifi_a";
        let body = ("State", Value::from("online"));
        self.conn
            .emit_signal(None::<BusName<'_>>, path, "net.connman.Service", "PropertyChanged", &body)
            .await
            .unwrap();
    }
}

async fn answer(conn: &Connection, state: &RefCell<State>, msg: &Message) {
    let header = msg.header();
    if state.borrow().silent {
        return;
    }
    let member = header.member().map(|m| m.as_str().to_owned()).unwrap_or_default();
    let interface = header.interface().map(|i| i.as_str().to_owned()).unwrap_or_default();
    let path = header.path().map(|p| p.as_str().to_owned()).unwrap_or_default();
    if (path.as_str(), interface.as_str(), member.as_str()) != (MANAGER, MANAGER_INTERFACE, "GetServices") {
        conn.reply_error(&header, "org.freedesktop.DBus.Error.UnknownMethod", &("no",)).await.unwrap();
        return;
    }
    state.borrow_mut().asked += 1;
    let services: Vec<(ObjectPath<'_>, HashMap<&str, Value<'_>>)> = state
        .borrow()
        .services
        .iter()
        .map(|(p, t, s)| {
            let props = HashMap::from([("Type", Value::from(t.clone())), ("State", Value::from(s.clone()))]);
            (ObjectPath::try_from(p.clone()).unwrap(), props)
        })
        .collect();
    conn.reply(&header, &(services,)).await.unwrap();
}

fn run<F: Future>(test: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

fn client(bus: &TestBus, timeout: Duration, told: &Rc<RefCell<Vec<String>>>) -> Connman {
    let told = Rc::clone(told);
    Connman::new(Bus::Address(bus.address().to_owned()), timeout, move |kind| {
        told.borrow_mut().push(kind);
        true
    })
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

const WIFI: (&str, &str, &str) = ("/net/connman/service/wifi_a", "wifi", "online");
const MOBILE: (&str, &str, &str) = ("/net/connman/service/cellular_b", "cellular", "ready");

#[test]
fn the_kind_follows_connmans_first_connected_service() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeConnman::start(&bus, &[WIFI, MOBILE]).await;
        let told = Rc::default();
        let connman = client(&bus, CALL_TIMEOUT, &told);
        assert_eq!(connman.kind().await, "wifi");
        fake.set(&[("/net/connman/service/wifi_a", "wifi", "idle"), MOBILE]);
        fake.emit().await;
        assert!(wait_for(|| told.borrow().len() == 1).await, "the change is told");
        assert_eq!(*told.borrow(), ["mobile"]);
        assert_eq!(connman.kind().await, "mobile");
        let before = fake.asked();
        fake.emit().await;
        assert!(wait_for(|| fake.asked() > before).await);
        fake.set(&[]);
        fake.emit().await;
        assert!(wait_for(|| told.borrow().len() >= 2).await);
        assert_eq!(*told.borrow(), ["mobile", NONE], "the same kind again is not told");
    });
}

#[test]
fn a_burst_of_signals_asks_once() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let fake = FakeConnman::start(&bus, &[WIFI]).await;
        let told = Rc::default();
        let connman = client(&bus, CALL_TIMEOUT, &told);
        assert_eq!(connman.kind().await, "wifi");
        assert_eq!(fake.asked(), 1);
        for _ in 0..5 {
            fake.emit().await;
        }
        assert!(wait_for(|| fake.asked() == 2).await);
        fake.set(&[MOBILE]);
        fake.emit().await;
        assert!(wait_for(|| !told.borrow().is_empty()).await);
        assert_eq!(fake.asked(), 3, "one question for the burst");
    });
}

#[test]
fn without_connman_the_kind_is_unknown() {
    let Some(bus) = TestBus::start() else { return };
    run(async {
        let connman = client(&bus, Duration::from_millis(200), &Rc::default());
        assert_eq!(connman.kind().await, UNKNOWN);
        let fake = FakeConnman::start(&bus, &[WIFI]).await;
        fake.state.borrow_mut().silent = true;
        let quiet = client(&bus, Duration::from_millis(200), &Rc::default());
        assert_eq!(quiet.kind().await, UNKNOWN, "a Connman that does not answer");
        fake.state.borrow_mut().silent = false;
        assert_eq!(quiet.kind().await, "wifi");
    });
    let nobus = Bus::Address("unix:path=/nonexistent/bus".to_owned());
    run(async {
        let connman = Connman::new(nobus, CALL_TIMEOUT, |_| true);
        assert_eq!(connman.kind().await, UNKNOWN, "no bus at all");
    });
}
