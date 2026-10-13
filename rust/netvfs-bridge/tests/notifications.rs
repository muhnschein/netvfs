// SPDX-License-Identifier: LGPL-2.1-or-later
//! The consent notification against a fake `org.freedesktop.Notifications`
//! on a private bus (skipped without `dbus-daemon`).

#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use futures_lite::StreamExt;
use netvfs_bridge::prompt::{ConsentPrompt, NotificationPrompt, PromptEvent};
use netvfs_bridge::testutil::TestBus;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use zbus::message::Type;
use zbus::names::BusName;
use zbus::zvariant::OwnedValue;
use zbus::{Connection, Message, MessageStream};

const SERVICE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
const INTERFACE: &str = "org.freedesktop.Notifications";
const WAIT: Duration = Duration::from_secs(10);

type NotifyArgs = (String, u32, String, String, String, Vec<String>, HashMap<String, OwnedValue>, i32);

/// How the fake answers `Notify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Id,
    Error,
    NotAnId,
}

/// The fake service: ids from 7 on, or the replaced one.
struct Fake {
    conn: Connection,
    calls: mpsc::UnboundedReceiver<Message>,
    answer: Arc<Mutex<Answer>>,
}

impl Fake {
    async fn start(bus: &TestBus) -> Self {
        let conn = bus.connect().await;
        conn.request_name(SERVICE).await.unwrap();
        let (sender, calls) = mpsc::unbounded_channel();
        let answer = Arc::new(Mutex::new(Answer::Id));
        let mut stream = MessageStream::from(&conn);
        let (server, mode) = (conn.clone(), Arc::clone(&answer));
        tokio::spawn(async move {
            let mut next = 7_u32;
            while let Some(Ok(message)) = stream.next().await {
                if message.message_type() != Type::MethodCall {
                    continue;
                }
                if message.header().member().unwrap().as_str() == "Notify" {
                    let args: NotifyArgs = message.body().deserialize().unwrap();
                    let header = message.header();
                    let mode = *mode.lock().unwrap();
                    match mode {
                        Answer::Id if args.1 != 0 => server.reply(&header, &args.1).await.unwrap(),
                        Answer::Id => {
                            server.reply(&header, &next).await.unwrap();
                            next += 1;
                        }
                        Answer::Error => {
                            server.reply_error(&header, "org.example.Failed", &"no").await.unwrap();
                        }
                        Answer::NotAnId => server.reply(&header, &"seven").await.unwrap(),
                    }
                }
                sender.send(message).unwrap();
            }
        });
        Self { conn, calls, answer }
    }

    async fn next_call(&mut self) -> Message {
        tokio::time::timeout(WAIT, self.calls.recv()).await.unwrap().unwrap()
    }

    async fn notify(&mut self) -> NotifyArgs {
        let call = self.next_call().await;
        assert_eq!(call.header().member().unwrap().as_str(), "Notify");
        call.body().deserialize().unwrap()
    }

    async fn close(&mut self) -> u32 {
        let call = self.next_call().await;
        assert_eq!(call.header().member().unwrap().as_str(), "CloseNotification");
        assert!(call.header().primary().flags().contains(zbus::message::Flags::NoReplyExpected));
        call.body().deserialize().unwrap()
    }

    async fn action(&self, id: u32, action: &str) {
        emit(&self.conn, None, "ActionInvoked", &(id, action)).await;
    }

    async fn closed(&self, id: u32) {
        emit(&self.conn, None, "NotificationClosed", &(id, 2_u32)).await;
    }
}

async fn emit<B>(conn: &Connection, to: Option<&str>, member: &str, body: &B)
where
    B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
{
    conn.emit_signal(to.map(|n| BusName::try_from(n).unwrap()), PATH, INTERFACE, member, body).await.unwrap();
}

struct Setup {
    bus: TestBus,
    fake: Fake,
    prompt: NotificationPrompt,
    client: Connection,
    events: mpsc::UnboundedReceiver<PromptEvent>,
}

fn start(bus: Option<Connection>) -> (NotificationPrompt, mpsc::UnboundedReceiver<PromptEvent>) {
    let (sender, events) = mpsc::unbounded_channel();
    let prompt = NotificationPrompt::start(bus, move |event| {
        sender.send(event).ok();
    });
    (prompt, events)
}

async fn setup() -> Option<Setup> {
    let bus = TestBus::start()?;
    let fake = Fake::start(&bus).await;
    let client = bus.connect().await;
    let (prompt, events) = start(Some(client.clone()));
    Some(Setup { bus, fake, prompt, client, events })
}

async fn next_event(events: &mut mpsc::UnboundedReceiver<PromptEvent>) -> PromptEvent {
    tokio::time::timeout(WAIT, events.recv()).await.unwrap().unwrap()
}

#[tokio::test]
async fn actions_answer() {
    let Some(mut s) = setup().await else { return };
    assert!(!s.prompt.is_shown());
    s.prompt.show("Lautta");
    assert!(s.prompt.is_shown());
    let (app, replaces, icon, summary, body, actions, hints, timeout) = s.fake.notify().await;
    assert_eq!(
        (app.as_str(), replaces, icon.as_str(), summary.as_str(), body.as_str(), timeout),
        ("netvfs", 0, "", "Lautta wants to use your network locations", "", 0)
    );
    assert_eq!(actions, ["allow", "Allow", "deny", "Don't allow"]);
    assert_eq!(hints.len(), 2);
    assert_eq!(String::try_from(hints["category"].try_clone().unwrap()).unwrap(), "x-nemo.general");
    assert_eq!(u8::try_from(&hints["urgency"]).unwrap(), 1);
    s.fake.action(7, "allow").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(true));
    assert!(!s.prompt.is_shown());

    for (id, action, event) in [
        (8, "deny", PromptEvent::Answered(false)),
        (9, "default", PromptEvent::Dismissed),
        (10, "", PromptEvent::Dismissed),
    ] {
        s.prompt.show("Lautta");
        assert_eq!(s.fake.notify().await.1, 0);
        s.fake.action(id, action).await;
        assert_eq!(next_event(&mut s.events).await, event);
        assert!(!s.prompt.is_shown());
    }
}

#[tokio::test]
async fn closed_and_stale_signals() {
    let Some(mut s) = setup().await else { return };
    s.prompt.show("A");
    s.fake.notify().await;
    // Other notifications, id 0, a malformed body and other members.
    s.fake.closed(6).await;
    s.fake.action(8, "allow").await;
    s.fake.action(0, "allow").await;
    emit(&s.fake.conn, None, "ActionInvoked", &7_u32).await;
    emit(&s.fake.conn, None, "NotificationClosed", &(7_u32, "x")).await;
    emit(&s.fake.conn, None, "ActionInvoked2", &(7_u32, "allow")).await;
    // None of them was taken: the answer is the first event.
    s.fake.action(7, "allow").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(true));
    s.prompt.show("A");
    s.fake.notify().await;
    s.fake.closed(7).await;
    s.fake.closed(8).await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Dismissed);
    assert!(!s.prompt.is_shown());
    // Closed already: a late action is ignored.
    s.fake.action(8, "allow").await;
    s.prompt.show("A");
    s.fake.notify().await;
    s.fake.action(9, "deny").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(false));
    assert_eq!(s.events.try_recv(), Err(mpsc::error::TryRecvError::Empty));
}

#[tokio::test]
async fn withdraw_closes_the_notification() {
    let Some(mut s) = setup().await else { return };
    s.prompt.withdraw(); // nothing shown: nothing sent
    s.prompt.show("A");
    s.fake.notify().await;
    s.prompt.withdraw();
    assert!(!s.prompt.is_shown());
    assert_eq!(s.fake.close().await, 7);
    s.prompt.withdraw();
    s.fake.action(7, "allow").await;
    s.prompt.show("A");
    assert_eq!(s.fake.notify().await.1, 0);
    s.fake.action(8, "allow").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(true));

    // Withdrawn before the service answered: closed once it did.
    s.prompt.show("B");
    s.prompt.withdraw();
    assert!(!s.prompt.is_shown());
    s.fake.notify().await;
    assert_eq!(s.fake.close().await, 9);
    s.fake.action(9, "allow").await;

    // Dropping the prompt withdraws its question.
    s.prompt.show("C");
    s.fake.notify().await;
    drop(s.prompt);
    assert_eq!(s.fake.close().await, 10);
    // No event, and the task may have ended already.
    s.events.try_recv().unwrap_err();
}

#[tokio::test]
async fn show_replaces() {
    let Some(mut s) = setup().await else { return };
    s.prompt.show("A");
    s.fake.notify().await;
    s.prompt.show("B");
    let args = s.fake.notify().await;
    assert_eq!((args.1, args.3.as_str()), (7, "B wants to use your network locations"));
    s.fake.action(7, "allow").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(true));
}

#[tokio::test]
async fn other_senders_are_ignored() {
    let Some(mut s) = setup().await else { return };
    s.prompt.show("A");
    s.fake.notify().await;
    let other = s.bus.connect().await;
    let to = s.client.unique_name().unwrap().to_string();
    emit(&other, Some(&to), "ActionInvoked", &(7_u32, "allow")).await;
    emit(&other, None, "ActionInvoked", &(7_u32, "allow")).await;
    emit(&other, Some(&to), "NotificationClosed", &(7_u32, 1_u32)).await;
    // The bus has handled what `other` sent once it answers a ping.
    other
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus.Peer"),
            "Ping",
            &(),
        )
        .await
        .unwrap();
    assert!(s.prompt.is_shown());
    s.fake.action(7, "deny").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(false));
}

#[tokio::test]
async fn failures_dismiss() {
    let Some(mut s) = setup().await else { return };
    for answer in [Answer::Error, Answer::NotAnId] {
        *s.fake.answer.lock().unwrap() = answer;
        s.prompt.show("A");
        assert!(s.prompt.is_shown());
        assert_eq!(next_event(&mut s.events).await, PromptEvent::Dismissed);
        assert!(!s.prompt.is_shown());
        s.fake.notify().await;
    }
    *s.fake.answer.lock().unwrap() = Answer::Id;
    s.prompt.show("A");
    s.fake.notify().await;
    s.fake.action(7, "allow").await;
    assert_eq!(next_event(&mut s.events).await, PromptEvent::Answered(true));
}

#[tokio::test]
async fn no_service() {
    let Some(bus) = TestBus::start() else { return };
    let (mut prompt, mut events) = start(Some(bus.connect().await));
    prompt.show("A");
    assert_eq!(next_event(&mut events).await, PromptEvent::Dismissed);
    assert!(!prompt.is_shown());
    // A failure that is no longer current is not reported.
    prompt.show("A");
    prompt.withdraw();
    prompt.show("A");
    assert_eq!(next_event(&mut events).await, PromptEvent::Dismissed);
    assert!(!prompt.is_shown());
    prompt.show("A");
    assert_eq!(next_event(&mut events).await, PromptEvent::Dismissed);
    assert_eq!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty));
}

#[tokio::test]
async fn no_bus() {
    let (mut prompt, mut events) = start(None);
    prompt.show("A");
    assert_eq!(next_event(&mut events).await, PromptEvent::Dismissed);
    assert!(!prompt.is_shown());
    prompt.withdraw();
    prompt.show("A");
    prompt.withdraw();
    prompt.show("A");
    assert_eq!(next_event(&mut events).await, PromptEvent::Dismissed);
    assert_eq!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty));
}
