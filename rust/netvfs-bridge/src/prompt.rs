// SPDX-License-Identifier: LGPL-2.1-or-later
//! Asking the user whether a consumer may use the network locations
//! (SPEC-v2 XB-6). The bridge, not the consumer, handles the answer.
//!
//! [`NotificationPrompt`] posts an `org.freedesktop.Notifications`
//! notification "<DisplayName> wants to use your network locations" with the
//! actions `allow` (Allow) and `deny` (Don't allow), answered through
//! `ActionInvoked`. Whether lipstick on Sailfish OS 5.2 shows freedesktop
//! actions and emits `ActionInvoked` to a process that owns no bus name is
//! unverified on a device; Settings can always grant or revoke.

use futures_lite::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc;
use zbus::names::OwnedUniqueName;
use zbus::zvariant::Value;
use zbus::{Connection, Message, MessageStream};

const SERVICE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
const INTERFACE: &str = "org.freedesktop.Notifications";
const ALLOW: &str = "allow";
const DENY: &str = "deny";
const NEVER_EXPIRES: i32 = 0;
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// What became of a shown question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptEvent {
    /// The user allowed (`true`) or refused.
    Answered(bool),
    /// Closed without an answer, or it could not be shown.
    Dismissed,
}

/// The consent question.
pub trait ConsentPrompt {
    /// Shows (or replaces) the question for `display_name`.
    fn show(&mut self, display_name: &str);
    /// Removes a shown question (the decision was taken elsewhere).
    fn withdraw(&mut self);
    /// Whether a question is shown and not answered yet.
    fn is_shown(&self) -> bool;
}

/// What the owner sees, and the number of its last request.
#[derive(Debug, Default)]
struct Shared {
    shown: bool,
    generation: u64,
}

#[derive(Debug)]
enum Command {
    Show { generation: u64, display_name: String },
    Withdraw { generation: u64 },
}

/// The question as a notification on the session bus.
///
/// The calls run on a task of their own: `show` returns at once and
/// [`is_shown`](ConsentPrompt::is_shown) is true from then on, until the
/// question is answered, closed or withdrawn, or cannot be posted (which
/// reports [`PromptEvent::Dismissed`]).
#[derive(Debug)]
pub struct NotificationPrompt {
    shared: Arc<Mutex<Shared>>,
    commands: mpsc::UnboundedSender<Command>,
}

impl NotificationPrompt {
    /// Starts the prompt on the current tokio runtime. `bus` is the session
    /// bus (`None`: none, every question is dismissed); `events` receives
    /// the outcome of the questions.
    pub fn start(bus: Option<Connection>, events: impl Fn(PromptEvent) + Send + 'static) -> Self {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (commands, receiver) = mpsc::unbounded_channel();
        let actor = Actor {
            bus,
            events: Box::new(events),
            shared: Arc::clone(&shared),
            generation: 0,
            id: 0,
            owner: None,
            signals: None,
        };
        tokio::spawn(actor.run(receiver));
        Self { shared, commands }
    }

    fn request(&self, shown: bool, command: impl FnOnce(u64) -> Command) {
        let generation = {
            let mut shared = lock(&self.shared);
            shared.generation = shared.generation.wrapping_add(1);
            shared.shown = shown;
            shared.generation
        };
        // The task ends only with this sender.
        self.commands.send(command(generation)).ok();
    }
}

impl ConsentPrompt for NotificationPrompt {
    fn show(&mut self, display_name: &str) {
        let display_name = display_name.to_owned();
        self.request(true, |generation| Command::Show { generation, display_name });
    }

    fn withdraw(&mut self) {
        if self.is_shown() {
            self.request(false, |generation| Command::Withdraw { generation });
        }
    }

    fn is_shown(&self) -> bool {
        lock(&self.shared).shown
    }
}

impl Drop for NotificationPrompt {
    fn drop(&mut self) {
        self.withdraw();
    }
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The task that talks to the notification service.
struct Actor {
    bus: Option<Connection>,
    events: Box<dyn Fn(PromptEvent) + Send>,
    shared: Arc<Mutex<Shared>>,
    /// The last request handled.
    generation: u64,
    /// The shown notification, `0` for none.
    id: u32,
    /// The service that posted it.
    owner: Option<OwnedUniqueName>,
    /// `ActionInvoked` and `NotificationClosed`, from the first question on.
    signals: Option<MessageStream>,
}

impl Actor {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => match command {
                    Some(Command::Show { generation, display_name }) => self.show(generation, &display_name).await,
                    Some(Command::Withdraw { generation }) => self.withdraw(generation).await,
                    None => break,
                },
                message = next_signal(&mut self.signals) => self.on_signal(&message),
            }
        }
    }

    async fn show(&mut self, generation: u64, display_name: &str) {
        self.generation = generation;
        let Some(bus) = self.bus.clone() else {
            return self.failed("no session bus");
        };
        if self.signals.is_none() {
            self.signals = subscribe(&bus).await;
        }
        let summary = format!("{display_name} wants to use your network locations");
        let hints = HashMap::from([("category", Value::from("x-nemo.general")), ("urgency", Value::U8(1))]);
        // A slice: an array would be a structure on the bus.
        let actions: &[&str] = &[ALLOW, "Allow", DENY, "Don't allow"];
        let body = ("netvfs", self.id, "", summary, "", actions, hints, NEVER_EXPIRES);
        let call = bus.call_method(Some(SERVICE), PATH, Some(INTERFACE), "Notify", &body);
        match tokio::time::timeout(NOTIFY_TIMEOUT, call).await {
            Ok(Ok(reply)) => match reply.body().deserialize::<u32>() {
                Ok(id) => {
                    self.id = id;
                    self.owner = reply.header().sender().map(|name| name.to_owned().into());
                }
                Err(e) => self.failed(&e.to_string()),
            },
            Ok(Err(e)) => self.failed(&e.to_string()),
            Err(_elapsed) => self.failed("no answer in time"),
        }
    }

    fn failed(&self, reason: &str) {
        crate::log::warning(format_args!("Cannot post the consent notification: {reason}"));
        self.finish(PromptEvent::Dismissed);
    }

    /// Reports `event` unless the owner asked for something else since.
    fn finish(&self, event: PromptEvent) {
        let current = {
            let mut shared = lock(&self.shared);
            let current = shared.generation == self.generation;
            if current {
                shared.shown = false;
            }
            current
        };
        if current {
            (self.events)(event);
        }
    }

    async fn withdraw(&mut self, generation: u64) {
        self.generation = generation;
        let id = std::mem::take(&mut self.id);
        if let (Some(bus), true) = (&self.bus, id != 0) {
            let sent = async {
                let message = Message::method_call(PATH, "CloseNotification")?
                    .destination(SERVICE)?
                    .interface(INTERFACE)?
                    .with_flags(zbus::message::Flags::NoReplyExpected)?
                    .build(&id)?;
                bus.send(&message).await
            };
            if let Err(e) = sent.await {
                crate::log::warning(format_args!("Cannot withdraw the consent notification: {e}"));
            }
        }
    }

    fn on_signal(&mut self, message: &Message) {
        let header = message.header();
        if self.id == 0 || self.owner.as_deref() != header.sender() {
            return;
        }
        let body = message.body();
        let event = match header.member().map(zbus::names::MemberName::as_str) {
            Some("ActionInvoked") => match body.deserialize::<(u32, String)>() {
                Ok((id, action)) if id == self.id => match action.as_str() {
                    ALLOW => PromptEvent::Answered(true),
                    DENY => PromptEvent::Answered(false),
                    _ => PromptEvent::Dismissed,
                },
                _ => return,
            },
            Some("NotificationClosed") => match body.deserialize::<(u32, u32)>() {
                Ok((id, _reason)) if id == self.id => PromptEvent::Dismissed,
                _ => return,
            },
            _ => return,
        };
        self.id = 0;
        self.finish(event);
    }
}

/// Subscribes to the signals of the notification service.
async fn subscribe(bus: &Connection) -> Option<MessageStream> {
    let rule = format!("type='signal',sender='{SERVICE}',path='{PATH}',interface='{INTERFACE}'");
    match MessageStream::for_match_rule(rule.as_str(), bus, None).await {
        Ok(stream) => Some(stream),
        Err(e) => {
            crate::log::warning(format_args!("Cannot watch the consent notification: {e}"));
            None
        }
    }
}

/// The next signal, or never when there is no subscription.
async fn next_signal(signals: &mut Option<MessageStream>) -> Message {
    loop {
        let Some(stream) = signals else {
            return std::future::pending().await;
        };
        match stream.next().await {
            Some(Ok(message)) => return message,
            Some(Err(_)) => (),
            None => *signals = None,
        }
    }
}
