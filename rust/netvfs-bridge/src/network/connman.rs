// SPDX-License-Identifier: LGPL-2.1-or-later
//! Connman client: `GetServices` on the system bus and the signal watch behind `NetworkChanged`. Connects on first call, so a bridge never asked for the network never touches the system bus.

use super::NetworkSource;
use super::classify::{self, Services, UNKNOWN};
use crate::core::LocalFuture;
use crate::drives::udisks::Bus;
use futures_lite::StreamExt;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::time::Duration;
use tokio::sync::OnceCell;
use zbus::{Connection, MessageStream};

/// Connman's name on the system bus.
pub const SERVICE: &str = "net.connman";
/// Connman's manager object.
pub const MANAGER: &str = "/";
/// Interface of `GetServices`.
pub const MANAGER_INTERFACE: &str = "net.connman.Manager";
/// How long a call waits for Connman.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// First signal of a burst to the new answer.
pub const DEBOUNCE: Duration = Duration::from_millis(500);
const RULE: &str = "type='signal',sender='net.connman'";

/// Connman's network; the core holds one.
pub struct Connman(Rc<Inner>);

struct Inner {
    bus: Bus,
    timeout: Duration,
    conn: OnceCell<Option<Connection>>,
    last: RefCell<Option<String>>,
    watching: Cell<bool>,
    changed: Box<dyn Fn(String) -> bool>,
}

impl std::fmt::Debug for Connman {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connman").field("bus", &self.0.bus).field("watching", &self.0.watching).finish()
    }
}

impl Connman {
    /// Connman on the system bus; `changed` is told of a new kind (false: stop telling).
    #[must_use]
    pub fn system(changed: impl Fn(String) -> bool + 'static) -> Self {
        Self::new(Bus::System, CALL_TIMEOUT, changed)
    }

    /// Connman on `bus`, each call waiting at most `timeout`.
    #[must_use]
    pub fn new(bus: Bus, timeout: Duration, changed: impl Fn(String) -> bool + 'static) -> Self {
        Self(Rc::new(Inner {
            bus,
            timeout,
            conn: OnceCell::new(),
            last: RefCell::new(None),
            watching: Cell::new(false),
            changed: Box::new(changed),
        }))
    }

    async fn connection(&self) -> Option<&Connection> {
        self.0.conn.get_or_init(|| connect(&self.0.bus)).await.as_ref()
    }

    async fn current(&self) -> String {
        let Some(conn) = self.connection().await else { return UNKNOWN.to_owned() };
        self.watch(conn).await;
        let kind = self.ask(conn).await;
        *self.0.last.borrow_mut() = Some(kind.clone());
        kind
    }

    async fn ask(&self, conn: &Connection) -> String {
        tokio::time::timeout(self.0.timeout, services(conn))
            .await
            .ok()
            .flatten()
            .map_or_else(|| UNKNOWN.to_owned(), |s| classify::network(&s).to_owned())
    }

    async fn asked_again(&self) -> bool {
        let Some(conn) = self.connection().await else { return false };
        let kind = self.ask(conn).await;
        if self.0.last.borrow().as_deref() == Some(kind.as_str()) {
            return true;
        }
        *self.0.last.borrow_mut() = Some(kind.clone());
        (self.0.changed)(kind)
    }

    async fn watch(&self, conn: &Connection) {
        if self.0.watching.replace(true) {
            return;
        }
        let mut signals = match MessageStream::for_match_rule(RULE, conn, None).await {
            Ok(signals) => signals,
            Err(e) => {
                crate::log::warning(format_args!("Network changes are seen only when asked again: {e}"));
                return;
            }
        };
        let inner = Rc::downgrade(&self.0);
        tokio::task::spawn_local(async move {
            while signals.next().await.is_some() {
                tokio::time::sleep(DEBOUNCE).await;
                while let Some(Some(_)) = futures_lite::future::poll_once(signals.next()).await {}
                if !ask_again(&inner).await {
                    break;
                }
            }
        });
    }
}

impl NetworkSource for Connman {
    fn kind(&self) -> LocalFuture<'_, String> {
        Box::pin(self.current())
    }
}

async fn ask_again(inner: &Weak<Inner>) -> bool {
    match inner.upgrade() {
        Some(inner) => Connman(inner).asked_again().await,
        None => false,
    }
}

async fn connect(bus: &Bus) -> Option<Connection> {
    let builder = match bus {
        Bus::System => zbus::connection::Builder::system(),
        Bus::Address(address) => zbus::connection::Builder::address(address.as_str()),
    };
    let connected = match builder {
        Ok(builder) => builder.build().await,
        Err(e) => Err(e),
    };
    connected
        .inspect_err(|e| crate::log::warning(format_args!("No system bus, so no network kind: {e}")))
        .ok()
}

async fn services(conn: &Connection) -> Option<Services> {
    let reply = conn
        .call_method(Some(SERVICE), MANAGER, Some(MANAGER_INTERFACE), "GetServices", &())
        .await
        .inspect_err(|e| crate::log::debug(format_args!("Connman GetServices failed: {e}")))
        .ok()?;
    reply.body().deserialize::<Services>().ok()
}

#[cfg(test)]
#[path = "connman_tests.rs"]
mod tests;
