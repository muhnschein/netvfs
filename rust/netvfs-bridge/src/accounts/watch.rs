// SPDX-License-Identifier: LGPL-2.1-or-later
//! Account changes: libaccounts' writers send `AccountChanged` on the
//! session bus, on one object path per service type it concerns, which
//! needs no access to the database. One write sends several signals, so a
//! change is reported 200 ms after the first signal, for all the signals
//! of that time.

use futures_lite::StreamExt;
use std::time::Duration;
use tokio::time::Instant;
use zbus::{Connection, MessageStream};

/// The interface of libaccounts-glib's signals (ag-internals.h).
pub const INTERFACE: &str = "com.google.code.AccountsSSO.Accounts";
/// The signal every writer sends.
pub const MEMBER: &str = "AccountChanged";
/// From the first signal of a change to its report.
pub const DEBOUNCE: Duration = Duration::from_millis(200);

/// The changes announced on the session bus.
#[derive(Debug)]
pub struct AccountChanges {
    signals: Option<MessageStream>,
    /// When the change being collected is reported.
    due: Option<Instant>,
}

impl AccountChanges {
    /// Subscribes on `bus` (any sender, any path). Without a bus, or when
    /// the subscription fails, no change is ever reported (logged).
    pub async fn subscribe(bus: Option<&Connection>) -> Self {
        let rule = format!("type='signal',interface='{INTERFACE}',member='{MEMBER}'");
        let signals = match bus {
            Some(bus) => {
                MessageStream::for_match_rule(rule.as_str(), bus, None).await.map_err(|e| e.to_string())
            }
            None => Err("no session bus".to_owned()),
        };
        let signals = signals
            .inspect_err(|e| {
                crate::log::warning(format_args!("Account changes are seen only after a restart: {e}"));
            })
            .ok();
        Self { signals, due: None }
    }

    /// Waits for the next change. Cancel-safe: a change being collected
    /// stays collected.
    pub async fn next(&mut self) {
        loop {
            match (self.due, &mut self.signals) {
                (None, None) => return std::future::pending().await,
                (None, Some(signals)) => match signals.next().await {
                    Some(Ok(_)) => self.due = Instant::now().checked_add(DEBOUNCE),
                    Some(Err(_)) => (),
                    None => self.signals = None,
                },
                (Some(due), None) => return self.report(due).await,
                (Some(due), Some(signals)) => tokio::select! {
                    () = tokio::time::sleep_until(due) => {
                        self.due = None;
                        return;
                    }
                    // Part of the change being collected.
                    signal = signals.next() => if signal.is_none() {
                        self.signals = None;
                    },
                },
            }
        }
    }

    async fn report(&mut self, due: Instant) {
        tokio::time::sleep_until(due).await;
        self.due = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestBus;
    use zbus::names::BusName;

    const QUIET: Duration = Duration::from_millis(500);

    async fn emit(bus: &Connection, path: &str, interface: &str, member: &str) {
        bus.emit_signal(None::<BusName<'_>>, path, interface, member, &()).await.unwrap();
    }

    async fn changed_within(changes: &mut AccountChanges, wait: Duration) -> bool {
        tokio::time::timeout(wait, changes.next()).await.is_ok()
    }

    #[tokio::test]
    async fn change_signal_debounced() {
        // tst_BridgeAccounts::directoryChangeSignal
        let Some(bus) = TestBus::start() else { return };
        let mut changes = AccountChanges::subscribe(Some(&bus.connect().await)).await;
        let writer = bus.connect().await;
        emit(&writer, "/org/example/other", INTERFACE, "Unrelated").await;
        emit(&writer, "/org/example/other", "org.example.Other", MEMBER).await;
        assert!(!changed_within(&mut changes, QUIET).await);

        // Two writes in a row, on the paths of two service types: one
        // change, reported 200 ms after the first signal.
        let first = Instant::now();
        emit(&writer, "/ServiceType/storage", INTERFACE, MEMBER).await;
        emit(&writer, "/ServiceType/sharing", INTERFACE, MEMBER).await;
        assert!(changed_within(&mut changes, Duration::from_secs(5)).await);
        assert!(first.elapsed() >= DEBOUNCE);
        assert!(!changed_within(&mut changes, QUIET).await);

        // A later signal is a new change.
        emit(&writer, "/", INTERFACE, MEMBER).await;
        assert!(changed_within(&mut changes, Duration::from_secs(5)).await);

        // A change being collected survives a cancelled wait.
        emit(&writer, "/", INTERFACE, MEMBER).await;
        assert!(!changed_within(&mut changes, Duration::from_millis(50)).await);
        assert!(changes.due.is_some());
        assert!(changed_within(&mut changes, Duration::from_secs(5)).await);

        // The bus goes away while a change is collected: it is still
        // reported, and nothing after it.
        emit(&writer, "/", INTERFACE, MEMBER).await;
        assert!(!changed_within(&mut changes, Duration::from_millis(50)).await);
        drop(bus);
        assert!(changed_within(&mut changes, Duration::from_secs(5)).await);
        assert!(!changed_within(&mut changes, QUIET).await);
        assert!(changes.signals.is_none());
    }

    #[tokio::test]
    async fn no_bus_no_changes() {
        let mut changes = AccountChanges::subscribe(None).await;
        assert!(changes.signals.is_none());
        assert!(!changed_within(&mut changes, Duration::from_millis(50)).await);
    }
}
