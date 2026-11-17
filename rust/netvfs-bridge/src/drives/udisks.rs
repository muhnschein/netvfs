// SPDX-License-Identifier: LGPL-2.1-or-later
//! UDisks2 client: `GetManagedObjects`, `Filesystem.Mount`/`Unmount` on the system bus, and the signal watch behind `DrivesChanged`. Connects on first call, so a bridge never asked for drives never touches the system bus.

use super::DriveSource;
use super::classify::{self, Drive, FILESYSTEM, ManagedObjects};
use crate::core::LocalFuture;
use crate::status::Status;
use futures_lite::StreamExt;
use netvfs_bridge_proto::ErrorName;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::rc::{Rc, Weak};
use std::time::Duration;
use tokio::sync::OnceCell;
use zbus::zvariant::Value;
use zbus::{Connection, MessageStream};

/// UDisks2's name on the system bus.
pub const SERVICE: &str = "org.freedesktop.UDisks2";
/// UDisks2's object manager.
pub const MANAGER: &str = "/org/freedesktop/UDisks2";
/// Interface of `GetManagedObjects`.
pub const OBJECT_MANAGER: &str = "org.freedesktop.DBus.ObjectManager";
/// Prefix of UDisks2's error names.
pub const ERROR_PREFIX: &str = "org.freedesktop.UDisks2.Error.";
/// How long a call waits for UDisks2.
pub const CALL_TIMEOUT: Duration = Duration::from_mins(1);
/// First signal of a burst to the new listing.
pub const DEBOUNCE: Duration = Duration::from_millis(200);
const RULE: &str = "type='signal',sender='org.freedesktop.UDisks2',path_namespace='/org/freedesktop/UDisks2'";

/// Where UDisks2 is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bus {
    /// The system bus.
    System,
    /// The bus at this address (tests).
    Address(String),
}

/// UDisks2's drives; the core holds one.
pub struct UDisks(Rc<Inner>);

struct Inner {
    bus: Bus,
    timeout: Duration,
    conn: OnceCell<Option<Connection>>,
    last: RefCell<Option<Vec<Drive>>>,
    watching: Cell<bool>,
    changed: Box<dyn Fn() -> bool>,
}

impl std::fmt::Debug for UDisks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UDisks").field("bus", &self.0.bus).field("watching", &self.0.watching).finish()
    }
}

impl UDisks {
    /// UDisks2 on the system bus; `changed` is told of listing changes (false: stop telling).
    #[must_use]
    pub fn system(changed: impl Fn() -> bool + 'static) -> Self {
        Self::new(Bus::System, CALL_TIMEOUT, changed)
    }

    /// UDisks2 on `bus`, each call waiting at most `timeout`.
    #[must_use]
    pub fn new(bus: Bus, timeout: Duration, changed: impl Fn() -> bool + 'static) -> Self {
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

    /// `ListDrives`: drives now, remembered as the last listing. First listing starts the watch.
    async fn listing(&self) -> Vec<Drive> {
        let drives = self
            .within(async {
                let conn = self.connection().await.ok_or_else(no_udisks)?;
                self.watch(conn).await;
                drives(conn).await
            })
            .await
            .unwrap_or_else(|status| {
                crate::log::debug(format_args!("No drives: {} {}", status.message, status.detail));
                Vec::new()
            });
        *self.0.last.borrow_mut() = Some(drives.clone());
        drives
    }

    async fn relisted(&self) -> bool {
        let Some(conn) = self.connection().await else { return false };
        let Ok(drives) = self.within(drives(conn)).await else { return true };
        if self.0.last.borrow().as_ref() == Some(&drives) {
            return true;
        }
        *self.0.last.borrow_mut() = Some(drives);
        (self.0.changed)()
    }

    /// Follows UDisks2's signals once, subscribed before the first listing so no later change is missed.
    async fn watch(&self, conn: &Connection) {
        if self.0.watching.replace(true) {
            return;
        }
        let mut signals = match MessageStream::for_match_rule(RULE, conn, None).await {
            Ok(signals) => signals,
            Err(e) => {
                crate::log::warning(format_args!("Drive changes are seen only when listed again: {e}"));
                return;
            }
        };
        let inner = Rc::downgrade(&self.0);
        tokio::task::spawn_local(async move {
            while signals.next().await.is_some() {
                tokio::time::sleep(DEBOUNCE).await;
                while let Some(Some(_)) = futures_lite::future::poll_once(signals.next()).await {}
                if !relist(&inner).await {
                    break;
                }
            }
        });
    }

    /// Mounts or unmounts drive `id` if `ListDrives` lists it now; mount point after a mount.
    async fn act(&self, id: &str, mount: bool) -> Result<Vec<u8>, Status> {
        let conn = self.connection().await.ok_or_else(no_udisks)?;
        let drive = drives(conn)
            .await?
            .into_iter()
            .find(|d| d.id == id)
            .ok_or_else(|| Status::new(ErrorName::NotFound, "No such drive"))?;
        if drive.mount_point.is_empty() != mount {
            return Ok(drive.mount_point);
        }
        if drive.locked {
            // Settings → Storage unlocks it; the bridge takes no passphrase.
            return Err(Status::new(ErrorName::Unsupported, "The drive is locked"));
        }
        // As Settings → Storage mounts: no question.
        let options = HashMap::from([("auth.no_user_interaction", Value::from(true))]);
        let path = drive.object_path();
        let member = if mount { "Mount" } else { "Unmount" };
        let reply = conn
            .call_method(Some(SERVICE), path.as_str(), Some(FILESYSTEM), member, &(options,))
            .await
            .map_err(status)?;
        if !mount {
            return Ok(Vec::new());
        }
        let point: String = reply.body().deserialize().map_err(|e| unexpected("Mount", &e))?;
        Ok(point.into_bytes())
    }

    async fn within<T>(&self, work: impl Future<Output = Result<T, Status>>) -> Result<T, Status> {
        tokio::time::timeout(self.0.timeout, work)
            .await
            .unwrap_or_else(|_| Err(Status::new(ErrorName::Timeout, "UDisks2 did not answer")))
    }
}

impl DriveSource for UDisks {
    fn list(&self) -> LocalFuture<'_, Vec<Drive>> {
        Box::pin(self.listing())
    }

    fn mount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<Vec<u8>, Status>> {
        Box::pin(self.within(self.act(id, true)))
    }

    fn unmount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<(), Status>> {
        Box::pin(async move { self.within(self.act(id, false)).await.map(drop) })
    }
}

async fn relist(inner: &Weak<Inner>) -> bool {
    match inner.upgrade() {
        Some(inner) => UDisks(inner).relisted().await,
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
    connected.inspect_err(|e| crate::log::warning(format_args!("No system bus, so no drives: {e}"))).ok()
}

async fn drives(conn: &Connection) -> Result<Vec<Drive>, Status> {
    let reply = conn
        .call_method(Some(SERVICE), MANAGER, Some(OBJECT_MANAGER), "GetManagedObjects", &())
        .await
        .map_err(status)?;
    let objects: ManagedObjects =
        reply.body().deserialize().map_err(|e| unexpected("GetManagedObjects", &e))?;
    Ok(classify::drives(&objects))
}

fn no_udisks() -> Status {
    Status::unsupported("UDisks2 cannot be reached")
}

fn unexpected(member: &str, e: &zbus::Error) -> Status {
    Status::internal(format!("UDisks2 answered {member} unexpectedly")).with_detail(e.to_string())
}

fn status(e: zbus::Error) -> Status {
    match e {
        zbus::Error::MethodError(name, message, _) => {
            let message = message.unwrap_or_default();
            let name = name.as_str();
            Status::new(error_name(name), "UDisks2 failed").with_detail(format!("{name}: {message}"))
        }
        other => Status::internal("Cannot ask UDisks2").with_detail(other.to_string()),
    }
}

/// The error name of a UDisks2 or bus error.
#[must_use]
pub fn error_name(dbus: &str) -> ErrorName {
    match dbus.strip_prefix(ERROR_PREFIX) {
        Some(
            "NotAuthorized" | "NotAuthorizedCanObtain" | "NotAuthorizedDismissed" | "OptionNotPermitted",
        ) => ErrorName::PermissionDenied,
        Some("DeviceBusy") => ErrorName::Locked,
        Some("Cancelled") => ErrorName::Canceled,
        Some("Timedout") => ErrorName::Timeout,
        Some("NotSupported") => ErrorName::Unsupported,
        Some("AlreadyMounted") => ErrorName::AlreadyExists,
        Some("NotMounted") => ErrorName::NotFound,
        Some(_) => ErrorName::Internal,
        None => bus_error_name(dbus),
    }
}

fn bus_error_name(dbus: &str) -> ErrorName {
    match dbus.strip_prefix("org.freedesktop.DBus.Error.") {
        Some("ServiceUnknown" | "NameHasNoOwner") => ErrorName::Unsupported,
        Some("UnknownObject" | "UnknownMethod" | "UnknownInterface") => ErrorName::NotFound,
        Some("NoReply" | "Timeout") => ErrorName::Timeout,
        Some("AccessDenied") => ErrorName::PermissionDenied,
        _ => ErrorName::Internal,
    }
}

#[cfg(test)]
#[path = "udisks_tests.rs"]
mod tests;
