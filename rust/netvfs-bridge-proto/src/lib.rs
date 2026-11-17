// SPDX-License-Identifier: LGPL-2.1-or-later
//! The netvfs bridge protocol `org.netvfs.Bridge1`: wire types, method table, error names and
//! limits that the bridge and its clients share, a client proxy, and (feature `fake`, tests only)
//! an in-process fake bridge with the replayer of the golden contract sequences
//! (`tests/bridge/contract`).
#![forbid(unsafe_code)]

pub mod connect;
pub mod errors;
pub mod limits;
pub mod methods;
pub mod proxy;
pub mod signals;
pub mod wire;

#[cfg(feature = "fake")]
pub mod fake;

pub use connect::{Connection, SignalStream, connect};
pub use errors::{BridgeError, ErrorName};
pub use methods::{INTERFACE, Lane, METHODS, MethodInfo, OBJECT_PATH, SIGNALS};
pub use proxy::Bridge1Proxy;
pub use signals::Signal;
pub use wire::*;
pub use zbus::zvariant;
pub use zeroize::Zeroizing;
/// Result of a proxy call, so that users need not depend on zbus.
pub type ProxyResult<T> = zbus::Result<T>;
