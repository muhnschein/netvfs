// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a level lets an app do in an account ([`netvfs_bridge_proto::access`]), decided before a call reaches the server; how long an added item stays the app's.

use crate::consent::Level;
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
pub use netvfs_bridge_proto::access::{After, Op, Own, Verdict, after, check, is_folder};
use std::time::Duration;

/// How long an added item stays the app's own.
pub const OWN_LIFETIME: Duration = Duration::from_hours(24);

/// A refused call: `PermissionDenied`, the level as detail.
#[must_use]
pub fn refused(level: Level) -> Status {
    let what = match level {
        Level::Full => "do this",
        Level::ReadAdd => "read and add",
        Level::Read => "read",
        Level::Add => "add",
    };
    Status::new(ErrorName::PermissionDenied, format!("This app may only {what} in this account"))
        .with_detail(level.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_name_the_level() {
        let r = refused(Level::Read);
        assert_eq!(r.name, ErrorName::PermissionDenied);
        assert_eq!(r.message, "This app may only read in this account");
        assert_eq!(r.detail, "read");
        assert_eq!(refused(Level::ReadAdd).message, "This app may only read and add in this account");
        assert_eq!(refused(Level::ReadAdd).detail, "read-add");
        assert_eq!(refused(Level::Add).message, "This app may only add in this account");
        assert_eq!(refused(Level::Add).detail, "add");
        assert_eq!(refused(Level::Full).message, "This app may only do this in this account");
    }
}
