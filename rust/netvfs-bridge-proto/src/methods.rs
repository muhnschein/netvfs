// SPDX-License-Identifier: LGPL-2.1-or-later
//! Names, method table and signals of `org.netvfs.Bridge1`. Table order is the C++ bridge's
//! `args.cpp` and the introspection XML; `tests/contract.rs` checks both against the XML.

/// Object path of the bridge.
pub const OBJECT_PATH: &str = "/org/netvfs/Bridge";
/// The bridge interface.
pub const INTERFACE: &str = "org.netvfs.Bridge1";
/// Signature of the `Entry` struct.
pub const ENTRY_SIGNATURE: &str = "(ayyyxxxxixxssqays)";
/// Introspection data the bridge serves, byte for byte; copy of the contract's
/// `tests/bridge/contract/org.netvfs.Bridge1.xml`, kept equal by `tests/contract.rs`.
pub const INTROSPECTION_XML: &str = include_str!("../org.netvfs.Bridge1.xml");

/// Connection pool a call runs in. A call may hint a lane; an empty hint selects the method's
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Short calls the user waits for.
    Interactive,
    /// Transfers and other long work.
    Bulk,
    /// Read handles (media playback).
    Stream,
}

impl Lane {
    /// The name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Bulk => "bulk",
            Self::Stream => "stream",
        }
    }

    /// A lane from its wire name, `None` if unknown. The empty hint is not a name: see
    /// [`Lane::from_hint`].
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "interactive" => Some(Self::Interactive),
            "bulk" => Some(Self::Bulk),
            "stream" => Some(Self::Stream),
            _ => None,
        }
    }

    /// A lane hint as calls carry it: empty means `default`.
    #[must_use]
    pub fn from_hint(hint: &str, default: Self) -> Option<Self> {
        if hint.is_empty() { Some(default) } else { Self::parse(hint) }
    }
}

/// One method of `org.netvfs.Bridge1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodInfo {
    /// Member name.
    pub name: &'static str,
    /// Input signature, without parentheses.
    pub input: &'static str,
    /// Output signature, without parentheses.
    pub output: &'static str,
    /// The lane the method runs in unless the call hints another.
    pub lane: Lane,
    /// Fails with `PermissionDenied` until the user granted consent.
    pub needs_consent: bool,
}

const fn method(
    name: &'static str,
    input: &'static str,
    output: &'static str,
    lane: Lane,
    needs_consent: bool,
) -> MethodInfo {
    MethodInfo { name, input, output, lane, needs_consent }
}

use Lane::{Bulk, Interactive, Stream};

/// The methods, in the order of `args.cpp` and of the XML.
pub const METHODS: [MethodInfo; 40] = [
    method("Hello", "s", "s", Interactive, false),
    method("GetConsent", "", "s", Interactive, false),
    method("RequestConsent", "", "", Interactive, false),
    // Consumer feature probe; reveals nothing of the user's locations.
    method("GetFeatures", "", "as", Interactive, false),
    // Without consent returns nothing instead of failing.
    method("ListLocations", "", "a(sssa{sv})", Interactive, false),
    method("Capabilities", "s", "(asasx)", Interactive, true),
    method("Disconnect", "s", "", Interactive, true),
    method("ConnectAdHoc", "saya{sv}", "s", Interactive, true),
    method("ForgetAdHoc", "s", "", Interactive, true),
    method("Discover", "b", "", Interactive, true),
    method("List", "saysu", "u", Interactive, true),
    method("Stat", "saybs", ENTRY_SIGNATURE, Interactive, true),
    method("ReadLink", "say", "ay", Interactive, true),
    method("SpaceInfo", "say", "xxx", Interactive, true),
    method("Checksum", "says", "ay", Bulk, true),
    method("MakeDir", "sayb", "", Interactive, true),
    method("RemoveFile", "say", "", Interactive, true),
    method("RemoveDir", "say", "", Interactive, true),
    method("Rename", "sayayb", "", Interactive, true),
    method("SetAttributes", "saya{sv}", "", Interactive, true),
    method("MakeSymlink", "sayay", "", Interactive, true),
    method("MakeHardlink", "sayay", "", Interactive, true),
    method("ServerCopy", "sayaya{sv}", "", Bulk, true),
    method("OpenRead", "says", "ux", Stream, true),
    method("Read", "uxu", "ay", Stream, true),
    method("ReadAhead", "uxx", "", Stream, true),
    method("Close", "u", "", Stream, true),
    method("Upload", "sayha{sv}", "u", Bulk, true),
    method("Download", "sayha{sv}", "u", Bulk, true),
    method("CopyAcross", "saysaya{sv}", "u", Bulk, true),
    method("RemoveTree", "say", "u", Bulk, true),
    method("Walk", "saya{sv}", "u", Bulk, true),
    // Cancel and Answer need no consent.
    method("Cancel", "u", "", Interactive, false),
    method("Answer", "sa{sv}", "", Interactive, false),
    method("OpenAccountSettings", "s", "", Interactive, true),
    method("AddAccount", "s", "", Interactive, true),
    // Shows nothing of the user's locations.
    method("OpenStorageSettings", "", "", Interactive, false),
    // Shows nothing of the user's locations; polkit lets any process of the user mount.
    method("ListDrives", "", "a(ssaya{sv})", Interactive, false),
    method("Mount", "s", "ay", Interactive, false),
    method("Unmount", "s", "", Interactive, false),
];

/// The signals as `(name, signature)`, in the order of the XML.
pub const SIGNALS: [(&str, &str); 10] = [
    ("ConsentChanged", "s"),
    ("LocationsChanged", ""),
    ("NearbyChanged", "a(sssq)"),
    ("ListBatch", "ua(ayyyxxxxixxssqays)"),
    ("ListDone", "uss"),
    ("JobProgress", "uxx"),
    ("WalkBatch", "ua(ay(ayyyxxxxixxssqays))"),
    ("JobFinished", "ussa{sv}"),
    ("Question", "ssa{sv}"),
    ("DrivesChanged", ""),
];

/// `GetFeatures`: the bridge opens Settings > Storage (`OpenStorageSettings`).
pub const FEATURE_STORAGE_SETTINGS: &str = "storage-settings";
/// `GetFeatures`: `ListDrives`, `Mount`, `Unmount` and `DrivesChanged`.
pub const FEATURE_DRIVES: &str = "drives";

/// The method called `name`.
#[must_use]
pub fn find_method(name: &str) -> Option<&'static MethodInfo> {
    METHODS.iter().find(|m| m.name == name)
}

/// The signature of the signal called `name`.
#[must_use]
pub fn find_signal(name: &str) -> Option<&'static str> {
    SIGNALS.iter().find(|(n, _)| *n == name).map(|(_, sig)| *sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // every method exactly once
    #[test]
    fn method_table_order_and_consent() {
        let expected = [
            "Hello",
            "GetConsent",
            "RequestConsent",
            "GetFeatures",
            "ListLocations",
            "Capabilities",
            "Disconnect",
            "ConnectAdHoc",
            "ForgetAdHoc",
            "Discover",
            "List",
            "Stat",
            "ReadLink",
            "SpaceInfo",
            "Checksum",
            "MakeDir",
            "RemoveFile",
            "RemoveDir",
            "Rename",
            "SetAttributes",
            "MakeSymlink",
            "MakeHardlink",
            "ServerCopy",
            "OpenRead",
            "Read",
            "ReadAhead",
            "Close",
            "Upload",
            "Download",
            "CopyAcross",
            "RemoveTree",
            "Walk",
            "Cancel",
            "Answer",
            "OpenAccountSettings",
            "AddAccount",
            "OpenStorageSettings",
            "ListDrives",
            "Mount",
            "Unmount",
        ];
        let names: Vec<&str> = METHODS.iter().map(|m| m.name).collect();
        assert_eq!(names, expected);
        assert!(find_method("Stat").unwrap().needs_consent);
        assert!(!find_method("Hello").unwrap().needs_consent);
        assert!(!find_method("ListLocations").unwrap().needs_consent);
        assert!(find_method("Nope").is_none());
        let free: Vec<&str> = METHODS.iter().filter(|m| !m.needs_consent).map(|m| m.name).collect();
        assert_eq!(
            free,
            [
                "Hello",
                "GetConsent",
                "RequestConsent",
                "GetFeatures",
                "ListLocations",
                "Cancel",
                "Answer",
                "OpenStorageSettings",
                "ListDrives",
                "Mount",
                "Unmount"
            ]
        );
    }

    #[test]
    fn default_lanes() {
        let of = |lane| METHODS.iter().filter(move |m| m.lane == lane).map(|m| m.name).collect::<Vec<_>>();
        assert_eq!(of(Stream), ["OpenRead", "Read", "ReadAhead", "Close"]);
        assert_eq!(
            of(Bulk),
            ["Checksum", "ServerCopy", "Upload", "Download", "CopyAcross", "RemoveTree", "Walk"]
        );
    }

    #[test]
    fn lane_names() {
        for lane in [Interactive, Bulk, Stream] {
            assert_eq!(Lane::parse(lane.as_str()), Some(lane));
        }
        assert_eq!(Lane::parse(""), None);
        assert_eq!(Lane::parse("Bulk"), None);
        assert_eq!(Lane::from_hint("", Stream), Some(Stream));
        assert_eq!(Lane::from_hint("bulk", Stream), Some(Bulk));
        assert_eq!(Lane::from_hint("fast", Stream), None);
    }

    #[test]
    fn signals_by_name() {
        assert_eq!(find_signal("ListBatch"), Some("ua(ayyyxxxxixxssqays)"));
        assert_eq!(find_signal("LocationsChanged"), Some(""));
        assert_eq!(find_signal("Hello"), None);
        assert!(SIGNALS.iter().all(|(_, sig)| !sig.contains("(ayyy") || sig.contains(ENTRY_SIGNATURE)));
    }
}
