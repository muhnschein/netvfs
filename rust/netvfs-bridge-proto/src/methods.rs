// SPDX-License-Identifier: LGPL-2.1-or-later
//! Names, the method table and the signals of `org.netvfs.Bridge1`
//! (SPEC-v2 XB-8..XB-10). The table is in the order of the C++ bridge's
//! `args.cpp` (netvfs 0.4), which is also the order of the introspection
//! XML; `tests/contract.rs` checks both against the XML.

/// Object path of the bridge (XB-8).
pub const OBJECT_PATH: &str = "/org/netvfs/Bridge";
/// The bridge interface (XB-8).
pub const INTERFACE: &str = "org.netvfs.Bridge1";
/// Protocol version that `Hello` announces and expects (XB-8).
pub const PROTOCOL_VERSION: u32 = 1;
/// Feature strings that `Hello` announces (XB-8: an additive change adds
/// one). `error-details`: error replies carry a second argument `a{sv}` with
/// `detail` and `retryAfterMs` (XC-24).
pub const FEATURES: [&str; 1] = ["error-details"];
/// Signature of the `Entry` struct (XB-9).
pub const ENTRY_SIGNATURE: &str = "(ayyyxxxxixxssqays)";
/// The introspection data the bridge serves, byte for byte (design §3.5). A
/// copy of the contract's `tests/bridge/contract/org.netvfs.Bridge1.xml`;
/// `tests/contract.rs` keeps the two equal.
pub const INTROSPECTION_XML: &str = include_str!("../org.netvfs.Bridge1.xml");

/// The connection pool a call runs in (XB-12). A call may hint a lane; an
/// empty hint selects the method's default.
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

    /// A lane from its wire name, or `None` for an unknown name. The empty
    /// hint is not a name: see [`Lane::from_hint`].
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
    /// XB-6: fails with `PermissionDenied` until the user granted consent.
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
pub const METHODS: [MethodInfo; 35] = [
    method("Hello", "us", "usas", Interactive, false),
    method("GetConsent", "", "s", Interactive, false),
    method("RequestConsent", "", "", Interactive, false),
    // Without consent it returns nothing instead of failing (XB-6).
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
    // Cancel and Answer need no consent (args.cpp).
    method("Cancel", "u", "", Interactive, false),
    method("Answer", "sa{sv}", "", Interactive, false),
    method("OpenAccountSettings", "s", "", Interactive, true),
    method("AddAccount", "s", "", Interactive, true),
];

/// The signals as `(name, signature)`, in the order of the XML.
pub const SIGNALS: [(&str, &str); 9] = [
    ("ConsentChanged", "s"),
    ("LocationsChanged", ""),
    ("NearbyChanged", "a(sssqay)"),
    ("ListBatch", "ua(ayyyxxxxixxssqays)"),
    ("ListDone", "uss"),
    ("JobProgress", "uxx"),
    ("WalkBatch", "ua(ay(ayyyxxxxixxssqays))"),
    ("JobFinished", "ussa{sv}"),
    ("Question", "ssa{sv}"),
];

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

    // netvfs 0.4's tst_bridgeunits methodTable: every method of XB-10 exactly once.
    #[test]
    fn method_table_order_and_consent() {
        let expected = [
            "Hello",
            "GetConsent",
            "RequestConsent",
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
        ];
        let names: Vec<&str> = METHODS.iter().map(|m| m.name).collect();
        assert_eq!(names, expected);
        assert!(find_method("Stat").unwrap().needs_consent);
        assert!(!find_method("Hello").unwrap().needs_consent);
        assert!(!find_method("ListLocations").unwrap().needs_consent);
        assert!(find_method("Nope").is_none());
        let free: Vec<&str> = METHODS.iter().filter(|m| !m.needs_consent).map(|m| m.name).collect();
        assert_eq!(free, ["Hello", "GetConsent", "RequestConsent", "ListLocations", "Cancel", "Answer"]);
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
