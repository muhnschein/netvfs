// SPDX-License-Identifier: LGPL-2.1-or-later
//! Which of UDisks2's block devices `ListDrives` lists (SPEC-v2 XB-20), from
//! what `GetManagedObjects` answers: a pure function of that answer, so that
//! it can be tested and fuzzed without a bus.
//!
//! A block device is listed when it has a filesystem UDisks2 can mount or is
//! a LUKS device not unlocked, is neither a system device nor hidden, and
//! belongs to a USB drive or to a drive with an SD medium. The unlocked
//! contents of an encrypted device go by that device: its hints, its drive.
//! The internal eMMC is on the `sdio` bus like a memory card, but its medium
//! is `flash_mmc`.

use netvfs_bridge_proto::{
    WireDrive, drive_info, value_bool, value_bytes, value_i64, value_str, value_strings,
};
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Str, Value};

/// UDisks2's interface of block devices.
pub const BLOCK: &str = "org.freedesktop.UDisks2.Block";
/// UDisks2's interface of a mountable filesystem.
pub const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
/// UDisks2's interface of drives.
pub const DRIVE: &str = "org.freedesktop.UDisks2.Drive";
/// UDisks2's interface of an encrypted device.
pub const ENCRYPTED: &str = "org.freedesktop.UDisks2.Encrypted";
/// The object paths of block devices; a drive id is what follows.
pub const BLOCK_DEVICES: &str = "/org/freedesktop/UDisks2/block_devices/";

/// The properties of one interface.
pub type Properties = HashMap<String, OwnedValue>;
/// The interfaces of one object.
pub type Interfaces = HashMap<String, Properties>;
/// What `org.freedesktop.DBus.ObjectManager.GetManagedObjects` answers.
pub type ManagedObjects = HashMap<OwnedObjectPath, Interfaces>;

/// What kind of drive a listed device is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A memory card.
    Sd,
    /// A USB drive.
    Usb,
}

impl Kind {
    /// The name `ListDrives` gives it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sd => drive_info::KIND_SD,
            Self::Usb => drive_info::KIND_USB,
        }
    }
}

/// A listed block device (XB-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drive {
    /// The last element of its object path.
    pub id: String,
    /// Its `IdLabel`; empty without one.
    pub label: String,
    /// Its first mount point, without the terminating NUL; empty when it is
    /// not mounted.
    pub mount_point: Vec<u8>,
    /// The drive it is on.
    pub kind: Kind,
    /// Bytes.
    pub size: i64,
    /// `IdType`.
    pub fs_type: String,
    /// Whether the device is read-only.
    pub read_only: bool,
    /// `IdUUID`; may be empty.
    pub uuid: String,
    /// The drive's vendor and model; may be empty.
    pub model: String,
    /// A LUKS device not unlocked: Settings → Storage unlocks it, no
    /// passphrase passes through the bridge, so it is never mounted.
    pub locked: bool,
}

impl Drive {
    /// Its object path.
    #[must_use]
    pub fn object_path(&self) -> String {
        format!("{BLOCK_DEVICES}{}", self.id)
    }

    /// The entry of `ListDrives`.
    #[must_use]
    pub fn wire(&self) -> WireDrive {
        let mut info = HashMap::from([
            (drive_info::KIND.to_owned(), owned_text(self.kind.as_str())),
            (drive_info::SIZE.to_owned(), OwnedValue::from(self.size)),
            (drive_info::FS_TYPE.to_owned(), owned_text(&self.fs_type)),
            (drive_info::READ_ONLY.to_owned(), OwnedValue::from(self.read_only)),
        ]);
        for (key, text) in [(drive_info::UUID, &self.uuid), (drive_info::MODEL, &self.model)] {
            if !text.is_empty() {
                info.insert(key.to_owned(), owned_text(text));
            }
        }
        if self.locked {
            info.insert(drive_info::LOCKED.to_owned(), OwnedValue::from(true));
        }
        WireDrive {
            id: self.id.clone(),
            label: self.label.clone(),
            mount_point: self.mount_point.clone(),
            info,
        }
    }
}

/// The drives of `objects`, sorted by id.
#[must_use]
pub fn drives(objects: &ManagedObjects) -> Vec<Drive> {
    let mut found: Vec<Drive> =
        objects.iter().filter_map(|(path, ifaces)| listed(objects, path, ifaces)).collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

fn listed(objects: &ManagedObjects, path: &OwnedObjectPath, ifaces: &Interfaces) -> Option<Drive> {
    let id = path.as_str().strip_prefix(BLOCK_DEVICES).filter(|id| drive_info::is_valid_id(id))?;
    let block = ifaces.get(BLOCK)?;
    let (mount_point, locked) = contents(block, ifaces)?;
    let backing = backing(objects, block)?;
    // UDisks2 marks every device without a drive a system device
    // (`update_hints`), so an unlocked one goes by its encrypted device.
    if flag(backing, "HintSystem") || flag(backing, "HintIgnore") || flag(block, "HintIgnore") {
        return None;
    }
    let drive = drive_of(objects, backing)?;
    let kind = kind(drive)?;
    let model = [text(drive, "Vendor"), text(drive, "Model")]
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some(Drive {
        id: id.to_owned(),
        label: text(block, "IdLabel"),
        mount_point,
        kind,
        size: block.get("Size").and_then(|v| value_i64(v)).unwrap_or(-1),
        fs_type: text(block, "IdType"),
        read_only: flag(block, "ReadOnly"),
        uuid: text(block, "IdUUID"),
        model,
        locked,
    })
}

/// What a listed block device holds: a filesystem UDisks2 can mount, with
/// its first mount point (empty while not mounted), or a LUKS device not
/// unlocked (locked). Once unlocked, its cleartext device is listed instead
/// ([`backing`]).
fn contents(block: &Properties, ifaces: &Interfaces) -> Option<(Vec<u8>, bool)> {
    match text(block, "IdUsage").as_str() {
        "filesystem" => {
            let points = ifaces.get(FILESYSTEM)?.get("MountPoints").and_then(|v| mount_points(v));
            Some((points.unwrap_or_default().into_iter().next().unwrap_or_default(), false))
        }
        "crypto" if text(block, "IdType") == "crypto_LUKS" => {
            object(ifaces.get(ENCRYPTED)?, "CleartextDevice").is_none().then(|| (Vec::new(), true))
        }
        _ => None,
    }
}

/// The block device on the drive: the encrypted device `block` is the
/// unlocked contents of, else `block`.
fn backing<'a>(objects: &'a ManagedObjects, block: &'a Properties) -> Option<&'a Properties> {
    match object(block, "CryptoBackingDevice") {
        Some(backing) => objects.iter().find(|(p, _)| p.as_str() == backing)?.1.get(BLOCK),
        None => Some(block),
    }
}

/// The drive of a block device. Logical volumes and other mapped devices
/// have none.
fn drive_of<'a>(objects: &'a ManagedObjects, block: &Properties) -> Option<&'a Properties> {
    let drive = object(block, "Drive")?;
    objects.iter().find(|(p, _)| p.as_str() == drive)?.1.get(DRIVE)
}

/// USB drives, and memory cards of any bus (a card reader's medium is SD as
/// well); the eMMC's medium is `flash_mmc` (udev's `80-udisks2.rules`).
fn kind(drive: &Properties) -> Option<Kind> {
    if text(drive, "ConnectionBus") == "usb" {
        return Some(Kind::Usb);
    }
    let media = drive.get("MediaCompatibility").and_then(|v| value_strings(v)).unwrap_or_default();
    media.iter().any(|m| m.starts_with("flash_sd")).then_some(Kind::Sd)
}

fn owned_text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

fn text(props: &Properties, name: &str) -> String {
    props.get(name).and_then(|v| value_str(v)).unwrap_or_default()
}

fn flag(props: &Properties, name: &str) -> bool {
    props.get(name).and_then(|v| value_bool(v)).unwrap_or(false)
}

/// An object path property; `None` for `/` (UDisks2's "none").
fn object<'a>(props: &'a Properties, name: &str) -> Option<&'a str> {
    match props.get(name).map(|v| &**v) {
        Some(Value::ObjectPath(p)) if p.as_str() != "/" => Some(p.as_str()),
        _ => None,
    }
}

/// `MountPoints` (`aay`): NUL-terminated paths, as UDisks2 sends them.
fn mount_points(value: &Value<'_>) -> Option<Vec<Vec<u8>>> {
    let Value::Array(points) = value else { return None };
    points
        .iter()
        .map(|p| {
            value_bytes(p).map(|mut bytes| {
                if bytes.last() == Some(&0) {
                    bytes.pop();
                }
                bytes
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
