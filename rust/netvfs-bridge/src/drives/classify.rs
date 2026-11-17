// SPDX-License-Identifier: LGPL-2.1-or-later
//! Which of UDisks2's block devices `ListDrives` lists, a pure function of `GetManagedObjects`' answer (testable and fuzzable without a bus).
//!
//! Listed: a filesystem UDisks2 can mount, or a locked LUKS device; not system, not hidden; on a USB drive or a drive with an SD medium. Unlocked contents of an encrypted device go by that device's hints and drive. The internal eMMC is on the `sdio` bus like a card, but its medium is `flash_mmc`.

use netvfs_bridge_proto::{
    WireDrive, drive_info, value_bool, value_bytes, value_i64, value_str, value_strings,
};
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Str, Value};

/// Block device interface.
pub const BLOCK: &str = "org.freedesktop.UDisks2.Block";
/// Mountable filesystem interface.
pub const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
/// Drive interface.
pub const DRIVE: &str = "org.freedesktop.UDisks2.Drive";
/// Encrypted device interface.
pub const ENCRYPTED: &str = "org.freedesktop.UDisks2.Encrypted";
/// Object paths of block devices; a drive id follows.
pub const BLOCK_DEVICES: &str = "/org/freedesktop/UDisks2/block_devices/";

/// Properties of one interface.
pub type Properties = HashMap<String, OwnedValue>;
/// Interfaces of one object.
pub type Interfaces = HashMap<String, Properties>;
/// What `GetManagedObjects` answers.
pub type ManagedObjects = HashMap<OwnedObjectPath, Interfaces>;

/// Kind of drive a listed device is on.
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

/// A listed block device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drive {
    /// Last element of its object path.
    pub id: String,
    /// `IdLabel`; empty without one.
    pub label: String,
    /// First mount point without the NUL; empty if not mounted.
    pub mount_point: Vec<u8>,
    /// The drive it is on.
    pub kind: Kind,
    /// Bytes.
    pub size: i64,
    /// `IdType`.
    pub fs_type: String,
    /// Whether read-only.
    pub read_only: bool,
    /// `IdUUID`; may be empty.
    pub uuid: String,
    /// Drive vendor and model; may be empty.
    pub model: String,
    /// Locked LUKS device: Settings → Storage unlocks it; no passphrase passes through the bridge, so never mounted.
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
    // UDisks2 marks every device without a drive a system device (`update_hints`): an unlocked one goes by its encrypted device.
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

fn backing<'a>(objects: &'a ManagedObjects, block: &'a Properties) -> Option<&'a Properties> {
    match object(block, "CryptoBackingDevice") {
        Some(backing) => objects.iter().find(|(p, _)| p.as_str() == backing)?.1.get(BLOCK),
        None => Some(block),
    }
}

fn drive_of<'a>(objects: &'a ManagedObjects, block: &Properties) -> Option<&'a Properties> {
    let drive = object(block, "Drive")?;
    objects.iter().find(|(p, _)| p.as_str() == drive)?.1.get(DRIVE)
}

/// USB drives and memory cards of any bus; the eMMC's medium is `flash_mmc` (udev's `80-udisks2.rules`).
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

fn object<'a>(props: &'a Properties, name: &str) -> Option<&'a str> {
    match props.get(name).map(|v| &**v) {
        Some(Value::ObjectPath(p)) if p.as_str() != "/" => Some(p.as_str()),
        _ => None,
    }
}

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
