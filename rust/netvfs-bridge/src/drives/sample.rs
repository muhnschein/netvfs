// SPDX-License-Identifier: LGPL-2.1-or-later
//! What UDisks2 describes of a phone with an SD card, a USB stick and an
//! internal eMMC (XB-20), for the tests of the classifier and the client.

use super::classify::{
    BLOCK, BLOCK_DEVICES, DRIVE, ENCRYPTED, FILESYSTEM, Interfaces, ManagedObjects, Properties,
};
use std::collections::HashMap;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub const CARD: &str = "/org/freedesktop/UDisks2/drives/SD_card_1234";
pub const EMMC: &str = "/org/freedesktop/UDisks2/drives/eMMC_5678";
pub const STICK: &str = "/org/freedesktop/UDisks2/drives/SanDisk_Ultra_9";

pub fn owned<'a>(v: impl Into<Value<'a>>) -> OwnedValue {
    OwnedValue::try_from(v.into()).unwrap()
}

pub fn object_path(p: &str) -> OwnedValue {
    OwnedValue::from(ObjectPath::try_from(p).unwrap())
}

pub fn props(pairs: Vec<(&str, OwnedValue)>) -> Properties {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

pub fn drive(bus: &str, media: &[&str]) -> Interfaces {
    let media: Vec<String> = media.iter().map(|m| (*m).to_owned()).collect();
    HashMap::from([(
        DRIVE.to_owned(),
        props(vec![
            ("ConnectionBus", owned(bus)),
            ("MediaCompatibility", owned(media)),
            ("Vendor", owned("  SanDisk ")),
            ("Model", owned("Ultra")),
        ]),
    )])
}

/// A block device of `drive` with a mountable `vfat` filesystem.
pub fn block(drive: &str, label: &str) -> Interfaces {
    HashMap::from([
        (
            BLOCK.to_owned(),
            props(vec![
                ("Drive", object_path(drive)),
                ("CryptoBackingDevice", object_path("/")),
                ("IdUsage", owned("filesystem")),
                ("IdType", owned("vfat")),
                ("IdLabel", owned(label)),
                ("IdUUID", owned("1234-ABCD")),
                ("Size", owned(64_000_000_000_u64)),
                ("ReadOnly", owned(false)),
                ("HintSystem", owned(false)),
                ("HintIgnore", owned(false)),
            ]),
        ),
        (FILESYSTEM.to_owned(), props(vec![("MountPoints", owned(Vec::<Vec<u8>>::new()))])),
    ])
}

/// A LUKS device of `drive` not unlocked: no filesystem, an `Encrypted`
/// interface without a cleartext device.
pub fn luks(drive: &str, label: &str) -> Interfaces {
    let mut ifaces = block(drive, label);
    ifaces.remove(FILESYSTEM);
    set(&mut ifaces, BLOCK, "IdUsage", owned("crypto"));
    set(&mut ifaces, BLOCK, "IdType", owned("crypto_LUKS"));
    set(&mut ifaces, BLOCK, "IdUUID", owned("5c1e0a4f-6d2b-4b8e-9f3a-2e7d1c0b9a88"));
    let encrypted =
        props(vec![("CleartextDevice", object_path("/")), ("HintEncryptionType", owned("luks2"))]);
    ifaces.insert(ENCRYPTED.to_owned(), encrypted);
    ifaces
}

/// Unlocks the LUKS device `id` of `objects` as `clear`, a cleartext
/// device with a `vfat` filesystem labelled `label`.
pub fn unlock(objects: &mut ManagedObjects, id: &str, clear: &str, label: &str) {
    let cleartext = format!("{BLOCK_DEVICES}{clear}");
    set(objects.get_mut(&device(id)).unwrap(), ENCRYPTED, "CleartextDevice", object_path(&cleartext));
    let mut contents = block("/", label);
    set(&mut contents, BLOCK, "CryptoBackingDevice", object_path(&format!("{BLOCK_DEVICES}{id}")));
    objects.insert(device(clear), contents);
}

pub fn set(ifaces: &mut Interfaces, iface: &str, name: &str, value: OwnedValue) {
    ifaces.get_mut(iface).unwrap().insert(name.to_owned(), value);
}

pub fn device(id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{BLOCK_DEVICES}{id}")).unwrap()
}

/// The card, the stick and the eMMC with a partition each.
pub fn phone() -> ManagedObjects {
    HashMap::from([
        (OwnedObjectPath::try_from(CARD).unwrap(), drive("sdio", &["flash_sd"])),
        (OwnedObjectPath::try_from(EMMC).unwrap(), drive("sdio", &["flash_mmc"])),
        (OwnedObjectPath::try_from(STICK).unwrap(), drive("usb", &[])),
        (device("mmcblk1p1"), block(CARD, "CARD")),
        (device("mmcblk0p20"), block(EMMC, "persist")),
        (device("sda1"), block(STICK, "")),
    ])
}
