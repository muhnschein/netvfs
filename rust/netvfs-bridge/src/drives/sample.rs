// SPDX-License-Identifier: LGPL-2.1-or-later
//! UDisks2 descriptions of a phone with SD card, USB stick and eMMC, and one with an encrypted card, for classifier and client tests.

use super::classify::{
    BLOCK, BLOCK_DEVICES, DRIVE, ENCRYPTED, FILESYSTEM, Interfaces, ManagedObjects, Properties,
};
use std::collections::HashMap;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub const CARD: &str = "/org/freedesktop/UDisks2/drives/SD_card_1234";
pub const EMMC: &str = "/org/freedesktop/UDisks2/drives/eMMC_5678";
pub const STICK: &str = "/org/freedesktop/UDisks2/drives/SanDisk_Ultra_9";
pub const UFS: &str = "/org/freedesktop/UDisks2/drives/UFS_4321";

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

/// A locked LUKS device of `drive`: no filesystem, `Encrypted` without cleartext device.
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

/// Unlocked contents of encrypted `backing`: `vfat` labelled `label`, no drive (system device to UDisks2).
pub fn cleartext(backing: &str, label: &str) -> Interfaces {
    let mut contents = block("/", label);
    set(&mut contents, BLOCK, "CryptoBackingDevice", object_path(&format!("{BLOCK_DEVICES}{backing}")));
    set(&mut contents, BLOCK, "HintSystem", owned(true));
    contents
}

/// Unlocks LUKS device `id` of `objects` as `clear`.
pub fn unlock(objects: &mut ManagedObjects, id: &str, clear: &str, label: &str) {
    let cleartext_device = format!("{BLOCK_DEVICES}{clear}");
    set(objects.get_mut(&device(id)).unwrap(), ENCRYPTED, "CleartextDevice", object_path(&cleartext_device));
    objects.insert(device(clear), cleartext(id, label));
}

pub fn set(ifaces: &mut Interfaces, iface: &str, name: &str, value: OwnedValue) {
    ifaces.get_mut(iface).unwrap().insert(name.to_owned(), value);
}

pub fn device(id: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(format!("{BLOCK_DEVICES}{id}")).unwrap()
}

/// Card, stick and eMMC with a partition each.
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

/// Phone with internal UFS and a whole-card encrypted memory card, `unlocked` as `dm_2d3` or not. Internal devices are system devices; root and encrypted `/home` are mapped without a drive.
pub fn encrypted_card(unlocked: bool) -> ManagedObjects {
    let system = |mut ifaces: Interfaces, mount_point: &[u8]| {
        set(&mut ifaces, BLOCK, "HintSystem", owned(true));
        set(&mut ifaces, BLOCK, "IdType", owned("ext4"));
        if !mount_point.is_empty() {
            set(&mut ifaces, FILESYSTEM, "MountPoints", owned(vec![[mount_point, b"\0"].concat()]));
        }
        ifaces
    };
    let mut home = luks("/", "");
    set(&mut home, BLOCK, "HintSystem", owned(true));
    let mut objects = HashMap::from([
        (OwnedObjectPath::try_from(CARD).unwrap(), drive("sdio", &["flash_sd"])),
        (OwnedObjectPath::try_from(UFS).unwrap(), drive("", &[])),
        (device("mmcblk0"), luks(CARD, "")),
        (device("sdc70"), system(block(UFS, ""), b"")),
        (device("loop0"), system(block("/", ""), b"/apex/com.android.runtime")),
        (device("dm_2d0"), system(block("/", "root"), b"/")),
        (device("dm_2d1"), home),
    ]);
    unlock(&mut objects, "dm_2d1", "dm_2d2", "");
    let cleartext = objects.get_mut(&device("dm_2d2")).unwrap();
    set(cleartext, FILESYSTEM, "MountPoints", owned(vec![b"/home\0".to_vec()]));
    if unlocked {
        unlock(&mut objects, "mmcblk0", "dm_2d3", "PHOTOS");
        set(objects.get_mut(&device("dm_2d3")).unwrap(), BLOCK, "IdType", owned("ext4"));
    }
    objects
}
