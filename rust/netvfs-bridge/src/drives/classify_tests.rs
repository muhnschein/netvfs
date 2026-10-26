// SPDX-License-Identifier: LGPL-2.1-or-later
// XB-20: what is listed of the devices of a phone with an SD card, a USB
// stick and an internal eMMC, as UDisks2 describes them.

use super::{BLOCK, BLOCK_DEVICES, DRIVE, ENCRYPTED, FILESYSTEM, Kind, ManagedObjects, drives};
use crate::drives::sample::{
    CARD, EMMC, STICK, block, cleartext, device, drive, encrypted_card, luks, object_path, owned, phone, set,
    unlock,
};
use netvfs_bridge_proto::{drive_info, value_bool, value_i64, value_str};
use zbus::zvariant::serialized::{Context, Data};
use zbus::zvariant::{LE, OwnedObjectPath, OwnedValue, to_bytes};

fn ids(objects: &ManagedObjects) -> Vec<String> {
    drives(objects).into_iter().map(|d| d.id).collect()
}

#[test]
fn cards_and_usb_drives_but_never_the_emmc() {
    let objects = phone();
    let listed = drives(&objects);
    assert_eq!(listed.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["mmcblk1p1", "sda1"]);
    let card = &listed[0];
    assert_eq!((card.kind, card.label.as_str(), card.fs_type.as_str()), (Kind::Sd, "CARD", "vfat"));
    assert_eq!((card.size, card.read_only, card.uuid.as_str()), (64_000_000_000, false, "1234-ABCD"));
    assert_eq!(card.model, "SanDisk Ultra");
    assert!(card.mount_point.is_empty());
    assert_eq!(card.object_path(), "/org/freedesktop/UDisks2/block_devices/mmcblk1p1");
    assert_eq!(listed[1].kind, Kind::Usb);
    assert_eq!(listed[1].label, "");
}

#[test]
fn a_card_in_a_reader_and_the_sdhc_and_sdxc_media() {
    let mut objects = phone();
    for media in ["flash_sdhc", "flash_sdxc"] {
        objects.insert(OwnedObjectPath::try_from(CARD).unwrap(), drive("", &["flash_cf", media]));
        assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"], "{media}");
    }
    objects.insert(OwnedObjectPath::try_from(CARD).unwrap(), drive("sdio", &[]));
    assert_eq!(ids(&objects), ["sda1"]);
}

#[test]
fn system_hidden_and_unmountable_devices_are_not_listed() {
    let cases: [(&str, &str, OwnedValue); 4] = [
        (BLOCK, "HintSystem", owned(true)),
        (BLOCK, "HintIgnore", owned(true)),
        (BLOCK, "IdUsage", owned("crypto")),
        (BLOCK, "IdUsage", owned("other")),
    ];
    for (iface, name, value) in cases {
        let mut objects = phone();
        let shown = format!("{name}={value:?}");
        set(objects.get_mut(&device("sda1")).unwrap(), iface, name, value);
        assert_eq!(ids(&objects), ["mmcblk1p1"], "{shown}");
    }
    // A partition table has no Filesystem.
    let mut objects = phone();
    objects.get_mut(&device("sda1")).unwrap().remove(FILESYSTEM);
    assert_eq!(ids(&objects), ["mmcblk1p1"]);
}

#[test]
fn devices_without_a_drive_or_of_an_unknown_drive_are_not_listed() {
    let mut objects = phone();
    // A logical volume on the eMMC, and a device of a drive that is gone.
    objects.insert(device("dm_2d0"), block("/", "home"));
    objects.insert(device("sdb1"), block("/org/freedesktop/UDisks2/drives/gone", "x"));
    let mut no_drive = block(STICK, "y");
    no_drive.get_mut(BLOCK).unwrap().remove("Drive");
    objects.insert(device("sdc1"), no_drive);
    assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"]);
}

#[test]
fn an_unlocked_card_is_listed_through_its_backing_device() {
    let mut objects = phone();
    objects.insert(device("dm_2d3"), cleartext("mmcblk1p1", "SECRET"));
    // The unlocked contents of an encrypted eMMC partition (Sailfish's home).
    objects.insert(device("dm_2d4"), cleartext("mmcblk0p20", "home"));
    // A backing device that is not there.
    objects.insert(device("dm_2d5"), cleartext("sdz9", "lost"));
    let listed = drives(&objects);
    assert_eq!(listed.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["dm_2d3", "mmcblk1p1", "sda1"]);
    assert_eq!((listed[0].kind, listed[0].label.as_str()), (Kind::Sd, "SECRET"));
}

#[test]
fn an_unlocked_device_goes_by_the_hints_of_its_encrypted_device() {
    // UDisks2 marks the cleartext device a system device: no drive.
    let mut objects = phone();
    objects.insert(device("dm_2d3"), cleartext("mmcblk1p1", "SECRET"));
    assert_eq!(ids(&objects), ["dm_2d3", "mmcblk1p1", "sda1"]);
    for name in ["HintSystem", "HintIgnore"] {
        let mut objects = phone();
        set(objects.get_mut(&device("mmcblk1p1")).unwrap(), BLOCK, name, owned(true));
        objects.insert(device("dm_2d3"), cleartext("mmcblk1p1", "SECRET"));
        assert_eq!(ids(&objects), ["sda1"], "{name} of the encrypted device");
    }
    let mut objects = phone();
    let mut hidden = cleartext("mmcblk1p1", "SECRET");
    set(&mut hidden, BLOCK, "HintIgnore", owned(true));
    objects.insert(device("dm_2d3"), hidden);
    assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"]);
}

#[test]
fn a_card_encrypted_whole_as_a_phone_describes_it() {
    let listed = drives(&encrypted_card(false));
    let seen = listed.iter().map(|d| (d.id.as_str(), d.locked)).collect::<Vec<_>>();
    assert_eq!(seen, [("mmcblk0", true)]);
    assert_eq!((listed[0].kind, listed[0].label.as_str()), (Kind::Sd, ""));
    // Unlocked: its cleartext device, a system device to UDisks2, and not
    // the cleartext device of `/home`, whose encrypted device has no drive.
    let listed = drives(&encrypted_card(true));
    let seen = listed.iter().map(|d| (d.id.as_str(), d.locked)).collect::<Vec<_>>();
    assert_eq!(seen, [("dm_2d3", false)]);
    let card = &listed[0];
    assert_eq!((card.kind, card.label.as_str(), card.fs_type.as_str()), (Kind::Sd, "PHOTOS", "ext4"));
    assert!(card.mount_point.is_empty());
    // `/home` stays out by its encrypted device's drive too: it has none.
    let mut objects = encrypted_card(true);
    set(objects.get_mut(&device("dm_2d1")).unwrap(), BLOCK, "HintSystem", owned(false));
    assert_eq!(ids(&objects), ["dm_2d3"]);
}

#[test]
fn a_locked_luks_device_is_listed_as_locked() {
    let mut objects = phone();
    objects.insert(device("mmcblk1p2"), luks(CARD, "VAULT"));
    objects.insert(device("sdb1"), luks(STICK, ""));
    let listed = drives(&objects);
    let ids = listed.iter().map(|d| (d.id.as_str(), d.locked)).collect::<Vec<_>>();
    assert_eq!(ids, [("mmcblk1p1", false), ("mmcblk1p2", true), ("sda1", false), ("sdb1", true)]);
    let vault = &listed[1];
    assert_eq!(
        (vault.kind, vault.label.as_str(), vault.fs_type.as_str()),
        (Kind::Sd, "VAULT", "crypto_LUKS")
    );
    assert_eq!((vault.size, vault.uuid.as_str()), (64_000_000_000, "5c1e0a4f-6d2b-4b8e-9f3a-2e7d1c0b9a88"));
    assert!(vault.mount_point.is_empty());
    assert_eq!((listed[3].kind, listed[3].label.as_str()), (Kind::Usb, ""));
    let wire = vault.wire();
    assert_eq!(value_bool(&wire.info[drive_info::LOCKED]), Some(true));
    assert_eq!(value_str(&wire.info[drive_info::FS_TYPE]).as_deref(), Some("crypto_LUKS"));
    assert!(!listed[0].wire().info.contains_key(drive_info::LOCKED));
}

#[test]
fn an_unlocked_luks_device_is_listed_by_its_cleartext_device_only() {
    let mut objects = phone();
    objects.insert(device("mmcblk1p2"), luks(CARD, "VAULT"));
    unlock(&mut objects, "mmcblk1p2", "dm_2d3", "SECRET");
    let listed = drives(&objects);
    let ids = listed.iter().map(|d| (d.id.as_str(), d.locked)).collect::<Vec<_>>();
    assert_eq!(ids, [("dm_2d3", false), ("mmcblk1p1", false), ("sda1", false)]);
    assert_eq!((listed[0].kind, listed[0].label.as_str()), (Kind::Sd, "SECRET"));
}

#[test]
fn luks_devices_of_the_emmc_hidden_or_of_other_kinds_are_not_listed() {
    let mut objects = phone();
    // The encrypted home of Sailfish OS on the eMMC.
    objects.insert(device("mmcblk0p21"), luks(EMMC, "home"));
    assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"]);
    let cases: [(&str, &str, OwnedValue); 4] = [
        (BLOCK, "HintSystem", owned(true)),
        (BLOCK, "HintIgnore", owned(true)),
        // Only LUKS, which Settings → Storage encrypts with, is listed.
        (BLOCK, "IdType", owned("BitLocker")),
        // A cleartext device that is not one of the listed objects still
        // means unlocked.
        (ENCRYPTED, "CleartextDevice", object_path(&format!("{BLOCK_DEVICES}dm_2d9"))),
    ];
    for (iface, name, value) in cases {
        let mut objects = phone();
        let mut vault = luks(CARD, "VAULT");
        let shown = format!("{name}={value:?}");
        set(&mut vault, iface, name, value);
        objects.insert(device("mmcblk1p2"), vault);
        assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"], "{shown}");
    }
    // Without the Encrypted interface UDisks2 cannot unlock it.
    let mut objects = phone();
    let mut vault = luks(CARD, "VAULT");
    vault.remove(ENCRYPTED);
    objects.insert(device("mmcblk1p2"), vault);
    assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"]);
}

#[test]
fn only_block_devices_with_valid_ids() {
    let mut objects = phone();
    objects.insert(OwnedObjectPath::try_from("/org/freedesktop/UDisks2/jobs/7").unwrap(), block(CARD, "j"));
    objects.insert(
        OwnedObjectPath::try_from("/org/freedesktop/UDisks2/block_devices").unwrap(),
        block(CARD, "r"),
    );
    objects.insert(device(&"x".repeat(65)), block(CARD, "long"));
    assert_eq!(ids(&objects), ["mmcblk1p1", "sda1"]);
}

#[test]
fn the_first_mount_point_without_its_nul() {
    let mut objects = phone();
    let points = vec![b"/run/media/defaultuser/CARD\0".to_vec(), b"/mnt/other\0".to_vec()];
    set(objects.get_mut(&device("mmcblk1p1")).unwrap(), FILESYSTEM, "MountPoints", owned(points));
    set(
        objects.get_mut(&device("sda1")).unwrap(),
        FILESYSTEM,
        "MountPoints",
        owned(vec![b"/no/nul".to_vec()]),
    );
    let listed = drives(&objects);
    assert_eq!(listed[0].mount_point, b"/run/media/defaultuser/CARD");
    assert_eq!(listed[1].mount_point, b"/no/nul");
    // Values of other types count as unknown.
    set(objects.get_mut(&device("sda1")).unwrap(), FILESYSTEM, "MountPoints", owned("/x"));
    set(objects.get_mut(&device("sda1")).unwrap(), BLOCK, "Size", owned("big"));
    set(objects.get_mut(&device("sda1")).unwrap(), BLOCK, "IdLabel", owned(7_u32));
    let stick = &drives(&objects)[1];
    assert!(stick.mount_point.is_empty());
    assert_eq!((stick.size, stick.label.as_str()), (-1, ""));
}

#[test]
fn the_wire_entry() {
    let mut objects = phone();
    set(objects.get_mut(&device("sda1")).unwrap(), BLOCK, "IdUUID", owned(""));
    set(objects.get_mut(&device("sda1")).unwrap(), BLOCK, "ReadOnly", owned(true));
    if let Some(d) = objects.get_mut(&OwnedObjectPath::try_from(STICK).unwrap()) {
        set(d, DRIVE, "Vendor", owned(""));
        set(d, DRIVE, "Model", owned(" "));
    }
    let listed = drives(&objects);
    let card = listed[0].wire();
    assert_eq!((card.id.as_str(), card.label.as_str()), ("mmcblk1p1", "CARD"));
    assert_eq!(value_str(&card.info[drive_info::KIND]).as_deref(), Some("sd"));
    assert_eq!(value_i64(&card.info[drive_info::SIZE]), Some(64_000_000_000));
    assert_eq!(value_str(&card.info[drive_info::FS_TYPE]).as_deref(), Some("vfat"));
    assert_eq!(value_bool(&card.info[drive_info::READ_ONLY]), Some(false));
    assert_eq!(value_str(&card.info[drive_info::UUID]).as_deref(), Some("1234-ABCD"));
    assert_eq!(value_str(&card.info[drive_info::MODEL]).as_deref(), Some("SanDisk Ultra"));
    let stick = listed[1].wire();
    assert_eq!(value_str(&stick.info[drive_info::KIND]).as_deref(), Some("usb"));
    assert_eq!(value_bool(&stick.info[drive_info::READ_ONLY]), Some(true));
    assert!(!stick.info.contains_key(drive_info::UUID) && !stick.info.contains_key(drive_info::MODEL));
}

/// As the fuzz target `udisks_objects` does: answers cut short or with a
/// byte flipped decode or fail, and what decodes is classified.
#[test]
fn damaged_answers_fail_or_classify() {
    let ctxt = Context::new_dbus(LE, 0);
    let bytes = to_bytes(ctxt, &phone()).unwrap().to_vec();
    let decode =
        |bytes: &[u8]| Data::new(bytes, ctxt).deserialize::<ManagedObjects>().map(|(objects, _)| objects);
    assert_eq!(ids(&decode(&bytes).unwrap()), ["mmcblk1p1", "sda1"]);
    let mut decoded = 0;
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 0x5a;
        for damaged in [&bytes[..at], flipped.as_slice()] {
            if let Ok(objects) = decode(damaged) {
                decoded += 1;
                for drive in drives(&objects) {
                    drop(drive.wire());
                }
            }
        }
    }
    assert!(decoded > 0);
}
