// SPDX-License-Identifier: LGPL-2.1-or-later
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_bridge::drives::classify::{ManagedObjects, drives};
use zbus::zvariant::LE;
use zbus::zvariant::serialized::{Context, Data};

fuzz_target!(|data: &[u8]| {
    let Ok((objects, _)) = Data::new(data, Context::new_dbus(LE, 0)).deserialize::<ManagedObjects>() else {
        return;
    };
    for drive in drives(&objects) {
        let _ = drive.wire();
    }
});
