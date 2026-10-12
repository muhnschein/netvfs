// SPDX-License-Identifier: LGPL-2.1-or-later
//! The helper's command line (anyone can run it): NUL-separated arguments,
//! answered from an empty database.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_accounts::db::Database;
use netvfs_accounts::serve::{serve_with, Command};
use netvfs_accounts::store::Store;

fuzz_target!(|data: &[u8]| {
    let arguments: Vec<String> =
        data.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    let _ = serve_with(&Command::parse(&arguments), Store::new(Database::empty()));
});
