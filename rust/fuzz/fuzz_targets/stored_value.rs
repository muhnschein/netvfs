// SPDX-License-Identifier: LGPL-2.1-or-later
//! A setting row as the accounts database may hold it: type string and
//! value text (the first byte gives the type's length), read as the helper
//! reads it and written into an answer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_accounts::gvariant::from_db;
use netvfs_accounts::qvariant::Value;
use netvfs_accounts::wire::Stream;

fuzz_target!(|data: &[u8]| {
    let Some((&length, rest)) = data.split_first() else { return };
    let split = usize::from(length % 8).min(rest.len());
    let (type_string, text) = rest.split_at(split);
    let value = from_db(type_string, Some(text));
    let _ = value.to_qstring();
    let _ = value.to_int();
    let mut stream = Stream::new();
    stream.variant(&value);
    stream.variant_map(&[("k".to_owned(), value), ("j".to_owned(), Value::Invalid)]);
});
