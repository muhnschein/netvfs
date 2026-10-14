// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writes the answers of netvfs-accounts' own encoder (wire.rs, qvariant.rs,
//! included by path) that `accounts::qds` must decode. Built by generate.sh
//! outside the workspace.
#![allow(dead_code)]

#[path = "../../../../netvfs-accounts/src/qvariant.rs"]
mod qvariant;
#[path = "../../../../netvfs-accounts/src/wire.rs"]
mod wire;

use qvariant::Value;
use wire::{Error, Outcome, Stream};

struct Params {
    provider: Option<&'static str>,
    host: Option<&'static str>,
    port: i32,
    username: Option<&'static str>,
    options: Vec<(String, Value)>,
    connect: i32,
    request: i32,
}

fn params(s: &mut Stream, p: &Params) {
    s.string(p.provider);
    s.string(p.host);
    s.i32(p.port);
    s.string(p.username);
    s.variant_map(&p.options);
    s.i32(p.connect);
    s.i32(p.request);
}

fn full() -> Params {
    Params {
        provider: Some("sftp"),
        host: Some("files.example"),
        port: 2222,
        username: Some("alice"),
        options: vec![
            ("key-file".into(), Value::String("/home/a/.ssh/id_ed25519".into())),
            ("compress".into(), Value::Bool(true)),
            ("negative".into(), Value::Int(-5)),
            ("unsigned".into(), Value::UInt(7)),
            ("long".into(), Value::LongLong(-1 << 40)),
            ("ulong".into(), Value::ULongLong(u64::MAX)),
            ("list".into(), Value::StringList(vec!["a".into(), "b c".into()])),
            ("map".into(), Value::Map(vec![("x".into(), Value::Invalid), ("é".into(), Value::Int(1))])),
            ("none".into(), Value::Invalid),
            ("Upper".into(), Value::String(String::new())),
        ],
        connect: 15000,
        request: 30000,
    }
}

fn empty() -> Params {
    Params { provider: None, host: None, port: 0, username: None, options: vec![], connect: 0, request: 0 }
}

fn write(name: &str, s: Stream) {
    std::fs::write(name, s.into_bytes()).unwrap();
}

fn main() {
    let mut s = Stream::answer(&Outcome::success());
    s.i32(3);
    s.i32(3);
    s.string(Some("sftp"));
    s.string(Some("Café ☕ 😀"));
    params(&mut s, &full());
    s.string(Some("/srv/ä"));
    s.i32(0);
    s.i32(4);
    s.string(Some("smb"));
    s.string(None);
    params(&mut s, &empty());
    s.string(None);
    s.i32(2);
    s.i32(i32::MAX);
    s.string(Some(""));
    s.string(Some("x"));
    params(&mut s, &empty());
    s.string(Some(""));
    s.i32(1);
    write("list.bin", s);

    let mut s = Stream::answer(&Outcome::success());
    s.i32(0);
    write("list-empty.bin", s);

    let mut s = Stream::answer(&Outcome::success());
    params(&mut s, &full());
    s.u32(42);
    s.bool(true);
    write("files.bin", s);

    write("ok.bin", Stream::answer(&Outcome::success()));
    write("not-found.bin", Stream::answer(&Outcome::failure(Error::NotFound, "No such account")));
    write("internal-empty.bin", Stream::answer(&Outcome::failure(Error::Internal, "")));
}
