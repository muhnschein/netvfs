// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `AccountChanged` signal libaccounts-glib's writers send on the
//! session bus after a change (`signal_account_changes`, ag-manager.c), so
//! that other processes (Settings, the bridge) see the helper's write. Like a
//! libaccounts-glib manager on Sailfish OS, the connection owns a name
//! `com.google.code.AccountsSSO.Accounts.uuid_<guid>` first: Sailjail lets
//! sandboxed applications receive signals only from named senders.
//!
//! A minimal client: EXTERNAL authentication, `Hello`, `RequestName`, the
//! signal, then a `GetId` whose reply shows the bus has taken the signal.
//! Best-effort: the bridge lists again after its own writes anyway.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::db::NewSetting;
use crate::qvariant::Value;
use crate::serve::Change;

/// The interface of the signal.
pub const INTERFACE: &str = "com.google.code.AccountsSSO.Accounts";
/// The name of the signal.
pub const MEMBER: &str = "AccountChanged";
/// Changes of the account's global settings, whose service type is "global".
pub const GLOBAL_PATH: &str = "/ServiceType/global";
const BUS_NAME_PREFIX: &str = "com.google.code.AccountsSSO.Accounts.uuid_";
const TIMEOUT: Duration = Duration::from_secs(5);
/// What the bus may send before the reply that ends the exchange.
const MAX_READ: usize = 256 * 1024;
const MAX_MESSAGE: usize = 64 * 1024;

/// Where the session bus listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// A unix socket at this path.
    Path(PathBuf),
    /// A Linux abstract socket name (without the leading NUL).
    Abstract(Vec<u8>),
}

/// The session bus. A set-id process uses its uid's runtime folder only, as
/// GLib does there (it ignores `DBUS_SESSION_BUS_ADDRESS`); otherwise the
/// first unix address of `DBUS_SESSION_BUS_ADDRESS`, else
/// `$XDG_RUNTIME_DIR/bus`.
#[must_use]
pub fn session_bus(set_id: bool, runtime_dir: &std::path::Path) -> Option<Address> {
    if set_id {
        return Some(Address::Path(runtime_dir.join("bus")));
    }
    if let Some(address) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
        return parse_address(&address.to_string_lossy());
    }
    std::env::var_os("XDG_RUNTIME_DIR").map(|dir| Address::Path(PathBuf::from(dir).join("bus")))
}

fn unescape(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let Some((&first, after)) = rest.split_first() {
        if first == b'%' {
            let (hex, tail) = after.split_at_checked(2)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            rest = tail;
        } else {
            out.push(first);
            rest = after;
        }
    }
    Some(out)
}

/// The first `unix:path=` or `unix:abstract=` of a D-Bus address list.
#[must_use]
pub fn parse_address(list: &str) -> Option<Address> {
    use std::os::unix::ffi::OsStringExt;
    for address in list.split(';') {
        let Some(params) = address.strip_prefix("unix:") else { continue };
        for param in params.split(',') {
            if let Some(path) = param.strip_prefix("path=") {
                return Some(Address::Path(PathBuf::from(std::ffi::OsString::from_vec(unescape(path)?))));
            }
            if let Some(name) = param.strip_prefix("abstract=") {
                return Some(Address::Abstract(unescape(name)?));
            }
        }
    }
    None
}

// ---- marshalling (little-endian) ----

mod kind {
    pub const METHOD_CALL: u8 = 1;
    pub const METHOD_RETURN: u8 = 2;
    pub const ERROR: u8 = 3;
    pub const SIGNAL: u8 = 4;
}

mod field {
    pub const PATH: u8 = 1;
    pub const INTERFACE: u8 = 2;
    pub const MEMBER: u8 = 3;
    pub const REPLY_SERIAL: u8 = 5;
    pub const DESTINATION: u8 = 6;
    pub const SIGNATURE: u8 = 8;
}

const NO_REPLY_EXPECTED: u8 = 0x1;

#[derive(Debug, Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn align(&mut self, n: usize) {
        while !self.bytes.len().is_multiple_of(n) {
            self.bytes.push(0);
        }
    }

    fn byte(&mut self, b: u8) {
        self.bytes.push(b);
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    fn len32(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }

    fn bool(&mut self, b: bool) {
        self.u32(u32::from(b));
    }

    /// A string or object path: no NUL inside.
    fn string(&mut self, s: &str) {
        let s = s.replace('\0', "");
        self.len32(s.len());
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
    }

    fn signature(&mut self, s: &str) {
        self.byte(u8::try_from(s.len()).unwrap_or(0));
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
    }

    /// An array whose elements `body` writes; `element_alignment` is that
    /// of the element type.
    fn array(&mut self, element_alignment: usize, body: impl FnOnce(&mut Self)) {
        self.align(4);
        let at = self.bytes.len();
        self.u32(0);
        self.align(element_alignment);
        let start = self.bytes.len();
        body(self);
        let length = u32::try_from(self.bytes.len().saturating_sub(start)).unwrap_or(u32::MAX);
        // The placeholder written above: the body only appends, so it is still there.
        if let Some(slot) = self.bytes.get_mut(at..).and_then(<[u8]>::first_chunk_mut::<4>) {
            *slot = length.to_le_bytes();
        }
    }
}

/// A variant value of a changed setting, as libaccounts-glib sends it.
fn variant(w: &mut Writer, setting: &NewSetting) {
    match crate::gvariant::from_db(setting.type_string.as_bytes(), Some(setting.text.as_bytes())) {
        Value::Bool(b) => {
            w.signature("b");
            w.bool(b);
        }
        other => {
            w.signature("s");
            w.string(&other.to_qstring().unwrap_or_default());
        }
    }
}

/// The body of `AccountChanged`: `(uuubbsa(ssua{sv}as))`: time stamp,
/// account, created, deleted, provider, and per service its name, type, id,
/// changed and removed settings. The helper changes global settings only.
fn changed_body(change: &Change, (sec, nsec): (u64, u32)) -> Vec<u8> {
    let mut w = Writer::default();
    // libaccounts-glib stores the seconds as 32 bits too.
    w.u32(u32::try_from(sec & u64::from(u32::MAX)).unwrap_or(0));
    w.u32(nsec);
    w.u32(change.account_id);
    w.bool(false);
    w.bool(false);
    w.string(&change.provider);
    w.array(8, |w| {
        w.align(8);
        w.string("global");
        w.string("global");
        w.u32(0);
        w.array(8, |w| {
            for setting in &change.settings {
                w.align(8);
                w.string(&String::from_utf8_lossy(&setting.key));
                variant(w, setting);
            }
        });
        w.array(4, |_| {});
    });
    w.bytes
}

struct Header<'a> {
    kind: u8,
    flags: u8,
    serial: u32,
    path: &'a str,
    interface: &'a str,
    member: &'a str,
    destination: Option<&'a str>,
    signature: &'a str,
}

fn message(h: &Header<'_>, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.byte(b'l');
    w.byte(h.kind);
    w.byte(h.flags);
    w.byte(1);
    w.len32(body.len());
    w.u32(h.serial);
    w.array(8, |w| {
        let string_field = |w: &mut Writer, code: u8, sig: &str, value: &str| {
            w.align(8);
            w.byte(code);
            w.signature(sig);
            w.string(value);
        };
        string_field(w, field::PATH, "o", h.path);
        string_field(w, field::INTERFACE, "s", h.interface);
        string_field(w, field::MEMBER, "s", h.member);
        if let Some(d) = h.destination {
            string_field(w, field::DESTINATION, "s", d);
        }
        if !h.signature.is_empty() {
            w.align(8);
            w.byte(field::SIGNATURE);
            w.signature("g");
            w.signature(h.signature);
        }
    });
    w.align(8);
    w.bytes.extend_from_slice(body);
    w.bytes
}

fn bus_call(serial: u32, member: &str, signature: &str, body: &[u8]) -> Vec<u8> {
    message(
        &Header {
            kind: kind::METHOD_CALL,
            flags: 0,
            serial,
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member,
            destination: Some("org.freedesktop.DBus"),
            signature,
        },
        body,
    )
}

/// What the exchange sends after authentication: `Hello`, `RequestName`,
/// the signal, `GetId` (serial 4, the reply that ends it).
fn messages(change: &Change, guid: &str, time: (u64, u32)) -> Vec<u8> {
    let mut out = bus_call(1, "Hello", "", &[]);
    let mut name = Writer::default();
    name.string(&format!("{BUS_NAME_PREFIX}{guid}"));
    name.u32(4); // DBUS_NAME_FLAG_DO_NOT_QUEUE
    out.extend(bus_call(2, "RequestName", "su", &name.bytes));
    out.extend(message(
        &Header {
            kind: kind::SIGNAL,
            flags: NO_REPLY_EXPECTED,
            serial: 3,
            path: GLOBAL_PATH,
            interface: INTERFACE,
            member: MEMBER,
            destination: None,
            signature: "uuubbsa(ssua{sv}as)",
        },
        &changed_body(change, time),
    ));
    out.extend(bus_call(4, "GetId", "", &[]));
    out
}

const LAST_SERIAL: u32 = 4;

// ---- reading replies ----

/// A received message's type and reply serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    /// The message type: 1 call, 2 return, 3 error, 4 signal.
    pub kind: u8,
    /// The `REPLY_SERIAL` header field, if the message has one.
    pub reply_serial: Option<u32>,
}

/// Reads the fixed part of a message header: its total length.
fn total_length(fixed: &[u8; 16]) -> Option<usize> {
    let read = |at: usize| -> Option<u32> {
        let b: [u8; 4] = *fixed.get(at..)?.first_chunk::<4>()?;
        Some(match fixed[0] {
            b'l' => u32::from_le_bytes(b),
            b'B' => u32::from_be_bytes(b),
            _ => return None,
        })
    };
    let body = usize::try_from(read(4)?).ok()?;
    let fields = usize::try_from(read(12)?).ok()?;
    // The header, padded to 8 bytes.
    let header = 16usize.checked_add(fields)?.checked_next_multiple_of(8)?;
    let total = header.checked_add(body)?;
    (total <= MAX_MESSAGE).then_some(total)
}

/// Parses one whole message's header for its type and `REPLY_SERIAL`.
#[must_use]
pub fn parse_received(message: &[u8]) -> Option<Received> {
    let fixed: &[u8; 16] = message.get(..16)?.try_into().ok()?;
    if total_length(fixed)? != message.len() || fixed[3] != 1 {
        return None;
    }
    let little = fixed[0] == b'l';
    let u32_at = |at: usize| -> Option<u32> {
        let b: [u8; 4] = *message.get(at..)?.first_chunk::<4>()?;
        Some(if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    };
    let end = 16usize.checked_add(usize::try_from(u32_at(12)?).ok()?)?;
    let mut at = 16;
    let mut reply_serial = None;
    while at < end {
        at = at.checked_next_multiple_of(8)?;
        // A header field: its code, then its signature (length, text, NUL).
        let field = message.get(at..)?;
        let code = *field.first()?;
        let sig_len = usize::from(*field.get(1)?);
        let sig = field.get(2..)?.get(..sig_len)?;
        at = at.checked_add(3)?.checked_add(sig_len)?;
        match sig {
            b"u" => {
                at = at.checked_next_multiple_of(4)?;
                let v = u32_at(at)?;
                if code == field::REPLY_SERIAL {
                    reply_serial = Some(v);
                }
                at = at.checked_add(4)?;
            }
            b"s" | b"o" => {
                at = at.checked_next_multiple_of(4)?;
                let len = usize::try_from(u32_at(at)?).ok()?;
                at = at.checked_add(4)?.checked_add(len)?.checked_add(1)?;
            }
            b"g" => {
                let len = usize::from(*message.get(at)?);
                at = at.checked_add(2)?.checked_add(len)?;
            }
            _ => return None,
        }
        if at > end {
            return None;
        }
    }
    Some(Received { kind: fixed[1], reply_serial })
}

fn read_message(reader: &mut impl Read, budget: &mut usize) -> io::Result<Received> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed message from the bus");
    let mut fixed = [0u8; 16];
    reader.read_exact(&mut fixed)?;
    let total = total_length(&fixed).ok_or_else(invalid)?;
    *budget = budget.checked_sub(total).ok_or_else(invalid)?;
    let mut whole = fixed.to_vec();
    whole.resize(total, 0);
    reader.read_exact(whole.get_mut(16..).ok_or_else(invalid)?)?;
    parse_received(&whole).ok_or_else(invalid)
}

/// Runs the exchange on `stream`: authenticates as `uid`, sends, and waits
/// for the reply to `GetId`.
///
/// # Errors
/// When the bus refuses, fails or sends nonsense.
pub fn exchange(stream: &mut (impl Read + Write), uid: u32, payload: &[u8]) -> io::Result<()> {
    let hex = hex(uid.to_string().as_bytes());
    stream.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let mut reader = BufReader::new(Read::take(&mut *stream, MAX_READ as u64));
    let mut line = Vec::new();
    reader.by_ref().take(512).read_until(b'\n', &mut line)?;
    if !line.starts_with(b"OK ") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the bus refused the authentication"));
    }
    let mut budget = MAX_READ;
    // The reader holds the stream; what it buffered past the line is the
    // bus's, read below.
    let rest = reader.buffer().to_vec();
    drop(reader);
    stream.write_all(b"BEGIN\r\n")?;
    stream.write_all(payload)?;
    let mut input = rest.chain(Read::take(&mut *stream, MAX_READ as u64));
    loop {
        let received = read_message(&mut input, &mut budget)?;
        if received.reply_serial == Some(LAST_SERIAL) {
            return if received.kind == kind::METHOD_RETURN {
                Ok(())
            } else {
                Err(io::Error::other("the bus answered with an error"))
            };
        }
        if received.kind == kind::ERROR && received.reply_serial.is_some() {
            return Err(io::Error::other("the bus refused a request"));
        }
    }
}

/// Lower-case hex digits of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len().saturating_mul(2)), |mut out, b| {
        // Writing to a String cannot fail.
        write!(out, "{b:02x}").ok();
        out
    })
}

/// A GUID as `g_dbus_generate_guid()` makes it: 32 hex digits.
fn guid() -> String {
    let mut random = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut random)).is_err() {
        let (sec, nsec) = crate::sandbox::monotonic_time();
        // The seconds (8 bytes), the nanoseconds and the process id (4 each).
        let fallback =
            sec.to_le_bytes().into_iter().chain(nsec.to_le_bytes()).chain(std::process::id().to_le_bytes());
        for (byte, value) in random.iter_mut().zip(fallback) {
            *byte = value;
        }
    }
    hex(&random)
}

/// Sends `AccountChanged` for `change` to the bus at `address`.
///
/// # Errors
/// When the bus cannot be reached or refuses.
pub fn announce(change: &Change, address: &Address) -> io::Result<()> {
    let mut stream = match address {
        Address::Path(path) => UnixStream::connect(path)?,
        Address::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            UnixStream::connect_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name)?)?
        }
    };
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let payload = messages(change, &guid(), crate::sandbox::monotonic_time());
    exchange(&mut stream, crate::sandbox::uid(), &payload)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn change() -> Change {
        Change {
            account_id: 7,
            provider: "fake".into(),
            settings: vec![
                NewSetting {
                    key: b"netvfs/attention".to_vec(),
                    type_string: "s",
                    text: "'auth-failed'".into(),
                },
                NewSetting { key: b"CredentialsNeedUpdate".to_vec(), type_string: "b", text: "true".into() },
            ],
        }
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_address("unix:path=/run/user/1/bus"), Some(Address::Path("/run/user/1/bus".into())));
        assert_eq!(
            parse_address("unix:abstract=/tmp/dbus-x%2cy,guid=00"),
            Some(Address::Abstract(b"/tmp/dbus-x,y".to_vec()))
        );
        assert_eq!(parse_address("tcp:host=x,port=1;unix:guid=1,path=/b"), Some(Address::Path("/b".into())));
        assert_eq!(parse_address("tcp:host=x"), None);
        assert_eq!(parse_address("unix:path=/a%zz"), None);
        assert_eq!(parse_address("unix:path=/a%2"), None);
        assert_eq!(parse_address(""), None);
        assert_eq!(
            session_bus(true, std::path::Path::new("/run/user/5")),
            Some(Address::Path("/run/user/5/bus".into()))
        );
    }

    #[test]
    fn signal_body() {
        let body = changed_body(&change(), (0x1_0000_0002, 3));
        // sec (low 32 bits), nsec, account, created, deleted
        assert_eq!(body[..20], [2, 0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // provider "fake"
        assert_eq!(body[20..29], [4, 0, 0, 0, b'f', b'a', b'k', b'e', 0]);
        // the array length, then its first struct at an 8-byte boundary
        let length = u32::from_le_bytes(body[32..36].try_into().unwrap()) as usize;
        assert_eq!(body.len(), 40 + length);
        assert_eq!(body[40..47], [6, 0, 0, 0, b'g', b'l', b'o']);
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("netvfs/attention"));
        assert!(text.contains("\u{1}s\0"));
        assert!(text.contains("auth-failed"));
        assert!(text.contains("CredentialsNeedUpdate\0\u{1}b\0"));
        // ends with an empty "as"
        assert_eq!(body[body.len() - 4..], [0, 0, 0, 0]);
    }

    #[test]
    fn only_messages_with_a_body_have_a_signature() {
        let contains = |message: &[u8], part: &[u8]| message.windows(part.len()).any(|w| w == part);
        // The SIGNATURE field: code 8, signature "g", then the value.
        assert!(!contains(&bus_call(1, "Hello", "", &[]), b"\x01g\0"));
        assert!(contains(&bus_call(2, "RequestName", "su", &[]), b"\x08\x01g\0\x02su\0"));
        let all = messages(&change(), &guid(), (1, 2));
        assert!(contains(&all, b"\x08\x01g\0\x13uuubbsa(ssua{sv}as)\0"));
    }

    #[test]
    fn messages_parse_back() {
        let payload = messages(&change(), &guid(), (1, 2));
        let mut input = &payload[..];
        let mut budget = MAX_READ;
        let kinds: Vec<_> = (0..4).map(|_| read_message(&mut input, &mut budget).unwrap().kind).collect();
        assert_eq!(kinds, [kind::METHOD_CALL, kind::METHOD_CALL, kind::SIGNAL, kind::METHOD_CALL]);
        assert!(input.is_empty());
        assert_eq!(guid().len(), 32);
        assert_ne!(guid(), guid());
    }

    fn reply(kind: u8, serial: u32, reply_serial: u32, endian: u8) -> Vec<u8> {
        let mut w = Writer::default();
        w.byte(b'l');
        w.byte(kind);
        w.byte(0);
        w.byte(1);
        w.u32(0);
        w.u32(serial);
        w.array(8, |w| {
            w.align(8);
            w.byte(field::REPLY_SERIAL);
            w.signature("u");
            w.u32(reply_serial);
            w.align(8);
            w.byte(field::DESTINATION);
            w.signature("s");
            w.string(":1.5");
            w.align(8);
            w.byte(field::SIGNATURE);
            w.signature("g");
            w.signature("");
        });
        w.align(8);
        let mut bytes = w.bytes;
        if endian == b'B' {
            bytes[0] = b'B';
            for at in [4, 8, 12] {
                bytes[at..at + 4].reverse();
            }
            // the REPLY_SERIAL value
            bytes[20..24].reverse();
            bytes[28..32].reverse();
        }
        bytes
    }

    #[test]
    fn replies() {
        assert_eq!(
            parse_received(&reply(kind::METHOD_RETURN, 9, 4, b'l')),
            Some(Received { kind: kind::METHOD_RETURN, reply_serial: Some(4) })
        );
        assert_eq!(
            parse_received(&reply(kind::ERROR, 9, 2, b'B')),
            Some(Received { kind: kind::ERROR, reply_serial: Some(2) })
        );
        let good = reply(kind::METHOD_RETURN, 1, 4, b'l');
        assert_eq!(parse_received(&good[..good.len() - 1]), None);
        let mut wrong_version = good.clone();
        wrong_version[3] = 2;
        assert_eq!(parse_received(&wrong_version), None);
        let mut wrong_endian = good.clone();
        wrong_endian[0] = b'x';
        assert_eq!(parse_received(&wrong_endian), None);
        let mut unknown_sig = good.clone();
        unknown_sig[18] = b'v';
        assert_eq!(parse_received(&unknown_sig), None);
        let mut huge = good;
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_received(&huge), None);
    }

    /// A bus that answers from a script.
    struct Script {
        input: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn run(input: Vec<u8>) -> (io::Result<()>, Vec<u8>) {
        let mut bus = Script { input: io::Cursor::new(input), written: Vec::new() };
        let result = exchange(&mut bus, 1000, b"PAYLOAD");
        (result, bus.written)
    }

    #[test]
    fn exchanges() {
        let mut ok = b"OK 1234\r\n".to_vec();
        ok.extend(reply(kind::METHOD_RETURN, 1, 1, b'l'));
        ok.extend(reply(kind::METHOD_RETURN, 2, 4, b'l'));
        let (result, written) = run(ok);
        assert!(matches!(result, Ok(())));
        assert_eq!(written, b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\nPAYLOAD");

        assert!(run(b"REJECTED EXTERNAL\r\n".to_vec()).0.is_err());
        assert!(run(Vec::new()).0.is_err());
        let mut error = b"OK 1\r\n".to_vec();
        error.extend(reply(kind::ERROR, 1, 2, b'l'));
        assert!(run(error).0.is_err());
        let mut last_error = b"OK 1\r\n".to_vec();
        last_error.extend(reply(kind::ERROR, 1, 4, b'l'));
        assert!(run(last_error).0.is_err());
        let mut cut = b"OK 1\r\n".to_vec();
        cut.extend(&reply(kind::METHOD_RETURN, 1, 4, b'l')[..20]);
        assert!(run(cut).0.is_err());
        let mut garbage = b"OK 1\r\n".to_vec();
        garbage.extend([b'x'; 32]);
        assert!(run(garbage).0.is_err());
    }

    /// `reply` with a body of `body` zero bytes.
    fn reply_with_body(kind: u8, serial: u32, reply_serial: u32, body: usize) -> Vec<u8> {
        let mut bytes = reply(kind, serial, reply_serial, b'l');
        bytes[4..8].copy_from_slice(&u32::try_from(body).unwrap().to_le_bytes());
        bytes.resize(bytes.len() + body, 0);
        bytes
    }

    #[test]
    fn exchanges_end_at_the_reply_to_get_id() {
        // Only the reply to GetId ends the exchange, whatever comes first.
        let mut late_error = b"OK 1\r\n".to_vec();
        late_error.extend(reply(kind::METHOD_RETURN, 1, 1, b'l'));
        late_error.extend(reply(kind::ERROR, 2, 4, b'l'));
        assert!(run(late_error).0.is_err());
    }

    #[test]
    fn exchanges_take_messages_up_to_the_limits() {
        let ok = |before: &[Vec<u8>]| {
            let mut input = b"OK 1\r\n".to_vec();
            for message in before {
                input.extend(message);
            }
            input.extend(reply(kind::METHOD_RETURN, 2, 4, b'l'));
            run(input).0
        };
        // A message up to MAX_MESSAGE long.
        let largest = reply_with_body(kind::METHOD_RETURN, 1, 1, MAX_MESSAGE - reply(0, 0, 0, b'l').len());
        assert_eq!(largest.len(), MAX_MESSAGE);
        assert!(matches!(ok(std::slice::from_ref(&largest)), Ok(())));
        let too_large = reply_with_body(kind::METHOD_RETURN, 1, 1, MAX_MESSAGE + 1);
        assert!(ok(&[too_large]).is_err());
        // Up to MAX_READ in all before the reply.
        let filler = vec![largest; MAX_READ / MAX_MESSAGE - 1];
        assert!(matches!(ok(&filler), Ok(())));
        let more =
            vec![reply_with_body(kind::METHOD_RETURN, 1, 1, MAX_MESSAGE / 2); 2 * MAX_READ / MAX_MESSAGE];
        assert!(ok(&more).is_err());
    }

    #[test]
    fn unreachable_bus() {
        let missing = Address::Path("/nonexistent/bus".into());
        assert!(announce(&change(), &missing).is_err());
    }
}
