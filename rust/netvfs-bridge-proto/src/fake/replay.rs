// SPDX-License-Identifier: LGPL-2.1-or-later
//! Replays the golden sequences of the contract (`tests/bridge/contract/*.json`) against a bridge.
//! Format and matching rules: the README next to the files.
//! [`replay_sequence`] drives any bridge: seeds it through a callback (consent and files), connects
//! through another, checks every reply and signal against the sequence and the method table's
//! signatures. [`replay`] and [`replay_dir`] run it against the in-process [`FakeBridge`]; the
//! bridge's own tests run it against the in-process bridge and the binary.

use super::{Consent, FakeBridge};
use crate::connect::Connection;
use crate::errors::{BridgeError, INVALID_ARGS};
use crate::methods::{INTERFACE, OBJECT_PATH, find_method, find_signal};
use futures_lite::StreamExt as _;
use serde_json::{Value as Json, json};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Notify;
use zbus::message::Type as MessageType;
use zbus::zvariant::{Array, Dict, Signature, Structure, StructureBuilder, Value};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// The one account the sequences run against: provider `fake`, name
/// `Fake 1`, host `fake.example`.
pub const ACCOUNT: &str = "account:1";

/// A parsed sequence file.
#[derive(Debug)]
pub struct Sequence {
    /// What the sequence shows.
    pub description: String,
    /// The consent the bridge starts with.
    pub consent: Consent,
    /// Files on the fake server of [`ACCOUNT`]: (path, content).
    pub files: Vec<(String, String)>,
    /// The steps, run in order on one connection.
    pub steps: Vec<Step>,
}

/// One step of a sequence.
#[derive(Debug)]
pub enum Step {
    /// A method call and what it must answer.
    Call {
        /// Member name.
        call: String,
        /// Signature the arguments are sent with (not always the right one).
        sig: String,
        /// Arguments.
        args: Vec<Json>,
        /// The expected reply or error.
        outcome: Outcome,
    },
    /// The next signal of that name, and what it must carry.
    Signal {
        /// Member name.
        signal: String,
        /// Expected arguments.
        args: Vec<Json>,
    },
}

/// What a call must answer.
#[derive(Debug)]
pub enum Outcome {
    /// A reply with these arguments.
    Reply(Vec<Json>),
    /// An error of this D-Bus name.
    Error(String),
}

fn text<'a>(v: &'a Json, key: &str) -> Result<&'a str, String> {
    v.get(key).and_then(Json::as_str).ok_or_else(|| format!("missing string \"{key}\""))
}

fn list(v: &Json, key: &str) -> Result<Vec<Json>, String> {
    v.get(key).and_then(Json::as_array).cloned().ok_or_else(|| format!("missing array \"{key}\""))
}

fn parse_step(step: &Json) -> Result<Step, String> {
    if let Some(signal) = step.get("signal").and_then(Json::as_str) {
        return Ok(Step::Signal { signal: signal.to_owned(), args: list(step, "args")? });
    }
    let outcome = match (step.get("reply"), step.get("error").and_then(Json::as_str)) {
        (Some(Json::Array(r)), None) => Outcome::Reply(r.clone()),
        (None, Some(e)) => Outcome::Error(e.to_owned()),
        _ => return Err("a call needs exactly one of \"reply\" and \"error\"".to_owned()),
    };
    Ok(Step::Call {
        call: text(step, "call")?.to_owned(),
        sig: text(step, "sig")?.to_owned(),
        args: list(step, "args")?,
        outcome,
    })
}

/// Parses a sequence file.
///
/// # Errors
/// A message naming what is malformed.
pub fn parse(source: &str) -> Result<Sequence, String> {
    let doc: Json = serde_json::from_str(source).map_err(|e| e.to_string())?;
    let consent = match text(&doc, "consent")? {
        "granted" => Consent::Granted,
        "denied" => Consent::Denied,
        "unknown" => Consent::Unknown,
        other => return Err(format!("unknown consent \"{other}\"")),
    };
    let files = match doc.get("files") {
        None => Vec::new(),
        Some(Json::Object(m)) => m
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|content| (k.clone(), content.to_owned()))
                    .ok_or_else(|| format!("file \"{k}\": the content must be a string"))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("\"files\" must be an object".to_owned()),
    };
    let steps = list(&doc, "steps")?
        .iter()
        .zip(1..)
        .map(|(s, n): (&Json, u32)| parse_step(s).map_err(|e| format!("step {n}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Sequence { description: text(&doc, "description")?.to_owned(), consent, files, steps })
}

/// The `*.json` files of `dir` in name order, parsed: (file name, sequence).
///
/// # Errors
/// A message naming the file that cannot be read or parsed.
pub fn load_dir(dir: &Path) -> Result<Vec<(String, Sequence)>, String> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .map(|e| e.map(|e| e.path()).map_err(|e| format!("{}: {e}", dir.display())))
        .collect::<Result<_, _>>()?;
    files.retain(|p| p.extension().is_some_and(|x| x == "json"));
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let source = std::fs::read_to_string(&file).map_err(|e| format!("{name}: {e}"))?;
            let seq = parse(&source).map_err(|e| format!("{name}: {e}"))?;
            Ok((name, seq))
        })
        .collect()
}

fn split_types(sig: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut rest = sig;
    while !rest.is_empty() {
        let end = type_end(rest)?;
        let (one, tail) = rest.split_at_checked(end).ok_or("bad signature")?;
        out.push(one);
        rest = tail;
    }
    Ok(out)
}

fn type_end(sig: &str) -> Result<usize, String> {
    let mut depth = 0usize;
    for (i, c) in sig.char_indices() {
        match c {
            'a' => continue,
            '(' | '{' => depth = depth.checked_add(1).ok_or("signature too deep")?,
            ')' | '}' => depth = depth.checked_sub(1).ok_or("unbalanced signature")?,
            _ => {}
        }
        if depth == 0 {
            return i.checked_add(1).ok_or_else(|| "signature too long".to_owned());
        }
    }
    Err(if depth == 0 { "truncated signature" } else { "unbalanced signature" }.to_owned())
}

/// The body signature as the message header carries it. zvariant 5 parses `(asasx)` (one struct)
/// and `asasx` (three arguments) to the same `Signature`, but the contract tells them apart.
fn wire_signature(msg: &zbus::Message) -> Result<String, String> {
    let bytes = msg.data().bytes();
    let le = match bytes.first() {
        Some(b'l') => true,
        Some(b'B') => false,
        _ => return Err("not a D-Bus message".to_owned()),
    };
    let mut r = Reader { bytes, pos: 12, le };
    let fields_len = usize::try_from(r.u32()?).map_err(|e| e.to_string())?;
    let end = r.pos.checked_add(fields_len).ok_or("bad header")?;
    while r.pos < end {
        r.align(8)?;
        let code = r.byte()?;
        let value_sig = r.sig()?;
        match (code, value_sig) {
            (8, "g") => return Ok(r.sig()?.to_owned()),
            (_, "g") => {
                r.sig()?;
            }
            (_, "s" | "o") => {
                r.align(4)?;
                let len = usize::try_from(r.u32()?).map_err(|e| e.to_string())?;
                r.skip(len.checked_add(1).ok_or("bad header")?)?;
            }
            (_, "u") => {
                r.align(4)?;
                r.u32()?;
            }
            (_, other) => return Err(format!("unexpected header field type {other}")),
        }
    }
    Ok(String::new())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    le: bool,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("bad header")?;
        let out = self.bytes.get(self.pos..end).ok_or("truncated header")?;
        self.pos = end;
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }

    fn align(&mut self, to: usize) -> Result<(), String> {
        let pad = self.pos.checked_next_multiple_of(to).ok_or("bad header")?.saturating_sub(self.pos);
        self.skip(pad)
    }

    fn byte(&mut self) -> Result<u8, String> {
        self.take(1)?.first().copied().ok_or_else(|| "truncated header".to_owned())
    }

    fn u32(&mut self) -> Result<u32, String> {
        let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_e| "truncated header".to_owned())?;
        Ok(if self.le { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) })
    }

    fn sig(&mut self) -> Result<&'a str, String> {
        let len = usize::from(self.byte()?);
        let raw = self.take(len)?;
        self.skip(1)?;
        std::str::from_utf8(raw).map_err(|e| e.to_string())
    }
}

fn bytes_of(v: &Json) -> Result<Vec<u8>, String> {
    if let Some(s) = v.get("bytes").and_then(Json::as_str) {
        return Ok(s.as_bytes().to_vec());
    }
    if let Some(h) = v.get("hex").and_then(Json::as_str) {
        let bad = || format!("bad hex \"{h}\"");
        if h.len() % 2 != 0 {
            return Err(bad());
        }
        return h
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair).ok().and_then(|p| u8::from_str_radix(p, 16).ok()).ok_or_else(bad)
            })
            .collect();
    }
    Err(format!("expected {{\"bytes\"}} or {{\"hex\"}}, got {v}"))
}

fn number<T: TryFrom<i64>>(t: &str, v: &Json) -> Result<T, String> {
    let n = v.as_i64().ok_or_else(|| format!("expected an integer, got {v}"))?;
    T::try_from(n).map_err(|_e| format!("{n} does not fit {t}"))
}

fn encode(t: &str, v: &Json) -> Result<Value<'static>, String> {
    let mut chars = t.chars();
    Ok(match chars.next() {
        Some('y') => Value::U8(number(t, v)?),
        Some('q') => Value::U16(number(t, v)?),
        Some('u') => Value::U32(number(t, v)?),
        Some('i') => Value::I32(number(t, v)?),
        Some('x') => Value::I64(number(t, v)?),
        Some('b') => Value::Bool(v.as_bool().ok_or_else(|| format!("expected a boolean, got {v}"))?),
        Some('s') => Value::from(v.as_str().ok_or_else(|| format!("expected a string, got {v}"))?.to_owned()),
        Some('a') => encode_array(chars.as_str(), v)?,
        Some('(') => {
            let inner = chars.as_str().strip_suffix(')').ok_or_else(|| format!("bad struct {t}"))?;
            let fields = split_types(inner)?;
            let items = v.as_array().filter(|a| a.len() == fields.len());
            let items = items.ok_or_else(|| format!("expected {} fields, got {v}", fields.len()))?;
            let mut b = StructureBuilder::new();
            for (ft, item) in fields.iter().zip(items) {
                b = b.append_field(encode(ft, item)?);
            }
            Value::Structure(b.build().map_err(|e| e.to_string())?)
        }
        _ => return Err(format!("unsupported type {t}")),
    })
}

fn encode_array(elem: &str, v: &Json) -> Result<Value<'static>, String> {
    if elem == "y" {
        return Ok(Value::from(bytes_of(v)?));
    }
    if elem.starts_with('{') {
        if elem == "{sv}" {
            return encode_dict(v);
        }
        return Err(format!("unsupported dictionary {elem}"));
    }
    let sig = Signature::try_from(elem).map_err(|e| e.to_string())?;
    let mut arr = Array::new(&sig);
    for item in v.as_array().ok_or_else(|| format!("expected an array, got {v}"))? {
        arr.append(encode(elem, item)?).map_err(|e| e.to_string())?;
    }
    Ok(Value::Array(arr))
}

fn encode_dict(v: &Json) -> Result<Value<'static>, String> {
    let obj = v.as_object().ok_or_else(|| format!("expected an object, got {v}"))?;
    let mut dict = Dict::new(&Signature::Str, &Signature::Variant);
    for (k, item) in obj {
        let inner = match item {
            Json::Bool(_) => encode("b", item)?,
            Json::Number(_) => encode("x", item)?,
            Json::String(_) => encode("s", item)?,
            other => return Err(format!("unsupported option value {other}")),
        };
        dict.append(Value::from(k.clone()), Value::Value(Box::new(inner))).map_err(|e| e.to_string())?;
    }
    Ok(Value::Dict(dict))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.extend([b >> 4, b & 0xf].into_iter().filter_map(|n| char::from_digit(u32::from(n), 16)));
    }
    out
}

fn decode(v: &Value<'_>) -> Json {
    match v {
        Value::U8(n) => json!(n),
        Value::Bool(b) => json!(b),
        Value::I16(n) => json!(n),
        Value::U16(n) => json!(n),
        Value::I32(n) => json!(n),
        Value::U32(n) => json!(n),
        Value::I64(n) => json!(n),
        Value::U64(n) => json!(n),
        Value::F64(n) => json!(n),
        Value::Str(s) => json!(s.as_str()),
        Value::Signature(s) => json!(s.to_string()),
        Value::ObjectPath(p) => json!(p.as_str()),
        Value::Value(inner) => decode(inner),
        Value::Array(a) => {
            if *a.element_signature() == Signature::U8 {
                let bytes: Vec<u8> =
                    a.iter().filter_map(|b| if let Value::U8(n) = b { Some(*n) } else { None }).collect();
                json!({ "hex": hex(&bytes) })
            } else {
                Json::Array(a.iter().map(decode).collect())
            }
        }
        Value::Dict(d) => {
            let mut map = serde_json::Map::new();
            for (k, item) in d.iter() {
                let key = match decode(k) {
                    Json::String(s) => s,
                    other => other.to_string(),
                };
                map.insert(key, decode(item));
            }
            Json::Object(map)
        }
        Value::Structure(s) => Json::Array(s.fields().iter().map(decode).collect()),
        Value::Fd(_) => json!("<fd>"),
    }
}

fn body_fields(msg: &zbus::Message) -> Result<(String, Vec<Json>), String> {
    let sig = wire_signature(msg)?;
    if sig.is_empty() {
        return Ok((sig, Vec::new()));
    }
    let body = msg.body();
    let s: Structure<'_> = body.deserialize().map_err(|e| e.to_string())?;
    let fields: Vec<Json> = s.fields().iter().map(decode).collect();
    // zvariant reads a one-struct body as that struct's fields; on the wire it is a single argument
    // (e.g. `Stat`'s entry).
    let one_struct = sig.starts_with('(') && split_types(&sig).is_ok_and(|t| t.len() == 1);
    let fields = if one_struct { vec![Json::Array(fields)] } else { fields };
    Ok((sig, fields))
}

fn normalise(v: &Json) -> Json {
    if v.as_object().is_some_and(|o| o.len() == 1 && (o.contains_key("bytes") || o.contains_key("hex")))
        && let Ok(b) = bytes_of(v)
    {
        return json!({ "hex": hex(&b) });
    }
    v.clone()
}

type Bindings = HashMap<String, Json>;

fn matches(expected: &Json, actual: &Json, binds: &mut Bindings) -> Result<(), String> {
    let expected = normalise(expected);
    if let Some(s) = expected.as_str() {
        if s == "*" {
            return Ok(());
        }
        if let Some(name) = s.strip_prefix('$') {
            return match binds.get(name) {
                Some(bound) if bound == actual => Ok(()),
                Some(bound) => Err(format!("${name} was {bound}, now {actual}")),
                None => {
                    binds.insert(name.to_owned(), actual.clone());
                    Ok(())
                }
            };
        }
    }
    match (&expected, actual) {
        (Json::Array(e), Json::Array(a)) => match_arrays(e, a, binds),
        (Json::Object(e), Json::Object(a)) => {
            for (k, ev) in e {
                let av = a.get(k).ok_or_else(|| format!("missing key \"{k}\" in {actual}"))?;
                matches(ev, av, binds).map_err(|m| format!("{k}: {m}"))?;
            }
            Ok(())
        }
        (e, a) if e == a => Ok(()),
        (e, a) => Err(format!("expected {e}, got {a}")),
    }
}

fn match_arrays(e: &[Json], a: &[Json], binds: &mut Bindings) -> Result<(), String> {
    let (items, prefix) = match e.split_last() {
        Some((last, rest)) if last.as_str() == Some("...") => (rest, true),
        _ => (e, false),
    };
    if a.len() < items.len() || (!prefix && a.len() != items.len()) {
        return Err(format!("expected {} elements, got {}", e.len(), a.len()));
    }
    for (i, (ev, av)) in items.iter().zip(a).enumerate() {
        matches(ev, av, binds).map_err(|m| format!("[{i}] {m}"))?;
    }
    Ok(())
}

fn substitute(v: &Json, binds: &Bindings) -> Result<Json, String> {
    match v {
        Json::String(s) => match s.strip_prefix('$') {
            Some(name) => binds.get(name).cloned().ok_or_else(|| format!("{s} is not bound yet")),
            None => Ok(v.clone()),
        },
        Json::Array(a) => {
            a.iter().map(|x| substitute(x, binds)).collect::<Result<Vec<_>, _>>().map(Json::Array)
        }
        Json::Object(o) => o
            .iter()
            .map(|(k, x)| substitute(x, binds).map(|y| (k.clone(), y)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(Json::Object),
        other => Ok(other.clone()),
    }
}

type Received = Result<(String, Vec<Json>), String>;

#[derive(Default)]
struct Inbox {
    queue: Mutex<VecDeque<(String, Received)>>,
    arrived: Notify,
}

impl Inbox {
    fn take(&self, member: &str) -> Option<Received> {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let at = q.iter().position(|(m, _)| m == member)?;
        q.remove(at).map(|(_, args)| args)
    }

    fn push(&self, member: String, args: Received) {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner).push_back((member, args));
        self.arrived.notify_waiters();
    }
}

fn collect_signals(conn: &Connection, inbox: Arc<Inbox>) -> tokio::task::JoinHandle<()> {
    let mut stream = zbus::MessageStream::from(conn.zbus());
    tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            let header = msg.header();
            if header.primary().msg_type() != MessageType::Signal
                || header.interface().map(zbus::names::InterfaceName::as_str) != Some(INTERFACE)
            {
                continue;
            }
            if let Some(member) = header.member().map(|m| m.as_str().to_owned()) {
                inbox.push(member, body_fields(&msg));
            }
        }
    })
}

fn error_name(e: &BridgeError) -> String {
    match e.dbus_name() {
        Some(name) => name.to_owned(),
        None => format!("transport failure: {e}"),
    }
}

fn check_reply_signature(call: &str, sig: &str) -> Result<(), String> {
    match find_method(call) {
        Some(m) if m.output != sig => {
            Err(format!("{call} replied ({sig}), the contract says ({})", m.output))
        }
        _ => Ok(()),
    }
}

fn check_error_signature(call: &str, name: &str, msg: &zbus::Message) -> Result<(), String> {
    let sig = wire_signature(msg)?;
    let fine = if name.starts_with(crate::errors::ERROR_PREFIX) {
        sig == "s" || sig == "sa{sv}"
    } else {
        // Errors of the D-Bus library carry at most the message.
        sig == "s" || sig.is_empty() || (name == INVALID_ARGS && sig == "sa{sv}")
    };
    if fine { Ok(()) } else { Err(format!("{call}: error {name} carried ({sig})")) }
}

async fn call_step(
    conn: &Connection,
    (call, sig, args, outcome): (&str, &str, &[Json], &Outcome),
    binds: &mut Bindings,
) -> Result<(), String> {
    let types = split_types(sig)?;
    if types.len() != args.len() {
        return Err(format!("{} arguments for signature \"{sig}\"", args.len()));
    }
    let mut builder = StructureBuilder::new();
    for (t, a) in types.iter().zip(args) {
        builder = builder.append_field(encode(t, &substitute(a, binds)?)?);
    }
    let sent = async {
        if types.is_empty() {
            conn.zbus().call_method(None::<&str>, OBJECT_PATH, Some(INTERFACE), call, &()).await
        } else {
            let body = builder.build().map_err(zbus::Error::Variant)?;
            conn.zbus().call_method(None::<&str>, OBJECT_PATH, Some(INTERFACE), call, &body).await
        }
    };
    let reply = tokio::time::timeout(STEP_TIMEOUT, sent).await.map_err(|_e| format!("{call}: no reply"))?;
    match (reply, outcome) {
        (Ok(msg), Outcome::Reply(expected)) => {
            let (got_sig, fields) = body_fields(&msg)?;
            check_reply_signature(call, &got_sig)?;
            matches(&Json::Array(expected.clone()), &Json::Array(fields), binds)
                .map_err(|m| format!("{call} reply: {m}"))
        }
        (Ok(_), Outcome::Error(want)) => Err(format!("{call}: expected {want}, got a reply")),
        (Err(e), Outcome::Error(want)) => {
            if let zbus::Error::MethodError(name, _, msg) = &e {
                check_error_signature(call, name.as_str(), msg)?;
            }
            let got = error_name(&BridgeError::from(e));
            if &got == want { Ok(()) } else { Err(format!("{call}: expected {want}, got {got}")) }
        }
        (Err(e), Outcome::Reply(_)) => {
            Err(format!("{call}: unexpected error {}", error_name(&BridgeError::from(e))))
        }
    }
}

async fn signal_step(
    inbox: &Inbox,
    signal: &str,
    expected: &[Json],
    binds: &mut Bindings,
) -> Result<(), String> {
    let wait = async {
        loop {
            let notified = inbox.arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(args) = inbox.take(signal) {
                return args;
            }
            notified.await;
        }
    };
    let (sig, args) = tokio::time::timeout(STEP_TIMEOUT, wait)
        .await
        .map_err(|_e| format!("signal {signal} never arrived"))?
        .map_err(|e| format!("signal {signal}: {e}"))?;
    match find_signal(signal) {
        Some(want) if want != sig => {
            return Err(format!("signal {signal} carried ({sig}), the contract says ({want})"));
        }
        Some(_) => {}
        None => return Err(format!("signal {signal} is not in the contract")),
    }
    matches(&Json::Array(expected.to_vec()), &Json::Array(args), binds)
        .map_err(|m| format!("signal {signal}: {m}"))
}

/// Replays `seq` against a bridge: `seed` prepares it (consent, files on [`ACCOUNT`]); `connect`
/// opens the one connection the steps run on.
///
/// # Errors
/// A message naming the step that failed and why.
pub async fn replay_sequence<S, C>(seq: &Sequence, seed: S, connect: C) -> Result<(), String>
where
    S: AsyncFnOnce(&Sequence) -> Result<(), String>,
    C: AsyncFnOnce() -> Result<Connection, String>,
{
    seed(seq).await.map_err(|e| format!("seeding: {e}"))?;
    let conn = connect().await.map_err(|e| format!("connecting: {e}"))?;
    let inbox = Arc::new(Inbox::default());
    let collector = collect_signals(&conn, Arc::clone(&inbox));
    let mut binds = Bindings::new();
    let mut outcome = Ok(());
    for (step, n) in seq.steps.iter().zip(1u32..) {
        let done = match step {
            Step::Call { call, sig, args, outcome } => {
                call_step(&conn, (call, sig, args, outcome), &mut binds).await
            }
            Step::Signal { signal, args } => signal_step(&inbox, signal, args, &mut binds).await,
        };
        if let Err(e) = done {
            outcome = Err(format!("step {n}: {e}"));
            break;
        }
    }
    collector.abort();
    conn.close().await;
    outcome
}

/// Replays `seq` on a fresh fake bridge with the account [`ACCOUNT`].
///
/// # Errors
/// A message naming the step that failed and why.
pub async fn replay(seq: &Sequence) -> Result<(), String> {
    let fake = FakeBridge::new();
    replay_sequence(
        seq,
        async |seq: &Sequence| {
            fake.set_consent(seq.consent).await;
            fake.add_account(1, "fake", "Fake 1", "fake.example").await;
            for (path, content) in &seq.files {
                fake.put_file(ACCOUNT, path.as_bytes(), content.as_bytes());
            }
            Ok(())
        },
        async || fake.connect().await.map_err(|e| e.to_string()),
    )
    .await
}

/// Replays every `*.json` file of `dir` (the contract directory) on the
/// fake; returns the names of the sequences that ran.
///
/// # Errors
/// A message naming the file and the step that failed.
pub async fn replay_dir(dir: &Path) -> Result<Vec<String>, String> {
    let dir = dir.to_owned();
    let sequences =
        tokio::task::spawn_blocking(move || load_dir(&dir)).await.map_err(|e| e.to_string())??;
    let mut ran = Vec::new();
    for (name, seq) in sequences {
        replay(&seq).await.map_err(|e| format!("{name}: {} ({e})", seq.description))?;
        ran.push(name);
    }
    Ok(ran)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binds() -> Bindings {
        Bindings::new()
    }

    #[test]
    fn signature_splitting() {
        assert_eq!(split_types("saya{sv}").unwrap(), vec!["s", "ay", "a{sv}"]);
        assert_eq!(split_types("a(sssa{sv})").unwrap(), vec!["a(sssa{sv})"]);
        assert_eq!(split_types("").unwrap(), Vec::<&str>::new());
        split_types("(s").unwrap_err();
        split_types("a").unwrap_err();
        split_types("s)").unwrap_err();
    }

    #[test]
    fn encoding_by_signature() {
        assert_eq!(encode("u", &json!(7)).unwrap(), Value::U32(7));
        assert_eq!(encode("x", &json!(-7)).unwrap(), Value::I64(-7));
        encode("u", &json!(-1)).unwrap_err();
        encode("y", &json!(256)).unwrap_err();
        encode("b", &json!("x")).unwrap_err();
        assert_eq!(encode("ay", &json!({"bytes": "ab"})).unwrap(), Value::from(vec![b'a', b'b']));
        assert_eq!(encode("ay", &json!({"hex": "00ff"})).unwrap(), Value::from(vec![0u8, 255]));
        encode("ay", &json!({"hex": "0"})).unwrap_err();
        encode("ay", &json!({"hex": "zz"})).unwrap_err();
        encode("ay", &json!("x")).unwrap_err();
        let d = encode("a{sv}", &json!({"n": 3, "b": true, "s": "x"})).unwrap();
        assert_eq!(decode(&d), json!({"n": 3, "b": true, "s": "x"}));
        encode("a{sv}", &json!({"l": [1]})).unwrap_err();
        encode("a{ss}", &json!({})).unwrap_err();
        let s = encode("(su)", &json!(["a", 1])).unwrap();
        assert_eq!(decode(&s), json!(["a", 1]));
        encode("(su)", &json!(["a"])).unwrap_err();
        encode("h", &json!(1)).unwrap_err();
        let a = encode("as", &json!(["x", "y"])).unwrap();
        assert_eq!(decode(&a), json!(["x", "y"]));
    }

    #[test]
    fn matching_rules() {
        let mut b = binds();
        matches(&json!("*"), &json!({"x": 1}), &mut b).unwrap();
        matches(&json!("$h"), &json!(5), &mut b).unwrap();
        matches(&json!("$h"), &json!(5), &mut b).unwrap();
        assert!(matches(&json!("$h"), &json!(6), &mut b).is_err());
        matches(&json!({"a": 1}), &json!({"a": 1, "b": 2}), &mut b).unwrap();
        assert!(matches(&json!({"a": 1, "c": 1}), &json!({"a": 1}), &mut b).is_err());
        matches(&json!([1, "..."]), &json!([1, 2, 3]), &mut b).unwrap();
        assert!(matches(&json!([1, 2, "..."]), &json!([1]), &mut b).is_err());
        assert!(matches(&json!([1]), &json!([1, 2]), &mut b).is_err());
        matches(&json!({"bytes": "ab"}), &json!({"hex": "6162"}), &mut b).unwrap();
        assert!(matches(&json!({"bytes": "ab"}), &json!({"hex": "6163"}), &mut b).is_err());
        assert!(matches(&json!(1), &json!(2), &mut b).is_err());
        matches(&json!("a"), &json!("a"), &mut b).unwrap();
    }

    #[test]
    fn substitution() {
        let mut b = binds();
        b.insert("h".into(), json!(9));
        assert_eq!(substitute(&json!(["$h", {"k": "$h"}, "x"]), &b).unwrap(), json!([9, {"k": 9}, "x"]));
        substitute(&json!("$nope"), &b).unwrap_err();
    }

    #[test]
    fn parsing() {
        let seq = parse(
            r#"{"description":"d","consent":"unknown","files":{"a":"b"},"steps":[
                {"call":"X","sig":"","args":[],"reply":[]},
                {"call":"Y","sig":"","args":[],"error":"E"},
                {"signal":"S","args":["*"]}]}"#,
        )
        .unwrap();
        assert_eq!(seq.consent, Consent::Unknown);
        assert_eq!(seq.files, vec![("a".to_owned(), "b".to_owned())]);
        assert_eq!(seq.steps.len(), 3);
        parse(r#"{"description":"d","consent":"maybe","steps":[]}"#).unwrap_err();
        parse(r#"{"description":"d","consent":"denied","files":{"a":1},"steps":[]}"#).unwrap_err();
        let err =
            parse(r#"{"description":"d","consent":"denied","steps":[{"call":"X","sig":"","args":[]}]}"#)
                .unwrap_err();
        assert!(err.starts_with("step 1: "), "{err}");
        parse("not json").unwrap_err();
    }

    #[test]
    fn signatures_of_replies() {
        check_reply_signature("Stat", "(ayyyxxxxixxssqays)").unwrap();
        assert!(check_reply_signature("Stat", "ayyyxxxxixxssqays").is_err());
        check_reply_signature("Frobnicate", "s").unwrap();
    }

    #[tokio::test]
    async fn inbox_hands_out_in_order() {
        let inbox = Inbox::default();
        let one = |n: i32| Ok((String::new(), vec![json!(n)]));
        inbox.push("A".into(), one(1));
        inbox.push("B".into(), one(2));
        inbox.push("A".into(), one(3));
        assert_eq!(inbox.take("A"), Some(one(1)));
        assert_eq!(inbox.take("A"), Some(one(3)));
        assert_eq!(inbox.take("A"), None);
        assert_eq!(inbox.take("B"), Some(one(2)));
    }

    #[tokio::test]
    async fn a_failing_expectation_is_reported() {
        let seq = parse(
            r#"{"description":"d","consent":"granted","steps":[
                {"call":"Hello","sig":"s","args":["t"],"reply":["another version"]}]}"#,
        )
        .unwrap();
        let err = replay(&seq).await.unwrap_err();
        assert!(err.contains("step 1"), "{err}");
    }

    #[tokio::test]
    async fn seeding_and_connecting_failures_are_reported() {
        let seq = parse(r#"{"description":"d","consent":"granted","steps":[]}"#).unwrap();
        let err =
            replay_sequence(&seq, async |_: &Sequence| Err("no".to_owned()), async || Err("x".to_owned()))
                .await
                .unwrap_err();
        assert_eq!(err, "seeding: no");
        let err = replay_sequence(&seq, async |_: &Sequence| Ok(()), async || Err("refused".to_owned()))
            .await
            .unwrap_err();
        assert_eq!(err, "connecting: refused");
    }
}
