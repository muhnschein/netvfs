// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-accounts-fake: a test stand-in for netvfs-accounts (feature
//! `test-bins`). It answers `list`, `files <id>` and
//! `attention <id> <state> [pin]` in the helper's format from the table
//! that `NETVFS_FAKE_ACCOUNTS` names, one tab-separated record per line:
//!
//! ```text
//! account    <id> <provider> <display name> <host> <port> <user> <files root> <attention>
//! option     <id> <key> <s|b|i|u> <value>
//! attention  <id> <state> <pin>
//! ```
//!
//! `attention` appends its record, so a later `list` shows it. `files`
//! reports credentials id 0 and an optional secret.

use netvfs_bridge::accounts::qds::Writer;
use netvfs_bridge::accounts::{Attention, ConnectionParams, Value};
use netvfs_bridge::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "Usage: netvfs-accounts list | files <id> | attention <id> <state> [pin]";

#[derive(Debug, Default)]
struct Account {
    id: i32,
    provider: String,
    display_name: String,
    params: ConnectionParams,
    files_root: String,
    attention: Attention,
}

fn attention(state: &str) -> Option<Attention> {
    match state {
        "auth-failed" => Some(Attention::AuthFailed),
        "server-identity-changed" => Some(Attention::ServerIdentityChanged),
        _ => None,
    }
}

fn value(kind: &str, text: &str) -> Value {
    match kind {
        "b" => Value::Bool(text == "true"),
        "i" => text.parse().map_or(Value::Invalid, Value::Int),
        "u" => text.parse().map_or(Value::Invalid, Value::UInt),
        _ => Value::String(text.to_owned()),
    }
}

fn parse_account(fields: &[&str]) -> Option<Account> {
    let [id, provider, display_name, host, port, user, files_root, state] = fields else {
        return None;
    };
    Some(Account {
        id: id.parse().ok()?,
        provider: (*provider).to_owned(),
        display_name: (*display_name).to_owned(),
        params: ConnectionParams {
            provider: (*provider).to_owned(),
            host: (*host).to_owned(),
            port: port.parse().ok()?,
            username: (*user).to_owned(),
            ..ConnectionParams::default()
        },
        files_root: (*files_root).to_owned(),
        attention: attention(state).unwrap_or_default(),
    })
}

/// Applies one record; `None` for a malformed one.
fn apply(accounts: &mut Vec<Account>, line: &str) -> Option<()> {
    let fields: Vec<&str> = line.split('\t').collect();
    let (&kind, rest) = fields.split_first()?;
    if kind == "account" {
        accounts.push(parse_account(rest)?);
        return Some(());
    }
    let (id, rest) = rest.split_first()?;
    let id: i32 = id.parse().ok()?;
    let account = accounts.iter_mut().find(|a| a.id == id)?;
    match (kind, rest) {
        ("option", [key, kind, text]) => {
            account.params.options.retain(|(k, _)| k != key);
            account.params.options.push(((*key).to_owned(), value(kind, text)));
        }
        ("attention", [state, _pin]) => account.attention = attention(state)?,
        _ => return None,
    }
    Some(())
}

fn load(path: &str) -> Result<Vec<Account>, Status> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Status::new(ErrorName::Internal, format!("Cannot read {path}: {e}")))?;
    let mut accounts = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        apply(&mut accounts, line)
            .ok_or_else(|| Status::new(ErrorName::Internal, format!("Bad record in {path}: {line}")))?;
    }
    Ok(accounts)
}

fn not_found() -> Status {
    Status::new(ErrorName::NotFound, "No such account")
}

fn find<'a>(accounts: &'a [Account], id: &str) -> Result<&'a Account, Status> {
    let id: i32 = id.trim().parse().map_err(|_e| not_found())?;
    accounts.iter().find(|a| id > 0 && a.id == id).ok_or_else(not_found)
}

fn list(accounts: &[Account]) -> Writer {
    let mut w = Writer::answer(None);
    w.i32(i32::try_from(accounts.len()).unwrap_or(i32::MAX));
    for a in accounts {
        w.i32(a.id);
        w.string(Some(&a.provider));
        w.string(Some(&a.display_name));
        w.params(&a.params);
        w.string(Some(&a.files_root));
        w.i32(a.attention as i32);
    }
    w
}

fn files(accounts: &[Account], id: &str) -> Result<Writer, Status> {
    let account = find(accounts, id)?;
    let mut w = Writer::answer(None);
    w.params(&account.params);
    w.u32(0);
    w.bool(true);
    Ok(w)
}

fn record_attention(
    path: &str,
    accounts: &[Account],
    id: &str,
    state: &str,
    pin: &str,
) -> Result<Writer, Status> {
    if attention(state).is_none() {
        return Err(Status::new(ErrorName::Unsupported, "Unknown attention state"));
    }
    let account = find(accounts, id)?;
    let write = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut f| writeln!(f, "attention\t{}\t{state}\t{pin}", account.id));
    write.map_err(|e| Status::new(ErrorName::Internal, format!("Cannot write {path}: {e}")))?;
    Ok(Writer::answer(None))
}

fn serve(path: &str, arguments: &[String]) -> Result<Writer, Status> {
    let accounts = load(path)?;
    match arguments {
        [c] if c == "list" => Ok(list(&accounts)),
        [c, id] if c == "files" => files(&accounts, id),
        [c, id, state] if c == "attention" => record_attention(path, &accounts, id, state, ""),
        [c, id, state, pin] if c == "attention" => record_attention(path, &accounts, id, state, pin),
        _ => Err(Status::new(ErrorName::Unsupported, USAGE)),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let path = std::env::var("NETVFS_FAKE_ACCOUNTS").unwrap_or_default();
    let answer = serve(&path, &arguments).unwrap_or_else(|status| Writer::answer(Some(&status)));
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(&answer.into_bytes()).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
