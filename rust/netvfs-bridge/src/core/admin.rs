// SPDX-License-Identifier: LGPL-2.1-or-later
//! The session, consent, locations, questions and the handoff (`Session::
//! Admin` of session.cpp, the consent half of bridgeserver.cpp): `Hello`,
//! `GetConsent`, `RequestConsent`, `ListLocations`, `Capabilities`,
//! `Disconnect`, `ConnectAdHoc`, `ForgetAdHoc`, `Discover`, `Cancel`,
//! `Answer`, `OpenAccountSettings` and `AddAccount`.

use super::questions::INSECURE_CONSENT;
use super::{Core, Event};
use crate::consent::{Consent, ConsentStore};
use crate::ffi::{Params, ParsedUrl, Value};
use crate::locations::book::no_consent;
use crate::locations::connector::Connector;
use crate::locations::spec::{AdHocSecret, LocationSpec};
use crate::locations::worker::{Turn, Work};
use crate::locations::{Answer, AskId, TaskContext};
use crate::prompt::PromptEvent;
use crate::server::args::{AdHocOpts, LocId, Secret, is_valid_token};
use crate::server::{OutSignal, Reply, ReplyTo, SessionId};
use crate::status::Status;
use netvfs_bridge_proto::{ErrorName, Lane};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::Instant;
use zbus::zvariant::{OwnedValue, Str};

/// Longest provider name a parsed URL may have.
const MAX_PROVIDER: usize = 32;

/// An ad-hoc location waiting for its first connection (or for the
/// consumer's answer to `insecure-consent`).
pub(crate) struct PendingAdHoc {
    /// Its name: the host.
    pub(crate) name: String,
    /// How to connect.
    pub(crate) params: Params,
    /// The path of the URL.
    pub(crate) path: Vec<u8>,
    /// The consumer's secret (XB-16).
    pub(crate) secret: Arc<AdHocSecret>,
}

/// Who waits for the answer to a question.
pub(crate) enum Waiter {
    /// A worker (identity-unknown, keyboard-interactive).
    Worker {
        /// The worker's id of the question.
        ask: AskId,
        /// Where the answer goes.
        answer: std::sync::mpsc::Sender<Option<Answer>>,
    },
    /// `ConnectAdHoc` of an insecure location (`insecure-consent`).
    Insecure {
        /// The session that called.
        sid: SessionId,
        /// The location.
        pending: Box<PendingAdHoc>,
        /// The answer slot of `ConnectAdHoc`.
        reply: ReplyTo,
    },
}

/// The text of option `key`, as the C++ `ConnectionParams::option` gave it.
fn option_text(params: &Params, key: &str) -> Option<String> {
    match params.options.get(key)? {
        Value::Str(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Int(n) => Some(n.to_string()),
        Value::Bytes(_) | Value::StrList(_) => None,
    }
}

/// W-2, XM-1: an ad-hoc location without transport security needs the
/// consumer's `insecure-consent` (`needsInsecureConsent`).
pub(crate) fn needs_insecure_consent(params: &Params) -> bool {
    let is =
        |key: &str, values: &[&str]| option_text(params, key).is_some_and(|v| values.contains(&v.as_str()));
    match params.provider.as_str() {
        "webdav" => is("tls", &["http"]),
        "ftp" => is("tls_mode", &["none"]),
        "smb" => is("security_profile", &["legacy", "guest"]),
        _ => false,
    }
}

/// Checks a parsed ad-hoc URL (`parseAdHoc`): never local files (XB-11),
/// an installed backend, `security_profile` for SMB only. The C++ parser's
/// output is checked as well (a provider token, a port).
///
/// # Errors
/// `PermissionDenied`, `Unsupported`, or `ProtocolError` (the dispatch
/// refuses it as invalid arguments).
pub(crate) fn check_ad_hoc(
    parsed: &ParsedUrl,
    opts: &AdHocOpts,
    provider_available: impl FnOnce(&str) -> bool,
) -> Result<(), Status> {
    let provider = parsed.params.provider.as_str();
    if !is_valid_token(provider, MAX_PROVIDER) || !(0..=65_535).contains(&parsed.params.port) {
        return Err(Status::invalid_args("Invalid location URL"));
    }
    if provider == "local" {
        return Err(Status::permission_denied("The bridge never accesses local files"));
    }
    if !provider_available(provider) {
        return Err(Status::new(ErrorName::Unsupported, format!("No backend for {provider} is installed")));
    }
    if opts.security_profile.is_some() && provider != "smb" {
        return Err(Status::invalid_args("security_profile applies to SMB only"));
    }
    Ok(())
}

/// A string value of a question's details.
fn text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

/// What an `insecure-consent` question shows: `url`, `provider`, `host`.
fn insecure_details(url: &str, params: &Params) -> HashMap<String, OwnedValue> {
    HashMap::from([
        ("url".to_owned(), text(url)),
        ("provider".to_owned(), text(&params.provider)),
        ("host".to_owned(), text(&params.host)),
    ])
}

impl Core {
    // ----------------------------------------------------------- session

    pub(super) fn on_hello(&mut self, sid: SessionId, reply: ReplyTo, protocol: u32, client: &str) {
        if let Some(session) = self.session(sid) {
            session.hello = true;
        }
        crate::log::debug(format_args!("Hello from {client} protocol {protocol}"));
        reply.ok(&Reply::Hello);
        if self.consent == Consent::Unknown {
            self.request_consent(); // XB-6: first Hello while unknown
        }
    }

    pub(super) fn on_get_consent(&self, reply: ReplyTo) {
        reply.ok(&Reply::Text(self.consent.as_str().to_owned()));
    }

    pub(super) fn on_request_consent(&mut self, reply: ReplyTo) {
        if self.consent != Consent::Granted {
            self.request_consent();
        }
        reply.ok(&Reply::Empty);
    }

    pub(super) fn on_list_locations(&self, reply: ReplyTo) {
        // XB-6: nothing until granted.
        let locations = if self.consent == Consent::Granted {
            let ffi = self.ffi;
            self.book
                .visible()
                .map(|spec| spec.wire(|params, path| ffi.url_format(params, path).ok()))
                .collect()
        } else {
            Vec::new()
        };
        reply.ok(&Reply::Locations(locations));
    }

    pub(super) fn on_capabilities(&mut self, sid: SessionId, reply: ReplyTo, loc: &LocId, lane: Lane) {
        self.run_request(sid, reply, loc.as_str(), lane, |conn| conn.capabilities().map(Reply::Capabilities));
    }

    pub(super) fn on_disconnect(&mut self, reply: ReplyTo, loc: &LocId) {
        if let Err(status) = self.pool_for(loc.as_str()) {
            reply.fail(&status);
            return;
        }
        self.book.disconnect(loc.as_str());
        reply.ok(&Reply::Empty);
    }

    // --------------------------------------------------------- ad-hoc

    pub(super) fn on_connect_ad_hoc(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        url: &str,
        secret: Secret,
        opts: AdHocOpts,
    ) {
        let ffi = self.ffi;
        let parsed = match self.url_override.as_ref().and_then(|parse| parse(url)) {
            Some(parsed) => Ok(parsed),
            None => ffi.url_parse(url),
        };
        let parsed = parsed
            .and_then(|parsed| check_ad_hoc(&parsed, &opts, |p| ffi.provider_available(p)).map(|()| parsed));
        let ParsedUrl { mut params, path } = match parsed {
            Ok(parsed) => parsed,
            Err(status) if status.name == ErrorName::ProtocolError => return reply.refuse(&status),
            Err(status) => return reply.fail(&status),
        };
        if let Some(user) = opts.user {
            params.username = user;
        }
        if let Some(profile) = opts.security_profile {
            params.options.insert("security_profile".to_owned(), Value::Str(profile));
        }
        // XB-16: the call's copy moves into the location's.
        let secret = AdHocSecret::new(params.username.clone(), secret.into_inner());
        let pending = PendingAdHoc { name: params.host.clone(), params, path, secret };
        if !needs_insecure_consent(&pending.params) {
            self.connect_ad_hoc(sid, reply, pending);
            return;
        }
        let url = ffi.url_format(&pending.params, &pending.path).unwrap_or_default();
        let details = insecure_details(&url, &pending.params);
        let id = self.questions.ask(sid, Waiter::Insecure { sid, pending: Box::new(pending), reply });
        self.emit_question(sid, &id, INSECURE_CONSENT, details);
    }

    /// The consumer answered `insecure-consent` (or did not: `accepted`
    /// false).
    pub(super) fn insecure_answered(
        &mut self,
        sid: SessionId,
        mut pending: PendingAdHoc,
        reply: ReplyTo,
        accepted: bool,
    ) {
        if !self.sessions.contains_key(&sid) {
            pending.secret.wipe();
            return;
        }
        if !accepted {
            pending.secret.wipe();
            reply.fail(&Status::new(ErrorName::SecurityPolicy, "The insecure connection was declined"));
            return;
        }
        pending.params.options.insert("allow_insecure".to_owned(), Value::Str("true".to_owned()));
        self.connect_ad_hoc(sid, reply, pending);
    }

    /// An accepted ad-hoc location: its pool connects first (XB-14), on an
    /// empty item of the interactive lane; [`Core::on_ad_hoc_done`] makes
    /// it visible.
    fn connect_ad_hoc(&mut self, sid: SessionId, reply: ReplyTo, pending: PendingAdHoc) {
        let id = self.book.reserve_ad_hoc_id();
        let secret = Arc::clone(&pending.secret);
        let spec = LocationSpec::ad_hoc(id.clone(), pending.name, pending.params, pending.path, Some(secret));
        if !self.book.start_ad_hoc(spec) {
            pending.secret.wipe();
            reply.fail(&Status::internal("The ad-hoc location id is taken"));
            return;
        }
        let Some((op, cancel)) = self.start_request(sid, reply) else {
            self.book.abandon_ad_hoc(&id);
            return;
        };
        let tx = self.tx.clone();
        let loc = id.clone();
        // Establishing is what the first item does (identity, then the secret).
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let result = turn.ready.map(|_| ());
            let kept = result.clone();
            drop(tx.send(Event::AdHocDone { sid, op, loc, result }));
            kept
        });
        self.book.submit(&id, Lane::Interactive, TaskContext::new(sid, cancel), work);
    }

    /// The first connection of ad-hoc location `loc` ended its attempt.
    pub(super) fn on_ad_hoc_done(&mut self, sid: SessionId, op: u64, loc: &str, result: Result<(), Status>) {
        self.quota.release_request();
        let reply = self.take_reply(sid, op);
        let result = result.and_then(|()| if self.book.add_ad_hoc(loc) { Ok(()) } else { Err(no_consent()) });
        match result {
            Ok(()) => {
                self.broadcast(&OutSignal::LocationsChanged);
                if let Some(reply) = reply {
                    reply.ok(&Reply::Text(loc.to_owned()));
                }
            }
            Err(status) => {
                self.book.abandon_ad_hoc(loc);
                if let Some(reply) = reply {
                    reply.fail(&status);
                }
            }
        }
    }

    pub(super) fn on_forget_ad_hoc(&mut self, reply: ReplyTo, loc: &LocId) {
        if !self.book.forget_ad_hoc(loc.as_str(), &*self.known_hosts) {
            reply.fail(&Status::new(ErrorName::NotFound, "No such ad-hoc location"));
            return;
        }
        self.broadcast(&OutSignal::LocationsChanged);
        reply.ok(&Reply::Empty);
    }

    // ------------------------------------------------- discovery, cancel

    pub(super) fn on_discover(&mut self, sid: SessionId, reply: ReplyTo, on: bool) {
        self.nearby.set_discovering(sid, on, Instant::now());
        reply.ok(&Reply::Empty);
    }

    pub(super) fn on_cancel(&mut self, sid: SessionId, reply: ReplyTo, id: u32) {
        let Some(session) = self.sessions.get(&sid) else { return };
        if let Some(op) = session.public.get(&id) {
            if let Some(op) = session.ops.get(op) {
                op.cancel.store(true, Ordering::Release);
            }
            self.kick_all();
        } else if id == 0 || id >= session.next_public {
            reply.fail(&Status::new(ErrorName::NotFound, "No such request or job"));
            return;
        }
        reply.ok(&Reply::Empty); // an id that already finished: nothing to do
    }

    pub(super) fn on_answer(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        id: &str,
        accept: bool,
        answers: Vec<Secret>,
    ) {
        let Some(waiter) = self.questions.answer(sid, id) else {
            reply.fail(&Status::new(ErrorName::NotFound, "No such question"));
            return;
        };
        let answer = Answer { accept, answers: answers.into_iter().map(Secret::into_inner).collect() };
        self.resolve(waiter, Some(answer));
        reply.ok(&Reply::Empty);
    }

    // ----------------------------------------------------------- handoff

    pub(super) fn on_open_account_settings(&self, reply: ReplyTo, loc: &LocId) {
        let account =
            self.book.find(loc.as_str()).and_then(|spec| spec.account_id().map(|id| (id, &spec.provider)));
        let Some((account_id, provider)) = account else {
            reply.fail(&Status::new(ErrorName::NotFound, "No such account"));
            return;
        };
        match self.handoff.open_account_settings(account_id, provider) {
            Ok(()) => reply.ok(&Reply::Empty),
            Err(status) => reply.fail(&status),
        }
    }

    pub(super) fn on_add_account(&self, reply: ReplyTo, provider: &str) {
        match self.handoff.add_account(provider) {
            Ok(()) => reply.ok(&Reply::Empty),
            Err(status) => reply.fail(&status),
        }
    }

    // ----------------------------------------------------------- consent

    /// `bridge.conf` changed on disk (`reloadConsent`).
    pub(super) fn reload_consent(&mut self) {
        let consent = self.consent_store.consent(&self.config.consumer.id);
        self.apply_consent(consent);
    }

    /// The consent is now `consent` (`applyConsent`): tells every session;
    /// a revocation closes them all and drops the locations (XB-6).
    pub(super) fn apply_consent(&mut self, consent: Consent) {
        if consent == self.consent {
            return;
        }
        let previous = std::mem::replace(&mut self.consent, consent);
        crate::log::debug(format_args!("Consent {}", consent.as_str()));
        if consent != Consent::Unknown {
            self.prompt.withdraw();
        }
        self.broadcast(&OutSignal::ConsentChanged(consent.as_str().to_owned()));
        if previous == Consent::Granted {
            // XB-6: revocation closes the consumer's connections at once and
            // cancels its work; ad-hoc locations and their secrets go.
            crate::log::warning(format_args!("Consent revoked; closing all connections"));
            let sids: Vec<SessionId> = self.sessions.keys().copied().collect();
            for sid in sids {
                if let Some(session) = self.sessions.get(&sid) {
                    session.outbox.close();
                }
                self.cancel_session(sid);
            }
            self.book.revoke();
        } else if consent == Consent::Granted {
            self.broadcast(&OutSignal::LocationsChanged);
        }
    }

    /// Shows the consent question unless granted or shown (`requestConsent`).
    pub(super) fn request_consent(&mut self) {
        if self.consent == Consent::Granted || self.prompt.is_shown() {
            return;
        }
        self.prompt.show(&self.config.consumer.display_name);
    }

    /// The prompt was answered (stored, then applied) or dismissed.
    pub(super) fn on_prompt(&mut self, event: PromptEvent) {
        let PromptEvent::Answered(allow) = event else { return };
        let consent = if allow { Consent::Granted } else { Consent::Denied };
        let store = ConsentStore::new(self.consent_store.path());
        let (id, tx) = (self.config.consumer.id.clone(), self.tx.clone());
        self.consent_writes = self.consent_writes.saturating_add(1);
        // The file lock may wait: off the core's thread.
        let writing = tokio::task::spawn_blocking(move || {
            // A failure is logged by the store; the answer holds until restart.
            drop(store.set_consent(&id, consent));
            drop(tx.send(Event::ConsentStored(consent)));
        });
        drop(writing);
    }

    /// The answer to the prompt was stored.
    pub(super) fn on_consent_stored(&mut self, consent: Consent) {
        self.consent_writes = self.consent_writes.saturating_sub(1);
        self.apply_consent(consent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::ValueMap;

    fn params(provider: &str, options: &[(&str, Value)]) -> Params {
        let options: ValueMap = options.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
        Params { provider: provider.to_owned(), host: "h".to_owned(), options, ..Params::default() }
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_owned())
    }

    #[test]
    fn insecure_transports_need_consent() {
        assert!(needs_insecure_consent(&params("webdav", &[("tls", s("http"))])));
        assert!(!needs_insecure_consent(&params("webdav", &[("tls", s("https"))])));
        assert!(!needs_insecure_consent(&params("webdav", &[])));
        assert!(needs_insecure_consent(&params("ftp", &[("tls_mode", s("none"))])));
        assert!(!needs_insecure_consent(&params("ftp", &[("tls_mode", s("explicit"))])));
        assert!(needs_insecure_consent(&params("smb", &[("security_profile", s("legacy"))])));
        assert!(needs_insecure_consent(&params("smb", &[("security_profile", s("guest"))])));
        assert!(!needs_insecure_consent(&params("smb", &[("security_profile", s("signed"))])));
        assert!(!needs_insecure_consent(&params("sftp", &[("tls", s("http"))])));
        // Options of other types as the C++ QVariant::toString gave them.
        assert!(!needs_insecure_consent(&params("webdav", &[("tls", Value::Bool(true))])));
        assert!(!needs_insecure_consent(&params("ftp", &[("tls_mode", Value::Bytes(b"none".to_vec()))])));
        assert_eq!(option_text(&params("x", &[("a", Value::Bool(false))]), "a").as_deref(), Some("false"));
        assert_eq!(option_text(&params("x", &[("a", Value::Int(-3))]), "a").as_deref(), Some("-3"));
        assert_eq!(option_text(&params("x", &[("a", Value::StrList(vec![]))]), "a"), None);
    }

    fn parsed(provider: &str, port: i32) -> ParsedUrl {
        let mut p = params(provider, &[]);
        p.port = port;
        ParsedUrl { params: p, path: b"/".to_vec() }
    }

    #[test]
    fn ad_hoc_urls_are_checked() {
        let none = AdHocOpts::default();
        let all = |_: &str| true;
        assert_eq!(check_ad_hoc(&parsed("sftp", 22), &none, all), Ok(()));
        assert_eq!(check_ad_hoc(&parsed("sftp", 0), &none, all), Ok(()));
        assert_eq!(check_ad_hoc(&parsed("sftp", 65_535), &none, all), Ok(()));
        let name = |r: Result<(), Status>| r.err().map(|s| (s.name, s.message));
        assert_eq!(
            name(check_ad_hoc(&parsed("sftp", 65_536), &none, all)),
            Some((ErrorName::ProtocolError, "Invalid location URL".to_owned()))
        );
        assert_eq!(
            name(check_ad_hoc(&parsed("sftp", -1), &none, all)).map(|n| n.0),
            Some(ErrorName::ProtocolError)
        );
        assert_eq!(
            name(check_ad_hoc(&parsed("S/FTP", 22), &none, all)).map(|n| n.0),
            Some(ErrorName::ProtocolError)
        );
        assert_eq!(
            name(check_ad_hoc(&parsed("local", 0), &none, all)),
            Some((ErrorName::PermissionDenied, "The bridge never accesses local files".to_owned()))
        );
        assert_eq!(
            name(check_ad_hoc(&parsed("nfs", 0), &none, |p| p != "nfs")),
            Some((ErrorName::Unsupported, "No backend for nfs is installed".to_owned()))
        );
        let profile = AdHocOpts { user: None, security_profile: Some("guest".to_owned()) };
        assert_eq!(check_ad_hoc(&parsed("smb", 445), &profile, all), Ok(()));
        assert_eq!(
            name(check_ad_hoc(&parsed("sftp", 22), &profile, all)),
            Some((ErrorName::ProtocolError, "security_profile applies to SMB only".to_owned()))
        );
    }

    #[test]
    fn insecure_questions_show_where() {
        let d = insecure_details("ftp://h/", &params("ftp", &[]));
        assert_eq!(d.len(), 3);
        assert_eq!(String::try_from(d["url"].clone()).unwrap(), "ftp://h/");
        assert_eq!(String::try_from(d["provider"].clone()).unwrap(), "ftp");
        assert_eq!(String::try_from(d["host"].clone()).unwrap(), "h");
    }
}
