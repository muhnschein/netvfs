// SPDX-License-Identifier: LGPL-2.1-or-later
//! Session, consent, locations, questions and settings handoff calls.

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
use netvfs_bridge_proto::methods::{FEATURE_DRIVES, FEATURE_STORAGE_SETTINGS};
use netvfs_bridge_proto::{ErrorName, Lane};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::Instant;
use zbus::zvariant::{OwnedValue, Str};

const MAX_PROVIDER: usize = 32;

pub(crate) struct PendingAdHoc {
    pub(crate) name: String,
    pub(crate) params: Params,
    pub(crate) path: Vec<u8>,
    pub(crate) secret: Arc<AdHocSecret>,
}

pub(crate) enum Waiter {
    Worker { ask: AskId, answer: std::sync::mpsc::Sender<Option<Answer>> },
    Insecure { sid: SessionId, pending: Box<PendingAdHoc>, reply: ReplyTo },
}

fn option_text(params: &Params, key: &str) -> Option<String> {
    match params.options.get(key)? {
        Value::Str(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Int(n) => Some(n.to_string()),
        Value::Bytes(_) | Value::StrList(_) => None,
    }
}

pub(crate) fn needs_insecure_consent(params: &Params) -> bool {
    params.provider == "smb" && option_text(params, "security_profile").is_some_and(|v| v == "guest")
}

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

fn text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

fn insecure_details(url: &str, params: &Params) -> HashMap<String, OwnedValue> {
    HashMap::from([
        ("url".to_owned(), text(url)),
        ("provider".to_owned(), text(&params.provider)),
        ("host".to_owned(), text(&params.host)),
    ])
}

impl Core {
    pub(super) fn on_hello(&mut self, sid: SessionId, reply: ReplyTo, client: &str) {
        if let Some(session) = self.session(sid) {
            session.hello = true;
        }
        crate::log::debug(format_args!("Hello from {client}"));
        reply.ok(&Reply::Hello);
        if self.consent == Consent::Unknown {
            self.request_consent();
        }
    }

    pub(super) fn on_get_consent(&self, reply: ReplyTo) {
        reply.ok(&Reply::Text(self.consent.as_str().to_owned()));
    }

    pub(super) fn on_get_features(&self, reply: ReplyTo) {
        let mut features = Vec::new();
        if self.handoff.offers_storage_settings() {
            features.push(FEATURE_STORAGE_SETTINGS.to_owned());
        }
        features.push(FEATURE_DRIVES.to_owned());
        reply.ok(&Reply::Names(features));
    }

    pub(super) fn on_request_consent(&mut self, reply: ReplyTo) {
        if self.consent != Consent::Granted {
            self.request_consent();
        }
        reply.ok(&Reply::Empty);
    }

    pub(super) fn on_list_locations(&mut self, reply: ReplyTo) {
        // Nothing until granted.
        let locations = if self.consent == Consent::Granted {
            let ffi = self.ffi;
            let states = self.book.states();
            let locations = self
                .book
                .visible()
                .map(|spec| {
                    let state = states.get(&spec.id).copied().unwrap_or_default();
                    spec.wire(state, |params, path| ffi.url_format(params, path).ok())
                })
                .collect();
            // A state not announced yet goes to every session soon.
            self.states.listed(&states, Instant::now());
            locations
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
        // The call's copy moves into the location's.
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

    pub(super) fn on_ad_hoc_done(&mut self, sid: SessionId, op: u64, loc: &str, result: Result<(), Status>) {
        self.quota.release_request();
        let reply = self.take_reply(sid, op);
        let result = result.and_then(|()| if self.book.add_ad_hoc(loc) { Ok(()) } else { Err(no_consent()) });
        match result {
            Ok(()) => {
                self.locations_changed();
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
        self.locations_changed();
        reply.ok(&Reply::Empty);
    }

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
        reply.ok(&Reply::Empty);
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

    pub(super) fn on_open_storage_settings(&self, reply: ReplyTo) {
        match self.handoff.open_storage_settings() {
            Ok(()) => reply.ok(&Reply::Empty),
            Err(status) => reply.fail(&status),
        }
    }

    pub(super) fn reload_consent(&mut self) {
        let consent = self.consent_store.consent(&self.config.consumer.id);
        self.apply_consent(consent);
    }

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
            // Revocation closes the consumer's connections at once and cancels its work; ad-hoc locations and secrets go.
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
            self.locations_changed();
        }
    }

    pub(super) fn request_consent(&mut self) {
        if self.consent == Consent::Granted || self.prompt.is_shown() {
            return;
        }
        self.prompt.show(&self.config.consumer.display_name);
    }

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
        assert!(needs_insecure_consent(&params("smb", &[("security_profile", s("guest"))])));
        assert!(!needs_insecure_consent(&params("smb", &[("security_profile", s("signed"))])));
        assert!(!needs_insecure_consent(&params("smb", &[])));
        assert!(!needs_insecure_consent(&params("sftp", &[("security_profile", s("guest"))])));
        // Other option types stringified like QVariant::toString.
        assert!(!needs_insecure_consent(&params("smb", &[("security_profile", Value::Bool(true))])));
        assert!(!needs_insecure_consent(&params(
            "smb",
            &[("security_profile", Value::Bytes(b"guest".to_vec()))]
        )));
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
            name(check_ad_hoc(&parsed("sftp/x", 22), &none, all)).map(|n| n.0),
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
        let d = insecure_details("smb://h/", &params("smb", &[]));
        assert_eq!(d.len(), 3);
        assert_eq!(String::try_from(d["url"].clone()).unwrap(), "smb://h/");
        assert_eq!(String::try_from(d["provider"].clone()).unwrap(), "smb");
        assert_eq!(String::try_from(d["host"].clone()).unwrap(), "h");
    }
}
