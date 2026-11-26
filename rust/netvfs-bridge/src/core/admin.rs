// SPDX-License-Identifier: LGPL-2.1-or-later

use super::Core;
use crate::consent::Consent;
use crate::prompt::PromptEvent;
use crate::server::args::LocId;
use crate::server::{OutSignal, Reply, ReplyTo, SessionId};
use crate::status::Status;
use netvfs_bridge_proto::methods::{
    FEATURE_CHECK, FEATURE_DRIVES, FEATURE_NETWORK, FEATURE_SEARCH, FEATURE_STORAGE_SETTINGS,
};
use netvfs_bridge_proto::{ErrorName, Lane};
use std::sync::atomic::Ordering;
use tokio::time::Instant;

impl Core {
    pub(super) fn on_hello(&mut self, sid: SessionId, reply: ReplyTo, client: &str) {
        if let Some(session) = self.session(sid) {
            session.hello = true;
        }
        crate::log::debug(format_args!("Hello from {client}"));
        reply.ok(&Reply::Hello);
        self.request_consent();
    }

    pub(super) fn on_get_consent(&self, reply: ReplyTo) {
        reply.ok(&Reply::Text(self.consent.wire().to_owned()));
    }

    pub(super) fn on_get_features(&self, reply: ReplyTo) {
        let mut features = Vec::new();
        if self.handoff.offers_storage_settings() {
            features.push(FEATURE_STORAGE_SETTINGS.to_owned());
        }
        features.push(FEATURE_DRIVES.to_owned());
        features.push(FEATURE_NETWORK.to_owned());
        features.push(FEATURE_CHECK.to_owned());
        features.push(FEATURE_SEARCH.to_owned());
        reply.ok(&Reply::Names(features));
    }

    pub(super) fn on_request_consent(&mut self, reply: ReplyTo) {
        self.request_consent();
        reply.ok(&Reply::Empty);
    }

    pub(super) fn on_list_locations(&mut self, reply: ReplyTo) {
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
        self.states.listed(&states, Instant::now());
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

    pub(super) fn on_open_account_settings(&self, reply: ReplyTo, loc: &LocId) {
        let account = self.book.find(loc.as_str()).map(|spec| (spec.account_id, &spec.provider));
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
        let before = self.levels();
        let previous = std::mem::replace(&mut self.consent, consent);
        let after = self.levels();
        let decided = self.consent.is_decided();
        crate::log::debug(format_args!("Consent {}", self.consent.wire()));
        self.update_prompt();
        if previous.wire() != self.consent.wire() {
            self.broadcast(&OutSignal::ConsentChanged(self.consent.wire().to_owned()));
        }
        let narrowed = previous.is_decided()
            && (!decided || before.iter().any(|(id, old)| narrows(*old, after.get(id).copied().flatten())));
        if narrowed {
            crate::log::warning(format_args!("Access narrowed; closing all connections"));
            let sids: Vec<SessionId> = self.sessions.keys().copied().collect();
            for sid in sids {
                if let Some(session) = self.sessions.get(&sid) {
                    session.outbox.close();
                }
                self.cancel_session(sid);
            }
            if !decided {
                self.book.revoke();
            }
        }
        self.apply_access();
        if before != after {
            self.locations_changed();
        }
    }

    pub(super) fn request_consent(&mut self) {
        if self.pending() && !self.prompt.is_shown() {
            self.prompt.show(&self.config.consumer.display_name);
        }
    }

    pub(super) fn update_prompt(&mut self) {
        if !self.pending() {
            self.prompt.withdraw();
        } else if self.sessions.values().any(|s| s.hello) {
            self.request_consent();
        }
    }

    pub(super) fn on_prompt(&mut self, event: PromptEvent) {
        if event != PromptEvent::Opened {
            return;
        }
        if let Err(status) = self.handoff.open_access_request() {
            crate::log::warning(format_args!("Cannot open the access request: {}", status.message));
        }
    }
}

fn narrows(old: Option<crate::consent::Level>, new: Option<crate::consent::Level>) -> bool {
    match (old, new) {
        (Some(old), Some(new)) => !new.covers(old),
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowing() {
        use crate::consent::Level::{Add, Full, Read, ReadAdd};
        assert!(!narrows(None, None));
        assert!(!narrows(None, Some(Read)));
        assert!(narrows(Some(Read), None));
        assert!(!narrows(Some(Read), Some(Read)));
        assert!(!narrows(Some(Read), Some(ReadAdd)));
        assert!(!narrows(Some(Add), Some(Full)));
        assert!(narrows(Some(Full), Some(ReadAdd)));
        assert!(narrows(Some(ReadAdd), Some(Read)));
        assert!(narrows(Some(Read), Some(Add)));
        assert!(narrows(Some(Add), Some(Read)));
    }
}
