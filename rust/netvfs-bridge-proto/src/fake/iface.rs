// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `org.netvfs.Bridge1` interface of the fake. Checks happen in the order
//! of the C++ bridge (`session.cpp`): argument validation
//! (`InvalidArgs`, `InvalidName`), then `Hello` first, then consent, then the
//! scripted latency and failures, then the operation.

use super::DEFAULT_CAPS;
use super::args::{self, Dict};
use super::fail::Fail;
use super::state::{CancelOutcome, Consent, InfoValue, RecordedAnswer, Session, Shared};
use super::transfer::{self, Env};
use super::tree::{Tree, TreeError};
use crate::errors::ErrorName;
use crate::limits::{MAX_HANDLES, MAX_PATH, RETRY_AFTER_MS};
use crate::methods::{Lane, OBJECT_PATH, find_method};
use crate::wire::{WireCapabilities, WireEntry, WireLocation, WireNearby, WireWalkItem};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::Arc;
use zbus::ObjectServer;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::{InterfaceName, MemberName};
use zbus::object_server::{DispatchResult2, Interface, SignalEmitter};
use zbus::zvariant::{OwnedFd, OwnedValue, Value};

/// Wraps the generated interface: a call whose signature differs from the
/// method table's fails with `InvalidArgs`, as in the real bridge (zbus alone
/// would answer with its own error name).
pub(super) struct Checked(Iface);

impl Checked {
    pub fn new(shared: Arc<Shared>, session: Arc<Session>) -> Self {
        Self(Iface::new(shared, session))
    }
}

// `Interface` is an async-trait trait; zbus re-exports the macro it uses.
// `DispatchResult2` is marked unstable in zbus 5: a zbus bump that changes
// it breaks this wrapper, and the tests show it (the fake is test-only).
#[zbus::export::async_trait::async_trait]
impl Interface for Checked {
    fn name() -> InterfaceName<'static> {
        Iface::name()
    }

    fn spawn_tasks_for_methods(&self) -> bool {
        self.0.spawn_tasks_for_methods()
    }

    async fn get(
        &self,
        property_name: &str,
        server: &ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<fdo::Result<OwnedValue>> {
        self.0.get(property_name, server, connection, header, emitter).await
    }

    async fn get_all(
        &self,
        server: &ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> fdo::Result<HashMap<String, OwnedValue>> {
        self.0.get_all(server, connection, header, emitter).await
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &Value<'_>,
        server: &ObjectServer,
        connection: &zbus::Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<fdo::Result<()>> {
        self.0.set_mut(property_name, value, server, connection, header, emitter).await
    }

    fn call<'call>(
        &'call self,
        server: &'call ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: MemberName<'call>,
    ) -> DispatchResult2<'call> {
        let wanted = find_method(name.as_str()).map(|m| m.input);
        let given = msg.body().signature().to_string_no_parens();
        if wanted.is_some_and(|w| w != given) {
            let message = format!("{} takes ({})", name.as_str(), wanted.unwrap_or_default());
            return DispatchResult2::new_async(connection, msg, async move {
                Err::<(), Fail>(Fail::args(&message))
            });
        }
        self.0.call(server, connection, msg, name)
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call ObjectServer,
        connection: &'call zbus::Connection,
        msg: &'call zbus::Message,
        name: MemberName<'call>,
    ) -> DispatchResult2<'call> {
        self.0.call_mut(server, connection, msg, name)
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        self.0.introspect_to_writer(writer, level);
    }
}

pub(super) struct Iface {
    shared: Arc<Shared>,
    session: Arc<Session>,
}

impl Iface {
    pub fn new(shared: Arc<Shared>, session: Arc<Session>) -> Self {
        Self { shared, session }
    }

    /// The checks before the operation. Consent and the default lane come
    /// from the method table ([`crate::methods::METHODS`]).
    async fn begin(&self, method: &str, lane: Option<Lane>, target: &str) -> Result<(), Fail> {
        let info =
            find_method(method).ok_or_else(|| Fail::net(ErrorName::Internal, "Not in the method table"))?;
        self.shared.record_call(method, lane.unwrap_or(info.lane).as_str(), target);
        if method != "Hello" && !self.session.with(|s| s.hello) {
            return Err(Fail::net(ErrorName::ProtocolError, "Hello must be the first call"));
        }
        if info.needs_consent && self.shared.with(|s| s.consent) != Consent::Granted {
            return Err(Fail::net(
                ErrorName::PermissionDenied,
                "The user has not allowed this app to use network locations",
            ));
        }
        let (latency, failure) = self.shared.with(|s| (s.latency, s.due_failure(method)));
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        match failure {
            Some(f) => Err(Fail::scripted(&f.name, &f.message).with_detail(f.detail, f.retry_after_ms)),
            None => Ok(()),
        }
    }

    fn require_location(&self, loc: &str) -> Result<(), Fail> {
        if self.shared.with(|s| s.locations.contains_key(loc)) {
            Ok(())
        } else {
            Err(Fail::net(ErrorName::NotFound, "No such location"))
        }
    }

    fn tree<R>(&self, loc: &str, f: impl FnOnce(&mut Tree) -> Result<R, TreeError>) -> Result<R, Fail> {
        self.require_location(loc)?;
        self.shared.with(|s| f(s.tree_mut(loc))).map_err(Fail::from)
    }

    fn env(&self, ctxt: &SignalEmitter<'_>) -> Env {
        if self.session.conn().is_none() {
            self.session.set_conn(ctxt.connection().clone());
        }
        Env { shared: Arc::clone(&self.shared), session: Arc::clone(&self.session), ctx: ctxt.to_owned() }
    }

    fn ask_consent(&self) {
        let auto = self.shared.with(|s| {
            s.consent_requests = s.consent_requests.saturating_add(1);
            s.auto_consent
        });
        if let Some(answer) = auto {
            self.shared.with(|s| s.consent = answer);
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move { shared.broadcast_consent(answer).await });
        }
    }

    /// Starts a job: validates the location, takes the id and runs `work`.
    fn start_job<F, Fut>(&self, ctxt: &SignalEmitter<'_>, work: F) -> u32
    where
        F: FnOnce(Env, u32, Arc<std::sync::atomic::AtomicBool>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let job = self.session.next_id();
        let cancel = self.session.register_job(job);
        let env = self.env(ctxt);
        tokio::spawn(work(env, job, cancel));
        job
    }

    async fn ask_in(
        &self,
        ctxt: &SignalEmitter<'_>,
        kind: &str,
        details: &[(String, InfoValue)],
    ) -> Option<RecordedAnswer> {
        let env = self.env(ctxt);
        env.ask(kind, details).await
    }

    async fn adhoc_questions(&self, ctxt: &SignalEmitter<'_>) -> Result<(), Fail> {
        let questions = self.shared.with(|s| s.adhoc_questions.clone());
        for q in questions {
            match self.ask_in(ctxt, &q.kind, &q.details).await {
                Some(a) if a.accept => {}
                Some(_) => return Err(declined(&q.kind)),
                None => return Err(Fail::net(ErrorName::Canceled, "The question was not answered")),
            }
        }
        Ok(())
    }
}

fn declined(kind: &str) -> Fail {
    match kind {
        "identity-unknown" => {
            Fail::net(ErrorName::ServerIdentityUnknown, "The server identity was not accepted")
        }
        "keyboard-interactive" => Fail::net(ErrorName::AuthFailed, "The sign-in was cancelled"),
        _ => Fail::net(ErrorName::SecurityPolicy, "The insecure connection was declined"),
    }
}

struct AdHocUrl {
    provider: &'static str,
    host: String,
    port: Option<i32>,
    user: Option<String>,
    path: Vec<u8>,
}

fn parse_adhoc(url: &str, opts: &args::AdHocOpts) -> Result<AdHocUrl, Fail> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| Fail::args("Not a valid URL"))?;
    let provider = match scheme {
        "sftp" | "ssh" => "sftp",
        "smb" => "smb",
        "fake" => "fake",
        "dav" | "davs" | "ftp" | "ftps" => {
            return Err(Fail::net(ErrorName::Unsupported, &format!("{scheme} URLs are no longer supported")));
        }
        "file" | "local" => {
            return Err(Fail::net(ErrorName::PermissionDenied, "The bridge never accesses local files"));
        }
        _ => return Err(Fail::net(ErrorName::Unsupported, "No backend for this scheme is installed")),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (userinfo, hostport) = authority.rsplit_once('@').map_or((None, authority), |(u, h)| (Some(u), h));
    if userinfo.is_some_and(|u| u.contains(':')) {
        return Err(Fail::net(ErrorName::SecurityPolicy, "A password in the URL is refused"));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<i32>().map_err(|e| Fail::args(&format!("Invalid port: {e}")))?)),
        None => (hostport, None),
    };
    if host.is_empty() {
        return Err(Fail::args("A URL needs a host"));
    }
    if opts.security_profile.is_some() && provider != "smb" {
        return Err(Fail::args("security_profile applies to SMB only"));
    }
    Ok(AdHocUrl {
        provider,
        host: host.to_owned(),
        port,
        user: opts.user.clone().or_else(|| userinfo.map(str::to_owned)),
        path: args::path(path.as_bytes())?,
    })
}

fn adhoc_info(p: &AdHocUrl) -> Vec<(String, InfoValue)> {
    let mut info = vec![
        ("kind".to_owned(), InfoValue::Str("adhoc".into())),
        ("host".to_owned(), InfoValue::Str(p.host.clone())),
        ("path".to_owned(), InfoValue::Bytes(p.path.clone())),
    ];
    if let Some(port) = p.port {
        info.push(("port".to_owned(), InfoValue::Int(port)));
    }
    if let Some(user) = &p.user {
        info.push(("user".to_owned(), InfoValue::Str(user.clone())));
    }
    info
}

#[zbus::interface(name = "org.netvfs.Bridge1")]
impl Iface {
    // ---- Session ---------------------------------------------------------

    async fn hello(&self, client: String) -> Result<String, Fail> {
        if client.len() > 256 {
            return Err(Fail::args("Argument 1 is too long"));
        }
        self.begin("Hello", None, &client).await?;
        self.session.with(|s| s.hello = true);
        if self.shared.with(|s| s.consent) == Consent::Unknown {
            self.ask_consent();
        }
        Ok(self.shared.with(|s| s.bridge_version.clone()))
    }

    async fn get_consent(&self) -> Result<String, Fail> {
        self.begin("GetConsent", None, "").await?;
        Ok(self.shared.with(|s| s.consent).as_str().to_owned())
    }

    async fn request_consent(&self) -> Result<(), Fail> {
        self.begin("RequestConsent", None, "").await?;
        if self.shared.with(|s| s.consent) != Consent::Granted {
            self.ask_consent();
        }
        Ok(())
    }

    // ---- Locations -------------------------------------------------------

    async fn list_locations(&self) -> Result<Vec<WireLocation>, Fail> {
        self.begin("ListLocations", None, "").await?;
        Ok(self.shared.with(|s| if s.consent == Consent::Granted { s.wire_locations() } else { Vec::new() }))
    }

    // A one-element tuple keeps the reply a single struct argument on the wire.
    async fn capabilities(&self, loc: String) -> Result<(WireCapabilities,), Fail> {
        let loc = args::location(&loc)?;
        self.begin("Capabilities", None, &loc).await?;
        self.require_location(&loc)?;
        Ok((self.shared.with(|s| {
            s.caps.get(&loc).cloned().unwrap_or_else(|| WireCapabilities {
                flags: DEFAULT_CAPS.iter().map(|f| (*f).to_owned()).collect(),
                checksum_algorithms: vec!["sha256".to_owned()],
                max_name_bytes: 255,
            })
        }),))
    }

    async fn disconnect(&self, loc: String) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        self.begin("Disconnect", None, &loc).await?;
        self.require_location(&loc)
    }

    // ---- Ad-hoc locations --------------------------------------------------

    async fn connect_ad_hoc(
        &self,
        url: String,
        secret: Vec<u8>,
        opts: Dict,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<String, Fail> {
        args::url(&url)?;
        args::secret(&secret)?;
        let opts = args::adhoc_opts(&opts)?;
        self.begin("ConnectAdHoc", None, &url).await?;
        let parsed = parse_adhoc(&url, &opts)?;
        self.shared.with(|s| s.received_secrets.push(secret));
        self.adhoc_questions(&ctxt).await?;
        let id = self.shared.with(|s| {
            let id = format!("adhoc:{}", s.next_adhoc);
            s.next_adhoc = s.next_adhoc.saturating_add(1);
            s.add_location(&id, parsed.provider, &parsed.host, adhoc_info(&parsed));
            id
        });
        self.shared.broadcast_locations().await;
        Ok(id)
    }

    async fn forget_ad_hoc(&self, loc: String) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        self.begin("ForgetAdHoc", None, &loc).await?;
        if !loc.starts_with("adhoc:") || !self.shared.with(|s| s.locations.contains_key(&loc)) {
            return Err(Fail::net(ErrorName::NotFound, "No such ad-hoc location"));
        }
        self.shared.with(|s| s.remove_location(&loc));
        self.shared.broadcast_locations().await;
        Ok(())
    }

    // ---- Discovery -------------------------------------------------------

    async fn discover(&self, on: bool, #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>) -> Result<(), Fail> {
        self.begin("Discover", None, "").await?;
        self.env(&ctxt);
        self.session.with(|s| s.discovering = on);
        if on {
            // As netvfs' NearbyService: a start signals what is known right
            // away, after the reply, also when that is nothing yet.
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move { shared.broadcast_nearby().await });
        } else if !self.shared.any_discovering() {
            // netvfs halts the discovery when its last client stops and
            // forgets what it found (Discovery::Private::halt).
            self.shared.with(|s| s.nearby.clear());
        }
        Ok(())
    }

    // ---- Listing -----------------------------------------------------------

    async fn list(
        &self,
        loc: String,
        dir: Vec<u8>,
        lane: String,
        batch: u32,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let loc = args::location(&loc)?;
        let dir = args::path(&dir)?;
        let lane = args::lane(&lane, Lane::Interactive)?;
        let batch = args::list_batch(batch)?;
        self.begin("List", Some(lane), &loc).await?;
        self.require_location(&loc)?;
        let listing = self.tree(&loc, |t| t.list(&dir));
        Ok(self
            .start_job(&ctxt, move |env, req, cancel| transfer::run_list(env, req, listing, batch, cancel)))
    }

    // ---- Metadata ----------------------------------------------------------

    async fn stat(
        &self,
        loc: String,
        path: Vec<u8>,
        follow: bool,
        lane: String,
    ) -> Result<(WireEntry,), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let lane = args::lane(&lane, Lane::Interactive)?;
        self.begin("Stat", Some(lane), &loc).await?;
        self.tree(&loc, |t| t.stat(&path, follow)).map(|e| (e,))
    }

    async fn read_link(&self, loc: String, path: Vec<u8>) -> Result<Vec<u8>, Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        self.begin("ReadLink", None, &loc).await?;
        self.tree(&loc, |t| t.read_link(&path))
    }

    async fn space_info(&self, loc: String, path: Vec<u8>) -> Result<(i64, i64, i64), Fail> {
        let loc = args::location(&loc)?;
        args::path(&path)?;
        self.begin("SpaceInfo", None, &loc).await?;
        let used = self.tree(&loc, |t| Ok(t.used_bytes()))?;
        let total = self.shared.with(|s| s.space_total.get(&loc).copied()).unwrap_or(1_000_000).max(used);
        Ok((total.saturating_sub(used), total, used))
    }

    async fn checksum(&self, loc: String, path: Vec<u8>, algo: String) -> Result<Vec<u8>, Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let algo = args::token(&algo, 32)?;
        self.begin("Checksum", None, &loc).await?;
        if algo != "sha256" {
            return Err(Fail::net(ErrorName::Unsupported, "Unknown checksum algorithm"));
        }
        self.tree(&loc, |t| t.file_data(&path).map(|d| sha2::Sha256::digest(d).to_vec()))
    }

    // ---- Namespace ---------------------------------------------------------

    async fn make_dir(&self, loc: String, path: Vec<u8>, exclusive: bool) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        self.begin("MakeDir", None, &loc).await?;
        self.tree(&loc, |t| t.make_dir(&path, exclusive))
    }

    async fn remove_file(&self, loc: String, path: Vec<u8>) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        self.begin("RemoveFile", None, &loc).await?;
        self.tree(&loc, |t| t.remove_file(&path))
    }

    async fn remove_dir(&self, loc: String, path: Vec<u8>) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        self.begin("RemoveDir", None, &loc).await?;
        self.tree(&loc, |t| t.remove_dir(&path))
    }

    async fn rename(&self, loc: String, from: Vec<u8>, to: Vec<u8>, replace: bool) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let from = args::path(&from)?;
        let to = args::path(&to)?;
        self.begin("Rename", None, &loc).await?;
        self.tree(&loc, |t| t.rename(&from, &to, replace))
    }

    async fn set_attributes(&self, loc: String, path: Vec<u8>, changes: Dict) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let changes = args::attributes(&changes)?;
        self.begin("SetAttributes", None, &loc).await?;
        if changes.is_empty() {
            return Ok(());
        }
        self.tree(&loc, |t| t.set_attributes(&path, changes.mode, changes.mtime_ms))
    }

    async fn make_symlink(&self, loc: String, target: Vec<u8>, link_path: Vec<u8>) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        if target.is_empty() || target.len() > MAX_PATH || target.contains(&0) {
            return Err(Fail::net(ErrorName::InvalidName, "Invalid link target"));
        }
        let link = args::path(&link_path)?;
        self.begin("MakeSymlink", None, &loc).await?;
        self.tree(&loc, |t| t.make_symlink(&target, &link))
    }

    async fn make_hardlink(&self, loc: String, existing: Vec<u8>, new_path: Vec<u8>) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let existing = args::path(&existing)?;
        let new_path = args::path(&new_path)?;
        self.begin("MakeHardlink", None, &loc).await?;
        self.tree(&loc, |t| t.make_hardlink(&existing, &new_path))
    }

    async fn server_copy(&self, loc: String, from: Vec<u8>, to: Vec<u8>, opts: Dict) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        let from = args::path(&from)?;
        let to = args::path(&to)?;
        let opts = args::copy_opts(&opts)?;
        self.begin("ServerCopy", None, &loc).await?;
        self.tree(&loc, |t| t.server_copy(&from, &to, opts.recursive, opts.replace))
    }

    // ---- Handles -----------------------------------------------------------

    async fn open_read(&self, loc: String, path: Vec<u8>, lane: String) -> Result<(u32, i64), Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let lane = args::lane(&lane, Lane::Stream)?;
        self.begin("OpenRead", Some(lane), &loc).await?;
        let size =
            self.tree(&loc, |t| t.file_data(&path).map(|d| i64::try_from(d.len()).unwrap_or(i64::MAX)))?;
        if self.session.open_handles() >= MAX_HANDLES {
            return Err(Fail::net(ErrorName::TooManyConnections, "Too many open handles")
                .with_detail(None, Some(RETRY_AFTER_MS)));
        }
        Ok((self.session.add_handle(&loc, &path), size))
    }

    async fn read(&self, handle: u32, offset: i64, max: u32) -> Result<Vec<u8>, Fail> {
        let offset = args::offset(offset)?;
        let max = args::read_size(max)?;
        self.begin("Read", None, &handle.to_string()).await?;
        let (loc, path) = self.handle(handle)?;
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        self.tree(&loc, |t| {
            let data = t.file_data(&path)?;
            Ok(data.iter().skip(offset).take(max).copied().collect())
        })
    }

    async fn read_ahead(&self, handle: u32, offset: i64, bytes: i64) -> Result<(), Fail> {
        args::offset(offset)?;
        args::offset(bytes)?;
        self.begin("ReadAhead", None, &handle.to_string()).await?;
        self.handle(handle).map(|_| ())
    }

    async fn close(&self, handle: u32) -> Result<(), Fail> {
        self.begin("Close", None, &handle.to_string()).await?;
        match self.session.with(|s| s.handles.remove(&handle)) {
            Some(_) => Ok(()),
            None => Err(Fail::net(ErrorName::NotFound, "No such handle")),
        }
    }

    // ---- Jobs --------------------------------------------------------------

    async fn upload(
        &self,
        loc: String,
        path: Vec<u8>,
        fd: OwnedFd,
        opts: Dict,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let opts = args::transfer_opts(&opts, true)?;
        self.begin("Upload", Some(opts.lane), &loc).await?;
        let file = transfer::Source::new(std::fs::File::from(std::os::fd::OwnedFd::from(fd)))?;
        self.require_location(&loc)?;
        Ok(self.start_job(&ctxt, move |env, job, cancel| {
            transfer::run_upload(env, job, cancel, loc, path, file, opts)
        }))
    }

    async fn download(
        &self,
        loc: String,
        path: Vec<u8>,
        fd: OwnedFd,
        opts: Dict,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        let opts = args::transfer_opts(&opts, false)?;
        self.begin("Download", Some(opts.lane), &loc).await?;
        let file = transfer::Source::new(std::fs::File::from(std::os::fd::OwnedFd::from(fd)))?;
        self.require_location(&loc)?;
        Ok(self.start_job(&ctxt, move |env, job, cancel| {
            transfer::run_download(env, job, cancel, loc, path, file, opts)
        }))
    }

    async fn copy_across(
        &self,
        src_loc: String,
        src: Vec<u8>,
        dst_loc: String,
        dst: Vec<u8>,
        opts: Dict,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let src_loc = args::location(&src_loc)?;
        let src = args::path(&src)?;
        let dst_loc = args::location(&dst_loc)?;
        let dst = args::path(&dst)?;
        let opts = args::copy_opts(&opts)?;
        self.begin("CopyAcross", None, &src_loc).await?;
        self.require_location(&src_loc)?;
        self.require_location(&dst_loc)?;
        Ok(self.start_job(&ctxt, move |env, job, cancel| {
            transfer::run_copy_across(env, job, cancel, (src_loc, src), (dst_loc, dst), opts)
        }))
    }

    async fn remove_tree(
        &self,
        loc: String,
        path: Vec<u8>,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let loc = args::location(&loc)?;
        let path = args::path(&path)?;
        self.begin("RemoveTree", None, &loc).await?;
        self.require_location(&loc)?;
        Ok(self
            .start_job(&ctxt, move |env, job, cancel| transfer::run_remove_tree(env, job, cancel, loc, path)))
    }

    async fn walk(
        &self,
        loc: String,
        root: Vec<u8>,
        opts: Dict,
        #[zbus(signal_emitter)] ctxt: SignalEmitter<'_>,
    ) -> Result<u32, Fail> {
        let loc = args::location(&loc)?;
        let root = args::path(&root)?;
        let opts = args::walk_opts(&opts)?;
        self.begin("Walk", None, &loc).await?;
        self.require_location(&loc)?;
        Ok(self
            .start_job(&ctxt, move |env, job, cancel| transfer::run_walk(env, job, cancel, loc, root, opts)))
    }

    async fn cancel(&self, id: u32) -> Result<(), Fail> {
        self.begin("Cancel", None, &id.to_string()).await?;
        match self.session.cancel(id) {
            CancelOutcome::Unknown => Err(Fail::net(ErrorName::NotFound, "No such request or job")),
            CancelOutcome::Canceled | CancelOutcome::Finished => Ok(()),
        }
    }

    // ---- Questions ---------------------------------------------------------

    async fn answer(&self, id: String, answer: Dict) -> Result<(), Fail> {
        let id = args::location(&id)?;
        let answer = args::answer_opts(&answer)?;
        self.begin("Answer", None, &id).await?;
        let Some(tx) = self.session.take_question(&id) else {
            return Err(Fail::net(ErrorName::NotFound, "No such question"));
        };
        let recorded = RecordedAnswer { id, accept: answer.accept, answers: answer.answers };
        self.shared.with(|s| s.answers.push(recorded.clone()));
        // The asker may have given up; the answer is still recorded.
        tx.send(recorded).ok();
        Ok(())
    }

    // ---- Handoff -----------------------------------------------------------

    async fn open_account_settings(&self, loc: String) -> Result<(), Fail> {
        let loc = args::location(&loc)?;
        self.begin("OpenAccountSettings", None, &loc).await?;
        if !loc.starts_with("account:") || !self.shared.with(|s| s.locations.contains_key(&loc)) {
            return Err(Fail::net(ErrorName::NotFound, "No such account"));
        }
        self.shared.with(|s| s.handoffs.push(format!("settings:{loc}")));
        Ok(())
    }

    async fn add_account(&self, provider: String) -> Result<(), Fail> {
        let provider = args::token(&provider, 32)?;
        self.begin("AddAccount", None, &provider).await?;
        self.shared.with(|s| s.handoffs.push(format!("add:{provider}")));
        Ok(())
    }

    // ---- Signals -----------------------------------------------------------

    #[zbus(signal)]
    pub async fn consent_changed(ctxt: &SignalEmitter<'_>, consent: String) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn locations_changed(ctxt: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn nearby_changed(ctxt: &SignalEmitter<'_>, nearby: Vec<WireNearby>) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn list_batch(ctxt: &SignalEmitter<'_>, req: u32, entries: Vec<WireEntry>) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn list_done(
        ctxt: &SignalEmitter<'_>,
        req: u32,
        error: String,
        message: String,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn job_progress(ctxt: &SignalEmitter<'_>, job: u32, done: i64, total: i64) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn walk_batch(
        ctxt: &SignalEmitter<'_>,
        job: u32,
        entries: Vec<WireWalkItem>,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn job_finished(
        ctxt: &SignalEmitter<'_>,
        job: u32,
        error: String,
        message: String,
        extra: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn question(
        ctxt: &SignalEmitter<'_>,
        id: String,
        kind: String,
        details: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;
}

impl Iface {
    fn handle(&self, handle: u32) -> Result<(String, Vec<u8>), Fail> {
        self.session
            .with(|s| s.handles.get(&handle).cloned())
            .ok_or_else(|| Fail::net(ErrorName::NotFound, "No such handle"))
    }
}

/// Signal context of a session, if its connection is up.
pub(super) fn context(session: &Session) -> Option<SignalEmitter<'static>> {
    let conn = session.conn()?;
    SignalEmitter::new(&conn, OBJECT_PATH).ok()
}

impl Shared {
    pub async fn broadcast_consent(&self, consent: Consent) {
        for session in self.sessions_snapshot() {
            if let Some(ctx) = context(&session) {
                // A closed client simply misses the signal.
                Iface::consent_changed(&ctx, consent.as_str().to_owned()).await.ok();
            }
        }
    }

    pub async fn broadcast_locations(&self) {
        for session in self.sessions_snapshot() {
            if let Some(ctx) = context(&session) {
                // As above.
                Iface::locations_changed(&ctx).await.ok();
            }
        }
    }

    pub async fn broadcast_nearby(&self) {
        let nearby = self.with(|s| s.nearby.clone());
        for session in self.sessions_snapshot() {
            if !session.with(|s| s.discovering) {
                continue;
            }
            if let Some(ctx) = context(&session) {
                // As above.
                Iface::nearby_changed(&ctx, nearby.clone()).await.ok();
            }
        }
    }

    /// A question to the newest client.
    pub async fn ask(&self, kind: &str, details: &[(String, InfoValue)]) -> Option<RecordedAnswer> {
        let session = self.sessions_snapshot().pop()?;
        let ctx = context(&session)?;
        ask_question(self, &session, &ctx, kind, details).await
    }
}

/// Sends a `Question` signal and waits for the matching `Answer`. `None` when
/// the asker is gone before an answer arrives.
pub(super) async fn ask_question(
    shared: &Shared,
    session: &Session,
    ctx: &SignalEmitter<'_>,
    kind: &str,
    details: &[(String, InfoValue)],
) -> Option<RecordedAnswer> {
    let id = shared.with(|s| {
        let id = format!("q{}", s.next_question);
        s.next_question = s.next_question.saturating_add(1);
        id
    });
    let rx = session.add_question(&id);
    let details: HashMap<String, OwnedValue> =
        details.iter().map(|(k, v)| (k.clone(), v.to_owned_value())).collect();
    Iface::question(ctx, id, kind.to_owned(), details).await.ok()?;
    rx.await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::args::AdHocOpts;

    fn plain() -> AdHocOpts {
        AdHocOpts::default()
    }

    #[test]
    fn ad_hoc_urls_are_taken_apart() {
        let opts = AdHocOpts { user: Some("me".into()), security_profile: None };
        let p = parse_adhoc("sftp://other@host.example:2222/a//b/", &opts).unwrap();
        assert_eq!((p.provider, p.host.as_str(), p.port), ("sftp", "host.example", Some(2222)));
        assert_eq!(p.user.as_deref(), Some("me"), "the option wins over the URL");
        assert_eq!(p.path, b"a/b");
        let p = parse_adhoc("sftp://other@host/", &plain()).unwrap();
        assert_eq!(p.user.as_deref(), Some("other"));
        let info = adhoc_info(&p);
        assert!(info.contains(&("kind".to_owned(), InfoValue::Str("adhoc".into()))));
        assert!(info.contains(&("user".to_owned(), InfoValue::Str("other".into()))));
        assert!(!info.iter().any(|(k, _)| k == "port"));
        assert_eq!(parse_adhoc("smb://h/", &plain()).unwrap().provider, "smb");
    }

    #[test]
    fn ad_hoc_urls_are_refused_as_the_bridge_refuses_them() {
        let bare = |url: &str, opts: &AdHocOpts| parse_adhoc(url, opts).err().map(|f| f.bare().to_owned());
        assert_eq!(bare("sftp://u:pw@h/", &plain()).as_deref(), Some("SecurityPolicy"));
        assert_eq!(bare("file:///x", &plain()).as_deref(), Some("PermissionDenied"));
        assert_eq!(bare("gopher://h/", &plain()).as_deref(), Some("Unsupported"));
        for url in ["dav://h/", "davs://h/", "ftp://h/", "ftps://h/", "https://h/"] {
            assert_eq!(bare(url, &plain()).as_deref(), Some("Unsupported"), "{url}");
        }
        let removed = parse_adhoc("davs://h/", &plain()).err();
        assert_eq!(removed.as_ref().map(Fail::message), Some("davs URLs are no longer supported"));
        let legacy = AdHocOpts { user: None, security_profile: Some("legacy".into()) };
        assert!(bare("sftp://h/", &legacy).is_some_and(|n| n.contains("InvalidArgs")));
        assert!(bare("smb://h/", &legacy).is_none());
        assert!(bare("nonsense", &plain()).is_some());
        assert!(bare("sftp:///x", &plain()).is_some());
        assert!(bare("sftp://h:notaport/", &plain()).is_some());
        assert!(bare("sftp://h/a/../b", &plain()).is_some());
    }

    #[test]
    fn declining_maps_to_the_error_of_the_question() {
        assert_eq!(declined("identity-unknown").bare(), "ServerIdentityUnknown");
        assert_eq!(declined("keyboard-interactive").bare(), "AuthFailed");
        assert_eq!(declined("insecure-consent").bare(), "SecurityPolicy");
        assert_eq!(declined("anything-else").bare(), "SecurityPolicy");
    }
}
