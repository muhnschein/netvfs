// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SFTP v3 client (design §4.4): one channel, requests matched to
//! replies by id. A writer task sends what [`Client::send`] queues (so
//! sending never waits, also outside the runtime), a reader task hands
//! each reply to the [`Pending`] that waits for it.
//!
//! A request whose caller stops waiting (cancel, timeout, a dropped
//! [`Pending`]) is *abandoned*: its id stays reserved and its reply is
//! dropped when it comes; a handle that an abandoned `OPEN` brings is
//! closed. More than [`MAX_ABANDONED`] abandoned requests at once end the
//! client (`ConnectionLost`), so a server that stops answering cannot make
//! the table grow (C-10). So does a reply nobody asked for, or one that
//! cannot be read.

use crate::errors::{Failure, connection_lost, malformed, timed_out, unexpected};
use crate::proto::{
    Attrs, FX_EOF, FX_OK, FXP_CLOSE, FXP_EXTENDED, FXP_FSTAT, FXP_LSTAT, FXP_MKDIR, FXP_OPEN, FXP_OPENDIR,
    FXP_READ, FXP_READDIR, FXP_READLINK, FXP_REALPATH, FXP_REMOVE, FXP_RENAME, FXP_RMDIR, FXP_SETSTAT,
    FXP_STAT, FXP_SYMLINK, FXP_WRITE, Name, Reply, ServerVersion, VERSION, decode_reply, decode_version,
};
use crate::wire::{MAX_PACKET, Packet, WireError};
use netvfs_vfs::{CancelToken, ErrorName, Status};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// Most requests abandoned at once before the client gives up.
pub const MAX_ABANDONED: usize = 64;

/// The client's end of the channel. Clones share it.
#[derive(Debug, Clone)]
pub struct Client {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    out: mpsc::UnboundedSender<Vec<u8>>,
    table: Mutex<Table>,
    /// Tripped when the client ends; stops both tasks.
    stop: CancelToken,
    timeout: Duration,
}

#[derive(Debug)]
struct Table {
    next_id: u32,
    slots: HashMap<u32, Slot>,
    abandoned: usize,
    /// Why the client ended, once it has.
    ended: Option<Status>,
}

#[derive(Debug)]
enum Slot {
    Waiting(oneshot::Sender<Reply>),
    /// The reply is dropped when it comes; a handle in it is closed.
    Abandoned {
        close_handle: bool,
    },
}

impl Shared {
    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the client: every waiting request fails with `reason` (the
    /// first reason wins), both tasks stop.
    fn end(&self, reason: Status) {
        let mut table = self.table();
        if table.ended.is_none() {
            table.ended = Some(reason);
        }
        table.slots.clear();
        table.abandoned = 0;
        drop(table);
        self.stop.cancel();
    }

    fn ended(&self) -> Status {
        self.table().ended.clone().unwrap_or_else(connection_lost)
    }

    /// Queues `packet` under a new id; `slot` is what waits for its reply.
    fn queue(&self, packet: Packet, slot: Slot) -> Result<u32, Status> {
        let mut table = self.table();
        if let Some(reason) = &table.ended {
            return Err(reason.clone());
        }
        let mut id = table.next_id;
        while table.slots.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        table.next_id = id.wrapping_add(1);
        let bytes = packet
            .finish(id)
            .ok_or_else(|| Status::new(ErrorName::InvalidName, "The request is too long for SFTP"))?;
        let abandoned = matches!(slot, Slot::Abandoned { .. });
        table.slots.insert(id, slot);
        if abandoned {
            table.abandoned = table.abandoned.saturating_add(1);
        }
        let over = table.abandoned > MAX_ABANDONED;
        drop(table);
        if self.out.send(bytes).is_err() {
            self.end(connection_lost());
            return Err(self.ended());
        }
        if over {
            self.end(too_many_abandoned());
        }
        Ok(id)
    }

    /// Sends `CLOSE` for `handle` without waiting for its reply.
    fn close_detached(&self, handle: &[u8]) {
        // A client that ended has no handles left to close.
        drop(self.queue(Packet::request(FXP_CLOSE).string(handle), Slot::Abandoned { close_handle: false }));
    }

    /// The caller of `id` stopped waiting; `rx` is its end of the reply.
    fn abandon(&self, id: u32, close_handle: bool, rx: &mut oneshot::Receiver<Reply>) {
        let mut table = self.table();
        if let Some(slot) = table.slots.get_mut(&id) {
            *slot = Slot::Abandoned { close_handle };
            table.abandoned = table.abandoned.saturating_add(1);
            let over = table.abandoned > MAX_ABANDONED;
            drop(table);
            if over {
                self.end(too_many_abandoned());
            }
            return;
        }
        // The reply was handed over under the lock: it is in `rx` now, or
        // the client ended and it never comes.
        let delivered = rx.try_recv().ok();
        drop(table);
        if let (true, Some(Reply::Handle(handle))) = (close_handle, delivered) {
            self.close_detached(&handle);
        }
    }

    /// Hands a reply to its request.
    fn dispatch(&self, body: &[u8]) -> Result<(), Status> {
        let (id, reply) = decode_reply(body).map_err(malformed)?;
        let mut table = self.table();
        match table.slots.remove(&id) {
            Some(Slot::Waiting(tx)) => {
                // Under the lock, so that a waiter that stops now finds the
                // reply in its receiver (`abandon`). A waiter that is gone
                // has abandoned its id first: `tx` always has a receiver.
                drop(tx.send(reply));
                Ok(())
            }
            Some(Slot::Abandoned { close_handle }) => {
                table.abandoned = table.abandoned.saturating_sub(1);
                drop(table);
                if let (true, Reply::Handle(handle)) = (close_handle, reply) {
                    self.close_detached(&handle);
                }
                Ok(())
            }
            None => {
                Err(Status::new(ErrorName::ProtocolError, "The server answered a request that was not sent")
                    .with_detail(format!("id {id}")))
            }
        }
    }
}

fn too_many_abandoned() -> Status {
    Status::new(ErrorName::ConnectionLost, "The server left too many requests unanswered")
}

/// A request on its way: [`wait`](Self::wait) for its reply, or drop it
/// to abandon it.
#[derive(Debug)]
pub struct Pending {
    shared: Arc<Shared>,
    id: u32,
    close_handle: bool,
    rx: Option<oneshot::Receiver<Reply>>,
}

impl Pending {
    /// The reply; `Canceled` when `cancel` trips first, `Timeout` after the
    /// request timeout. Either abandons the request.
    ///
    /// # Errors
    /// [`Failure::Local`]: canceled, timed out, or the client ended.
    pub async fn wait(mut self, cancel: &CancelToken) -> Result<Reply, Failure> {
        let timeout = self.shared.timeout;
        let Some(rx) = self.rx.as_mut() else {
            return Err(Failure::Local(Status::internal("The request was already answered")));
        };
        let outcome = tokio::select! {
            biased;
            reply = rx => Some(reply),
            () = cancel.canceled() => None,
            () = tokio::time::sleep(timeout) => return Err(Failure::Local(timed_out(timeout.as_millis()))),
        };
        // Answered or ended: nothing to abandon. Else the drop abandons it.
        match outcome {
            Some(reply) => {
                self.rx = None;
                reply.map_err(|_closed| Failure::Local(self.shared.ended()))
            }
            None => Err(Failure::Local(Status::canceled())),
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(mut rx) = self.rx.take() {
            self.shared.abandon(self.id, self.close_handle, &mut rx);
        }
    }
}

/// `ConnectionLost` for an I/O error of the channel.
fn lost(e: &std::io::Error) -> Status {
    connection_lost().with_detail(e.to_string())
}

/// Reads one packet body, its length checked before the buffer is made.
async fn read_packet<R: AsyncRead + Unpin>(read: &mut R) -> Result<Vec<u8>, Status> {
    let mut len = [0; 4];
    read.read_exact(&mut len).await.map_err(|e| lost(&e))?;
    let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if len == 0 || len > MAX_PACKET {
        return Err(
            malformed(WireError("a packet length is out of range")).with_detail(format!("{len} bytes"))
        );
    }
    let mut body = vec![0; len];
    read.read_exact(&mut body).await.map_err(|e| lost(&e))?;
    Ok(body)
}

async fn read_loop<R: AsyncRead + Unpin>(mut read: R, shared: Arc<Shared>) {
    let stop = shared.stop.clone();
    let reason = tokio::select! {
        () = stop.canceled() => None,
        reason = async {
            loop {
                let body = match read_packet(&mut read).await {
                    Ok(body) => body,
                    Err(e) => return e,
                };
                if let Err(e) = shared.dispatch(&body) {
                    return e;
                }
            }
        } => Some(reason),
    };
    if let Some(reason) = reason {
        shared.end(reason);
    }
}

async fn write_loop<W, F>(
    mut write: W,
    mut queue: mpsc::UnboundedReceiver<Vec<u8>>,
    shared: Arc<Shared>,
    on_end: F,
) where
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    let stop = shared.stop.clone();
    let failed = tokio::select! {
        () = stop.canceled() => false,
        failed = async {
            while let Some(bytes) = queue.recv().await {
                if write.write_all(&bytes).await.is_err() || write.flush().await.is_err() {
                    return true;
                }
            }
            false
        } => failed,
    };
    if failed {
        shared.end(connection_lost());
    }
    on_end.await;
}

/// Runs `work` under `cancel` and `timeout`.
async fn bounded<T>(
    work: impl Future<Output = Result<T, Status>>,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<T, Status> {
    match tokio::time::timeout(timeout, cancel.guard(work)).await {
        Ok(result) => result,
        Err(_) => Err(timed_out(timeout.as_millis())),
    }
}

impl Client {
    /// Sends `INIT`, reads `VERSION`, then starts the reader and writer
    /// tasks on the current runtime. `on_end` runs when the client ends
    /// (it closes the channel); on a failure here it runs at once.
    ///
    /// # Errors
    /// Canceled, timed out, the channel failed, or `VERSION` was not
    /// readable or not version 3.
    pub async fn start<R, W, F>(
        mut read: R,
        mut write: W,
        on_end: F,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<(Self, ServerVersion), Status>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let handshake = async {
            let init = Packet::init(VERSION).finish(0).ok_or_else(|| Status::internal("INIT"))?;
            write.write_all(&init).await.map_err(|e| lost(&e))?;
            write.flush().await.map_err(|e| lost(&e))?;
            let body = read_packet(&mut read).await?;
            let version = decode_version(&body).map_err(malformed)?;
            if version.version == VERSION {
                Ok(version)
            } else {
                Err(Status::new(ErrorName::Unsupported, "The server does not speak SFTP version 3")
                    .with_detail(format!("version {}", version.version)))
            }
        };
        let version = match bounded(handshake, timeout, cancel).await {
            Ok(version) => version,
            Err(e) => {
                tokio::spawn(on_end);
                return Err(e);
            }
        };
        let (out, queue) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            out,
            table: Mutex::new(Table { next_id: 1, slots: HashMap::new(), abandoned: 0, ended: None }),
            stop: CancelToken::new(),
            timeout,
        });
        tokio::spawn(read_loop(read, Arc::clone(&shared)));
        tokio::spawn(write_loop(write, queue, Arc::clone(&shared), on_end));
        Ok((Self { shared }, version))
    }

    /// Ends the client: waiting requests and later ones fail with `reason`.
    pub fn end(&self, reason: Status) {
        self.shared.end(reason);
    }

    /// Whether the client ended.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.shared.table().ended.is_some()
    }

    /// Why the client ended (`ConnectionLost` while it has not).
    #[must_use]
    pub fn end_reason(&self) -> Status {
        self.shared.ended()
    }

    /// The request timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.shared.timeout
    }

    /// Queues a request; does not wait (no runtime needed).
    ///
    /// # Errors
    /// The client ended, or the request is too long.
    pub fn send(&self, packet: Packet) -> Result<Pending, Failure> {
        self.send_as(packet, false)
    }

    /// As [`send`](Self::send) for a request that opens a handle: if it
    /// is abandoned, the handle its reply brings is closed.
    fn send_as(&self, packet: Packet, close_handle: bool) -> Result<Pending, Failure> {
        let (tx, rx) = oneshot::channel();
        let id = self.shared.queue(packet, Slot::Waiting(tx))?;
        Ok(Pending { shared: Arc::clone(&self.shared), id, close_handle, rx: Some(rx) })
    }

    /// Sends a request and waits for its reply.
    ///
    /// # Errors
    /// As [`send`](Self::send) and [`Pending::wait`].
    pub async fn call(&self, packet: Packet, cancel: &CancelToken) -> Result<Reply, Failure> {
        self.send(packet)?.wait(cancel).await
    }

    /// Sends `CLOSE` for `handle` and does not wait for the reply.
    pub fn close_detached(&self, handle: &[u8]) {
        self.shared.close_detached(handle);
    }

    /// `STAT` (`follow`) or `LSTAT`.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn stat(&self, path: &[u8], follow: bool, cancel: &CancelToken) -> Result<Attrs, Failure> {
        let kind = if follow { FXP_STAT } else { FXP_LSTAT };
        attrs(self.call(Packet::request(kind).string(path), cancel).await?)
    }

    /// `FSTAT`.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn fstat(&self, handle: &[u8], cancel: &CancelToken) -> Result<Attrs, Failure> {
        attrs(self.call(Packet::request(FXP_FSTAT).string(handle), cancel).await?)
    }

    /// `OPEN` with `SSH_FXF_*` flags; `attrs` for a file it creates.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn open(
        &self,
        path: &[u8],
        flags: u32,
        attrs: &Attrs,
        cancel: &CancelToken,
    ) -> Result<Vec<u8>, Failure> {
        let packet = attrs.encode(Packet::request(FXP_OPEN).string(path).u32(flags));
        handle(self.send_as(packet, true)?.wait(cancel).await?)
    }

    /// `OPENDIR`.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn opendir(&self, path: &[u8], cancel: &CancelToken) -> Result<Vec<u8>, Failure> {
        handle(self.send_as(Packet::request(FXP_OPENDIR).string(path), true)?.wait(cancel).await?)
    }

    /// `READDIR`; `None` at the end of the folder.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn readdir(&self, handle: &[u8], cancel: &CancelToken) -> Result<Option<Vec<Name>>, Failure> {
        match self.call(Packet::request(FXP_READDIR).string(handle), cancel).await? {
            Reply::Name(names) => Ok(Some(names)),
            Reply::Status(s) if s.code == FX_EOF => Ok(None),
            other => Err(not_ok(other)),
        }
    }

    /// `CLOSE`.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn close(&self, handle: &[u8], cancel: &CancelToken) -> Result<(), Failure> {
        ok(self.call(Packet::request(FXP_CLOSE).string(handle), cancel).await?)
    }

    /// `READ` of `len` bytes at `offset`, not waited for.
    ///
    /// # Errors
    /// The client ended.
    pub fn read(&self, handle: &[u8], offset: u64, len: u32) -> Result<Pending, Failure> {
        self.send(Packet::request(FXP_READ).string(handle).u64(offset).u32(len))
    }

    /// `WRITE` of `data` at `offset`, not waited for.
    ///
    /// # Errors
    /// The client ended, or `data` does not fit in a packet.
    pub fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> Result<Pending, Failure> {
        self.send(Packet::request(FXP_WRITE).string(handle).u64(offset).string(data))
    }

    /// A request answered by `STATUS`: `REMOVE`, `RMDIR`, `MKDIR` (with
    /// its attributes), `RENAME`, `SETSTAT`, `SYMLINK`.
    ///
    /// # Errors
    /// The server's status or a local failure.
    pub async fn simple(&self, request: Simple<'_>, cancel: &CancelToken) -> Result<(), Failure> {
        let packet = match request {
            Simple::Remove(path) => Packet::request(FXP_REMOVE).string(path),
            Simple::Rmdir(path) => Packet::request(FXP_RMDIR).string(path),
            Simple::Mkdir(path, attrs) => attrs.encode(Packet::request(FXP_MKDIR).string(path)),
            Simple::Rename(from, to) => Packet::request(FXP_RENAME).string(from).string(to),
            Simple::Setstat(path, attrs) => attrs.encode(Packet::request(FXP_SETSTAT).string(path)),
            // OpenSSH's order (target, then the link), which every server
            // this backend meets uses (phase 3 design §10).
            Simple::Symlink { target, link } => Packet::request(FXP_SYMLINK).string(target).string(link),
        };
        ok(self.call(packet, cancel).await?)
    }

    /// `REALPATH` or `READLINK`: the one name of the reply.
    ///
    /// # Errors
    /// The server's status, a reply with another number of names, or a
    /// local failure.
    pub async fn path_of(&self, request: PathOf<'_>, cancel: &CancelToken) -> Result<Vec<u8>, Failure> {
        let packet = match request {
            PathOf::Realpath(path) => Packet::request(FXP_REALPATH).string(path),
            PathOf::Readlink(path) => Packet::request(FXP_READLINK).string(path),
        };
        match self.call(packet, cancel).await? {
            Reply::Name(mut names) if names.len() == 1 => {
                Ok(names.pop().map(|n| n.filename).unwrap_or_default())
            }
            other => Err(not_ok(other)),
        }
    }

    /// `EXTENDED` `name` with `fields` (each a `string`); the reply as is.
    ///
    /// # Errors
    /// A local failure (the server's status comes back as a reply).
    pub async fn extended(
        &self,
        name: &str,
        fields: Fields<'_>,
        cancel: &CancelToken,
    ) -> Result<Reply, Failure> {
        let mut packet = Packet::request(FXP_EXTENDED).string(name.as_bytes());
        for field in fields {
            packet = match *field {
                Field::Str(bytes) => packet.string(bytes),
                Field::U64(n) => packet.u64(n),
            };
        }
        self.call(packet, cancel).await
    }
}

/// The fields of an `EXTENDED` request.
pub type Fields<'a> = &'a [Field<'a>];

/// One field of an `EXTENDED` request.
#[derive(Debug, Clone, Copy)]
pub enum Field<'a> {
    /// A `string`.
    Str(&'a [u8]),
    /// A `uint64`.
    U64(u64),
}

/// Requests answered by `STATUS`.
#[derive(Debug, Clone, Copy)]
pub enum Simple<'a> {
    /// `REMOVE`.
    Remove(&'a [u8]),
    /// `RMDIR`.
    Rmdir(&'a [u8]),
    /// `MKDIR` with the attributes of the new folder.
    Mkdir(&'a [u8], Attrs),
    /// `RENAME` (fails on an existing target, XS-6).
    Rename(&'a [u8], &'a [u8]),
    /// `SETSTAT`.
    Setstat(&'a [u8], Attrs),
    /// `SYMLINK`.
    Symlink {
        /// What the link points to, verbatim.
        target: &'a [u8],
        /// The link to create.
        link: &'a [u8],
    },
}

/// Requests answered by one name.
#[derive(Debug, Clone, Copy)]
pub enum PathOf<'a> {
    /// `REALPATH`.
    Realpath(&'a [u8]),
    /// `READLINK`.
    Readlink(&'a [u8]),
}

/// The failure for a reply that is not the one wanted: the server's status,
/// or a protocol error.
#[must_use]
pub fn not_ok(reply: Reply) -> Failure {
    match reply {
        Reply::Status(s) if s.code != FX_OK => Failure::Server(s),
        _ => unexpected(),
    }
}

/// `STATUS` OK, else the failure.
///
/// # Errors
/// Another status or reply.
pub fn ok(reply: Reply) -> Result<(), Failure> {
    match reply {
        Reply::Status(s) if s.code == FX_OK => Ok(()),
        other => Err(not_ok(other)),
    }
}

fn attrs(reply: Reply) -> Result<Attrs, Failure> {
    match reply {
        Reply::Attrs(a) => Ok(a),
        other => Err(not_ok(other)),
    }
}

fn handle(reply: Reply) -> Result<Vec<u8>, Failure> {
    match reply {
        Reply::Handle(h) => Ok(h),
        other => Err(not_ok(other)),
    }
}

#[cfg(test)]
mod tests;
