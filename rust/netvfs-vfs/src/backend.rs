// SPDX-License-Identifier: LGPL-2.1-or-later
//! Async counterparts of `NetVfs::Backend`, `ReadHandle` and `WriteHandle` (`src/core/backend.h`),
//! and the callbacks a call hands to a backend: [`ListSink`], [`Prompter`], [`Source`], [`Sink`],
//! [`Progress`].
//! The C ABI (netvfs-backend) runs every call on the caller's thread (`block_on`): callbacks are
//! plain synchronous calls made by the call's own future, never from a spawned task. Every call
//! takes the connection's [`CancelToken`]; it ends with `Canceled` soon after the token trips, and
//! leaves the connection usable or reports `ConnectionLost` later. Methods with a default return
//! `Unsupported` unless the matching capability is reported.

use crate::cancel::CancelToken;
use crate::status::Status;
use crate::types::{
    Attributes, Capabilities, Credentials, Entry, ListOptions, Params, PromptRequest, RenameMode,
    ServerIdentity, SpaceInfo, WriteOptions,
};
use std::future::{Future, Ready};
use zeroize::Zeroizing;

/// `NetVfs::ListSink`.
pub trait ListSink {
    /// One batch; `false` stops the listing, which then ends with
    /// `Canceled`.
    fn entries(&mut self, batch: &[Entry]) -> bool;
}

/// `NetVfs::AuthPrompter`.
pub trait Prompter {
    /// One answer per prompt, or `None` when the user declines (the call
    /// then fails with `AuthFailed`). May block until the user answers.
    fn answer(&mut self, request: &PromptRequest) -> Option<Vec<Zeroizing<Vec<u8>>>>;
}

/// `NetVfs::Progress` of a transfer.
pub trait Progress {
    /// Bytes moved so far, of `total` when known.
    fn update(&mut self, done: u64, total: Option<u64>);
    /// Whether the caller wants the transfer to stop (it then ends with
    /// `Canceled`).
    fn canceled(&mut self) -> bool;
}

/// The local side of an upload: reads in order.
pub trait Source {
    /// Fills the start of `buf`; `Ok(0)` at the end.
    ///
    /// # Errors
    /// A failure of the local side.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status>;
    /// The bytes from here to the end, when known.
    fn size(&self) -> Option<u64>;
}

/// The local side of a download: writes in order.
pub trait Sink {
    /// Writes all of `data`.
    ///
    /// # Errors
    /// A failure of the local side.
    fn write(&mut self, data: &[u8]) -> Result<(), Status>;
}

/// `NetVfs::ReadHandle`: random access to one remote file. After
/// the backend's disconnect every call is `ConnectionLost`.
pub trait ReadHandle {
    /// The size at open time.
    fn size(&self) -> Option<u64>;
    /// Fills the start of `buf` from `offset`; less than `buf.len()` only
    /// at the end of the file, 0 at or past it.
    fn read(
        &mut self,
        offset: u64,
        buf: &mut [u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<usize, Status>>;
    /// A hint; may do nothing.
    fn read_ahead(&mut self, offset: u64, bytes: u64);
    /// Closes the handle.
    fn close(self, cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;
}

/// `NetVfs::WriteHandle`: sequential writes with an explicit commit.
pub trait WriteHandle {
    /// Appends `data`.
    fn write(&mut self, data: &[u8], cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;
    /// The file offset the next write goes to.
    fn position(&self) -> u64;
    /// Flushes, closes and applies the modification time.
    fn commit(self, cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;
    /// Closes without commit; what was written may remain.
    fn abort(self) -> impl Future<Output = ()>;
}

/// The handle type of a backend without handles: no value of it exists.
#[derive(Debug)]
pub enum NoHandle {}

impl ReadHandle for NoHandle {
    fn size(&self) -> Option<u64> {
        match *self {}
    }

    fn read(&mut self, _: u64, _: &mut [u8], _: &CancelToken) -> impl Future<Output = Result<usize, Status>> {
        no_future(self)
    }

    fn read_ahead(&mut self, _: u64, _: u64) {
        match *self {}
    }

    fn close(self, _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
        no_future(&self)
    }
}

impl WriteHandle for NoHandle {
    fn write(&mut self, _: &[u8], _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
        no_future(self)
    }

    fn position(&self) -> u64 {
        match *self {}
    }

    fn commit(self, _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
        no_future(&self)
    }

    fn abort(self) -> impl Future<Output = ()> {
        no_future(&self)
    }
}

/// The future of a [`NoHandle`] method, which no one can call: there is no
/// `NoHandle` value.
fn no_future<T>(handle: &NoHandle) -> Ready<T> {
    match *handle {}
}

/// `Unsupported` for an optional method.
fn unsupported<T>(what: &str) -> Result<T, Status> {
    Err(Status::unsupported(format!("{what} is not supported")))
}

/// `NetVfs::Backend`: one connection. Paths are protocol bytes of normalised paths
/// (`Names::encode`).
pub trait Backend {
    /// What [`open_read`](Self::open_read) gives ([`NoHandle`] without
    /// read handles).
    type Read: ReadHandle;
    /// What [`open_write`](Self::open_write) gives ([`NoHandle`] without
    /// write handles).
    type Write: WriteHandle;

    /// Opens the transport and reports the server identity, if the protocol has one; sends no
    /// credentials.
    fn connect(
        &mut self,
        params: &Params,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Option<ServerIdentity>, Status>>;
    /// Signs in; without a prompter, interactive methods are not tried.
    fn authenticate(
        &mut self,
        credentials: &Credentials,
        prompter: Option<&mut dyn Prompter>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;
    /// Valid after `authenticate`; stable for the connection's life.
    fn capabilities(&self) -> Capabilities;
    /// Closes the connection; open handles fail with `ConnectionLost`.
    fn disconnect(&mut self) -> impl Future<Output = ()>;
    /// `ConnectionLost` when the connection is gone.
    fn keep_alive(&mut self, cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;

    /// The entry at `path`, following a final symlink when `follow` is set
    /// (`stat`) or not (`lstat`).
    fn stat(
        &mut self,
        path: &[u8],
        follow: bool,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Entry, Status>>;
    /// Batches of at most `options.batch_size` entries; `.` and `..` never appear.
    fn list(
        &mut self,
        dir: &[u8],
        options: ListOptions,
        sink: &mut dyn ListSink,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;
    /// With `exclusive` an existing entry is `AlreadyExists`, without it an existing folder is
    /// success.
    fn make_dir(
        &mut self,
        path: &[u8],
        exclusive: bool,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;
    /// A folder is `IsADirectory`.
    fn remove_file(&mut self, path: &[u8], cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;
    /// A non-empty folder is `DirectoryNotEmpty`.
    fn remove_dir(&mut self, path: &[u8], cancel: &CancelToken) -> impl Future<Output = Result<(), Status>>;
    /// `NoReplace` fails with `AlreadyExists` if `to` exists; replacing a folder is `AlreadyExists`
    /// in both modes.
    fn rename(
        &mut self,
        from: &[u8],
        to: &[u8],
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;

    /// Every field is checked first; an unsupported one changes nothing.
    fn set_attributes(
        &mut self,
        path: &[u8],
        changes: &Attributes,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>> {
        let _ = (path, changes, cancel);
        async { unsupported("setAttributes") }
    }
    /// The target verbatim.
    fn read_link(
        &mut self,
        path: &[u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Vec<u8>, Status>> {
        let _ = (path, cancel);
        async { unsupported("readLink") }
    }
    /// `target` verbatim (may be relative).
    fn make_symlink(
        &mut self,
        target: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>> {
        let _ = (target, link, cancel);
        async { unsupported("makeSymlink") }
    }
    /// Hard link `new_path` to `existing`.
    fn make_hardlink(
        &mut self,
        existing: &[u8],
        link: &[u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>> {
        let _ = (existing, link, cancel);
        async { unsupported("makeHardlink") }
    }
    /// A server-side copy (`ServerCopy`, `ServerCopyRecursive`).
    fn copy(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>> {
        let _ = (from, to, recursive, mode, cancel);
        async { unsupported("copy") }
    }
    /// The digest of one of `checksum_algorithms`; another algorithm is `Unsupported`.
    fn checksum(
        &mut self,
        path: &[u8],
        algorithm: &str,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Vec<u8>, Status>> {
        let _ = (path, algorithm, cancel);
        async { unsupported("checksum") }
    }
    /// Free, total and used bytes.
    fn space_info(
        &mut self,
        dir: &[u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<SpaceInfo, Status>> {
        let _ = (dir, cancel);
        async { unsupported("spaceInfo") }
    }

    /// Needs `ReadHandles`.
    fn open_read(
        &mut self,
        path: &[u8],
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Self::Read, Status>> {
        let _ = (path, cancel);
        async { unsupported("openRead") }
    }
    /// `Resume` needs `WriteResume`.
    fn open_write(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<Self::Write, Status>> {
        let _ = (path, options, cancel);
        async { unsupported("openWrite") }
    }
    /// Streams `source` to `path` in bounded memory.
    fn upload(
        &mut self,
        path: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;
    /// `length` bytes from `offset` (`None`: to the end) into `sink`.
    fn download(
        &mut self,
        path: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<(), Status>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::ErrorName;
    use std::future::ready;

    /// Only what a backend must have; every optional method is the trait's default.
    struct Minimal;

    impl Backend for Minimal {
        type Read = NoHandle;
        type Write = NoHandle;

        fn connect(
            &mut self,
            _: &Params,
            _: &CancelToken,
        ) -> impl Future<Output = Result<Option<ServerIdentity>, Status>> {
            ready(Ok(None))
        }
        fn authenticate(
            &mut self,
            _: &Credentials,
            _: Option<&mut dyn Prompter>,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }
        fn disconnect(&mut self) -> impl Future<Output = ()> {
            ready(())
        }
        fn keep_alive(&mut self, _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn stat(
            &mut self,
            _: &[u8],
            _: bool,
            _: &CancelToken,
        ) -> impl Future<Output = Result<Entry, Status>> {
            ready(Ok(Entry::default()))
        }
        fn list(
            &mut self,
            _: &[u8],
            _: ListOptions,
            _: &mut dyn ListSink,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn make_dir(
            &mut self,
            _: &[u8],
            _: bool,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn remove_file(&mut self, _: &[u8], _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn remove_dir(&mut self, _: &[u8], _: &CancelToken) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn rename(
            &mut self,
            _: &[u8],
            _: &[u8],
            _: RenameMode,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn upload(
            &mut self,
            _: &[u8],
            _: &WriteOptions,
            _: &mut dyn Source,
            _: &mut dyn Progress,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
        fn download(
            &mut self,
            _: &[u8],
            _: u64,
            _: Option<u64>,
            _: &mut dyn Sink,
            _: &mut dyn Progress,
            _: &CancelToken,
        ) -> impl Future<Output = Result<(), Status>> {
            ready(Ok(()))
        }
    }

    fn unsupported_named<T: std::fmt::Debug>(r: Result<T, Status>, what: &str) {
        let s = r.unwrap_err();
        assert_eq!(s.name, ErrorName::Unsupported);
        assert_eq!(s.message, format!("{what} is not supported"));
    }

    #[tokio::test]
    async fn optional_methods_default_to_unsupported() {
        let mut b = Minimal;
        let c = CancelToken::new();
        unsupported_named(b.set_attributes(b"f", &Attributes::default(), &c).await, "setAttributes");
        unsupported_named(b.read_link(b"f", &c).await, "readLink");
        unsupported_named(b.make_symlink(b"t", b"l", &c).await, "makeSymlink");
        unsupported_named(b.make_hardlink(b"e", b"l", &c).await, "makeHardlink");
        unsupported_named(b.copy(b"a", b"b", true, RenameMode::Replace, &c).await, "copy");
        unsupported_named(b.checksum(b"f", "sha256", &c).await, "checksum");
        unsupported_named(b.space_info(b"d", &c).await, "spaceInfo");
        unsupported_named(b.open_read(b"f", &c).await, "openRead");
        unsupported_named(b.open_write(b"f", &WriteOptions::default(), &c).await, "openWrite");
    }

    #[tokio::test]
    async fn required_methods_are_the_backends_own() {
        let mut b = Minimal;
        let c = CancelToken::new();
        assert_eq!(b.connect(&Params::default(), &c).await, Ok(None));
        assert_eq!(b.authenticate(&Credentials::default(), None, &c).await, Ok(()));
        assert_eq!(b.capabilities(), Capabilities::default());
        assert_eq!(b.keep_alive(&c).await, Ok(()));
        b.disconnect().await;
    }
}
