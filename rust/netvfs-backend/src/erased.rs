// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Backend`], [`ReadHandle`] and [`WriteHandle`] behind `dyn`: the C ABI
//! picks the backend by provider name at run time. The traits' futures are
//! boxed here and nowhere else; each method forwards to the backend's own.
//! The backend's method is called only when its future is first polled,
//! so a backend that does its work before it returns a future (`ready`)
//! still does nothing for a call refused at once (a tripped cancel).
//!
//! The objects are `Send`, not `Sync`: a connection is used by one thread
//! at a time, not always by the thread that made it (C-8; the QML code
//! makes backends on the GUI thread and runs them on a pool thread).

use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capabilities, Credentials, Entry, ListOptions, ListSink, Params,
    Progress, Prompter, ReadHandle, RenameMode, ServerIdentity, Sink, Source, SpaceInfo, Status, WriteHandle,
    WriteOptions,
};
use std::future::Future;
use std::pin::Pin;

/// A boxed future of one call.
pub type Call<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// [`Backend`] as an object.
#[allow(missing_docs, reason = "each method is the Backend method of the same name")]
pub trait DynBackend: Send {
    fn connect<'a>(
        &'a mut self,
        params: &'a Params,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Option<ServerIdentity>, Status>>;
    fn authenticate<'a>(
        &'a mut self,
        credentials: &'a Credentials,
        prompter: Option<&'a mut dyn Prompter>,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn capabilities(&self) -> Capabilities;
    fn disconnect(&mut self) -> Call<'_, ()>;
    fn keep_alive<'a>(&'a mut self, cancel: &'a CancelToken) -> Call<'a, Result<(), Status>>;
    fn stat<'a>(
        &'a mut self,
        path: &'a [u8],
        follow: bool,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Entry, Status>>;
    fn list<'a>(
        &'a mut self,
        dir: &'a [u8],
        options: ListOptions,
        sink: &'a mut dyn ListSink,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn make_dir<'a>(
        &'a mut self,
        path: &'a [u8],
        exclusive: bool,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn remove_file<'a>(&'a mut self, path: &'a [u8], cancel: &'a CancelToken)
    -> Call<'a, Result<(), Status>>;
    fn remove_dir<'a>(&'a mut self, path: &'a [u8], cancel: &'a CancelToken) -> Call<'a, Result<(), Status>>;
    fn rename<'a>(
        &'a mut self,
        from: &'a [u8],
        to: &'a [u8],
        mode: RenameMode,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn set_attributes<'a>(
        &'a mut self,
        path: &'a [u8],
        changes: &'a Attributes,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn read_link<'a>(
        &'a mut self,
        path: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Vec<u8>, Status>>;
    fn make_symlink<'a>(
        &'a mut self,
        target: &'a [u8],
        link: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn make_hardlink<'a>(
        &'a mut self,
        existing: &'a [u8],
        link: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn copy<'a>(
        &'a mut self,
        from: &'a [u8],
        to: &'a [u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn checksum<'a>(
        &'a mut self,
        path: &'a [u8],
        algorithm: &'a str,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Vec<u8>, Status>>;
    fn space_info<'a>(
        &'a mut self,
        dir: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<SpaceInfo, Status>>;
    fn open_read<'a>(
        &'a mut self,
        path: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Box<dyn DynRead>, Status>>;
    fn open_write<'a>(
        &'a mut self,
        path: &'a [u8],
        options: &'a WriteOptions,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Box<dyn DynWrite>, Status>>;
    fn upload<'a>(
        &'a mut self,
        path: &'a [u8],
        options: &'a WriteOptions,
        source: &'a mut dyn Source,
        progress: &'a mut dyn Progress,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
    fn download<'a>(
        &'a mut self,
        path: &'a [u8],
        offset: u64,
        length: Option<u64>,
        sink: &'a mut dyn Sink,
        progress: &'a mut dyn Progress,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>>;
}

/// [`ReadHandle`] as an object.
#[allow(missing_docs, reason = "each method is the ReadHandle method of the same name")]
pub trait DynRead: Send {
    fn size(&self) -> Option<u64>;
    fn read<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a mut [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<usize, Status>>;
    fn read_ahead(&mut self, offset: u64, bytes: u64);
    fn close(self: Box<Self>, cancel: &CancelToken) -> Call<'_, Result<(), Status>>;
}

/// [`WriteHandle`] as an object.
#[allow(missing_docs, reason = "each method is the WriteHandle method of the same name")]
pub trait DynWrite: Send {
    fn write<'a>(&'a mut self, data: &'a [u8], cancel: &'a CancelToken) -> Call<'a, Result<(), Status>>;
    fn position(&self) -> u64;
    fn commit(self: Box<Self>, cancel: &CancelToken) -> Call<'_, Result<(), Status>>;
    fn abort(self: Box<Self>) -> Call<'static, ()>;
}

impl<R: ReadHandle + Send + 'static> DynRead for R {
    fn size(&self) -> Option<u64> {
        ReadHandle::size(self)
    }

    fn read<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a mut [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<usize, Status>> {
        Box::pin(async move { ReadHandle::read(self, offset, buf, cancel).await })
    }

    fn read_ahead(&mut self, offset: u64, bytes: u64) {
        ReadHandle::read_ahead(self, offset, bytes);
    }

    fn close(self: Box<Self>, cancel: &CancelToken) -> Call<'_, Result<(), Status>> {
        Box::pin(async move { ReadHandle::close(*self, cancel).await })
    }
}

impl<W: WriteHandle + Send + 'static> DynWrite for W {
    fn write<'a>(&'a mut self, data: &'a [u8], cancel: &'a CancelToken) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { WriteHandle::write(self, data, cancel).await })
    }

    fn position(&self) -> u64 {
        WriteHandle::position(self)
    }

    fn commit(self: Box<Self>, cancel: &CancelToken) -> Call<'_, Result<(), Status>> {
        Box::pin(async move { WriteHandle::commit(*self, cancel).await })
    }

    fn abort(self: Box<Self>) -> Call<'static, ()> {
        Box::pin(async move { WriteHandle::abort(*self).await })
    }
}

impl<B> DynBackend for B
where
    B: Backend + Send,
    B::Read: Send + 'static,
    B::Write: Send + 'static,
{
    fn connect<'a>(
        &'a mut self,
        params: &'a Params,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Option<ServerIdentity>, Status>> {
        Box::pin(async move { Backend::connect(self, params, cancel).await })
    }

    fn authenticate<'a>(
        &'a mut self,
        credentials: &'a Credentials,
        prompter: Option<&'a mut dyn Prompter>,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::authenticate(self, credentials, prompter, cancel).await })
    }

    fn capabilities(&self) -> Capabilities {
        Backend::capabilities(self)
    }

    fn disconnect(&mut self) -> Call<'_, ()> {
        Box::pin(async move { Backend::disconnect(self).await })
    }

    fn keep_alive<'a>(&'a mut self, cancel: &'a CancelToken) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::keep_alive(self, cancel).await })
    }

    fn stat<'a>(
        &'a mut self,
        path: &'a [u8],
        follow: bool,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Entry, Status>> {
        Box::pin(async move { Backend::stat(self, path, follow, cancel).await })
    }

    fn list<'a>(
        &'a mut self,
        dir: &'a [u8],
        options: ListOptions,
        sink: &'a mut dyn ListSink,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::list(self, dir, options, sink, cancel).await })
    }

    fn make_dir<'a>(
        &'a mut self,
        path: &'a [u8],
        exclusive: bool,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::make_dir(self, path, exclusive, cancel).await })
    }

    fn remove_file<'a>(
        &'a mut self,
        path: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::remove_file(self, path, cancel).await })
    }

    fn remove_dir<'a>(&'a mut self, path: &'a [u8], cancel: &'a CancelToken) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::remove_dir(self, path, cancel).await })
    }

    fn rename<'a>(
        &'a mut self,
        from: &'a [u8],
        to: &'a [u8],
        mode: RenameMode,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::rename(self, from, to, mode, cancel).await })
    }

    fn set_attributes<'a>(
        &'a mut self,
        path: &'a [u8],
        changes: &'a Attributes,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::set_attributes(self, path, changes, cancel).await })
    }

    fn read_link<'a>(
        &'a mut self,
        path: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Vec<u8>, Status>> {
        Box::pin(async move { Backend::read_link(self, path, cancel).await })
    }

    fn make_symlink<'a>(
        &'a mut self,
        target: &'a [u8],
        link: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::make_symlink(self, target, link, cancel).await })
    }

    fn make_hardlink<'a>(
        &'a mut self,
        existing: &'a [u8],
        link: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::make_hardlink(self, existing, link, cancel).await })
    }

    fn copy<'a>(
        &'a mut self,
        from: &'a [u8],
        to: &'a [u8],
        recursive: bool,
        mode: RenameMode,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::copy(self, from, to, recursive, mode, cancel).await })
    }

    fn checksum<'a>(
        &'a mut self,
        path: &'a [u8],
        algorithm: &'a str,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Vec<u8>, Status>> {
        Box::pin(async move { Backend::checksum(self, path, algorithm, cancel).await })
    }

    fn space_info<'a>(
        &'a mut self,
        dir: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<SpaceInfo, Status>> {
        Box::pin(async move { Backend::space_info(self, dir, cancel).await })
    }

    fn open_read<'a>(
        &'a mut self,
        path: &'a [u8],
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Box<dyn DynRead>, Status>> {
        Box::pin(async move {
            let handle: Box<dyn DynRead> = Box::new(Backend::open_read(self, path, cancel).await?);
            Ok(handle)
        })
    }

    fn open_write<'a>(
        &'a mut self,
        path: &'a [u8],
        options: &'a WriteOptions,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<Box<dyn DynWrite>, Status>> {
        Box::pin(async move {
            let handle: Box<dyn DynWrite> = Box::new(Backend::open_write(self, path, options, cancel).await?);
            Ok(handle)
        })
    }

    fn upload<'a>(
        &'a mut self,
        path: &'a [u8],
        options: &'a WriteOptions,
        source: &'a mut dyn Source,
        progress: &'a mut dyn Progress,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::upload(self, path, options, source, progress, cancel).await })
    }

    fn download<'a>(
        &'a mut self,
        path: &'a [u8],
        offset: u64,
        length: Option<u64>,
        sink: &'a mut dyn Sink,
        progress: &'a mut dyn Progress,
        cancel: &'a CancelToken,
    ) -> Call<'a, Result<(), Status>> {
        Box::pin(async move { Backend::download(self, path, offset, length, sink, progress, cancel).await })
    }
}
