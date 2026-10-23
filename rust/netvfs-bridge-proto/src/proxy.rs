// SPDX-License-Identifier: LGPL-2.1-or-later
//! zbus proxy for `org.netvfs.Bridge1` at `/org/netvfs/Bridge` (XB-8..XB-10).
//! The interface text is `org.netvfs.Bridge1.xml` ([`crate::methods::INTROSPECTION_XML`]).

use crate::wire::{Opts, WireCapabilities, WireEntry, WireLocation};
use zbus::zvariant::Fd;

#[zbus::proxy(
    interface = "org.netvfs.Bridge1",
    default_path = "/org/netvfs/Bridge",
    // A peer-to-peer connection has no bus to route by name; zbus still wants a
    // destination and the bridge ignores it.
    default_service = "org.netvfs.Bridge",
    gen_blocking = false
)]
/// Client calls of `org.netvfs.Bridge1`. Signals come from
/// [`crate::Connection::signals`], in order.
pub trait Bridge1 {
    // Session
    /// `Hello(client)` → bridge version. The first call.
    fn hello(&self, client: &str) -> zbus::Result<String>;
    /// `GetConsent` → `granted`, `denied` or `unknown`.
    fn get_consent(&self) -> zbus::Result<String>;
    /// `RequestConsent`: asks the user again.
    fn request_consent(&self) -> zbus::Result<()>;
    /// `GetFeatures` → what the bridge offers besides the methods of netvfs
    /// 0.4 (`UnknownMethod` from an older bridge: nothing).
    fn get_features(&self) -> zbus::Result<Vec<String>>;

    // Locations
    /// `ListLocations`: the locations in scope (none without consent).
    fn list_locations(&self) -> zbus::Result<Vec<WireLocation>>;
    /// `Capabilities(loc)`.
    fn capabilities(&self, loc: &str) -> zbus::Result<WireCapabilities>;
    /// `Disconnect(loc)`: closes the pooled connections of a location.
    fn disconnect(&self, loc: &str) -> zbus::Result<()>;

    // Ad-hoc locations
    /// `ConnectAdHoc(url, secret, opts)` → location id. See also
    /// [`crate::Connection::connect_ad_hoc_wiping`].
    fn connect_ad_hoc(&self, url: &str, secret: &[u8], opts: &Opts) -> zbus::Result<String>;
    /// `ForgetAdHoc(loc)`.
    fn forget_ad_hoc(&self, loc: &str) -> zbus::Result<()>;

    // Discovery
    /// `Discover(on)`: starts or stops `NearbyChanged`.
    fn discover(&self, on: bool) -> zbus::Result<()>;

    // Listing
    /// `List(loc, dir, lane, batch)` → request id; entries follow as
    /// `ListBatch`, then `ListDone`.
    fn list(&self, loc: &str, dir: &[u8], lane: &str, batch: u32) -> zbus::Result<u32>;

    // Metadata
    /// `Stat(loc, path, follow, lane)`.
    fn stat(&self, loc: &str, path: &[u8], follow: bool, lane: &str) -> zbus::Result<WireEntry>;
    /// `ReadLink(loc, path)` → target.
    fn read_link(&self, loc: &str, path: &[u8]) -> zbus::Result<Vec<u8>>;
    /// `SpaceInfo(loc, path)` → (free, total, used).
    fn space_info(&self, loc: &str, path: &[u8]) -> zbus::Result<(i64, i64, i64)>;
    /// `Checksum(loc, path, algo)` → digest.
    fn checksum(&self, loc: &str, path: &[u8], algo: &str) -> zbus::Result<Vec<u8>>;

    // Namespace
    /// `MakeDir(loc, path, exclusive)`.
    fn make_dir(&self, loc: &str, path: &[u8], exclusive: bool) -> zbus::Result<()>;
    /// `RemoveFile(loc, path)`.
    fn remove_file(&self, loc: &str, path: &[u8]) -> zbus::Result<()>;
    /// `RemoveDir(loc, path)`: an empty folder.
    fn remove_dir(&self, loc: &str, path: &[u8]) -> zbus::Result<()>;
    /// `Rename(loc, from, to, replace)`.
    fn rename(&self, loc: &str, from: &[u8], to: &[u8], replace: bool) -> zbus::Result<()>;
    /// `SetAttributes(loc, path, changes)`: `mode`, `mtimeMs`, `atimeMs`.
    fn set_attributes(&self, loc: &str, path: &[u8], changes: &Opts) -> zbus::Result<()>;
    /// `MakeSymlink(loc, target, linkPath)`.
    fn make_symlink(&self, loc: &str, target: &[u8], link_path: &[u8]) -> zbus::Result<()>;
    /// `MakeHardlink(loc, existing, newPath)`.
    fn make_hardlink(&self, loc: &str, existing: &[u8], new_path: &[u8]) -> zbus::Result<()>;
    /// `ServerCopy(loc, from, to, opts)`: a copy on the server.
    fn server_copy(&self, loc: &str, from: &[u8], to: &[u8], opts: &Opts) -> zbus::Result<()>;

    // Handles
    /// `OpenRead(loc, path, lane)` → (handle, size).
    fn open_read(&self, loc: &str, path: &[u8], lane: &str) -> zbus::Result<(u32, i64)>;
    /// `Read(handle, offset, max)` → data; empty at the end.
    fn read(&self, handle: u32, offset: i64, max: u32) -> zbus::Result<Vec<u8>>;
    /// `ReadAhead(handle, offset, bytes)`: a hint.
    fn read_ahead(&self, handle: u32, offset: i64, bytes: i64) -> zbus::Result<()>;
    /// `Close(handle)`.
    fn close(&self, handle: u32) -> zbus::Result<()>;

    // Jobs
    /// `Upload(loc, path, fd, opts)` → job id.
    fn upload(&self, loc: &str, path: &[u8], fd: Fd<'_>, opts: &Opts) -> zbus::Result<u32>;
    /// `Download(loc, path, fd, opts)` → job id.
    fn download(&self, loc: &str, path: &[u8], fd: Fd<'_>, opts: &Opts) -> zbus::Result<u32>;
    /// `CopyAcross(srcLoc, src, dstLoc, dst, opts)` → job id.
    fn copy_across(
        &self,
        src_loc: &str,
        src: &[u8],
        dst_loc: &str,
        dst: &[u8],
        opts: &Opts,
    ) -> zbus::Result<u32>;
    /// `RemoveTree(loc, path)` → job id.
    fn remove_tree(&self, loc: &str, path: &[u8]) -> zbus::Result<u32>;
    /// `Walk(loc, root, opts)` → job id; entries follow as `WalkBatch`.
    fn walk(&self, loc: &str, root: &[u8], opts: &Opts) -> zbus::Result<u32>;
    /// `Cancel(id)`: a request or a job.
    fn cancel(&self, id: u32) -> zbus::Result<()>;

    // Questions
    /// `Answer(id, answer)`: `accept` and keyboard-interactive `answers`. See
    /// also [`crate::Connection::answer_wiping`].
    fn answer(&self, id: &str, answer: &Opts) -> zbus::Result<()>;

    // Handoff
    /// `OpenAccountSettings(loc)`: hands off to the account settings.
    fn open_account_settings(&self, loc: &str) -> zbus::Result<()>;
    /// `AddAccount(provider)`: hands off to the account creation.
    fn add_account(&self, provider: &str) -> zbus::Result<()>;
    /// `OpenStorageSettings()`: hands off to Settings › Storage.
    fn open_storage_settings(&self) -> zbus::Result<()>;
}
