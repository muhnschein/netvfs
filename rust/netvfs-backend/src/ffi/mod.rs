// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C ABI of `src/backends/rs/netvfs_rs.h` (design §1, §2): [`nvr_get`]
//! is the library's one export and hands out [`TABLE`].
//!
//! Every table function catches panics and reports `Internal` (or does
//! nothing, for those without a result), except `free` and `nvr_get`, which
//! do nothing that can panic. A connection takes one call at a time; the
//! callbacks of a call run on the caller's thread (S3).
//!
//! This module is the crate's only one with `unsafe`; every block says why
//! it holds.
#![allow(unsafe_code)]

mod alloc;
mod callback;
mod conn;
mod marshal;
pub mod raw;

pub use alloc::live_blocks;
pub use conn::live_objects;

use raw::NvrTable;

/// The table, in the header's order.
pub static TABLE: NvrTable = NvrTable {
    free: alloc::free,
    reply_set: callback::reply_set,
    conn_new: conn::conn_new,
    conn_free: conn::conn_free,
    cancel: conn::cancel,
    reset_cancel: conn::reset_cancel,
    connect: conn::connect,
    authenticate: conn::authenticate,
    capabilities: conn::capabilities,
    disconnect: conn::disconnect,
    keep_alive: conn::keep_alive,
    stat: conn::stat,
    list: conn::list,
    make_dir: conn::make_dir,
    remove_file: conn::remove_file,
    remove_dir: conn::remove_dir,
    rename: conn::rename,
    set_attributes: conn::set_attributes,
    read_link: conn::read_link,
    make_symlink: conn::make_symlink,
    make_hardlink: conn::make_hardlink,
    copy: conn::copy,
    checksum: conn::checksum,
    space_info: conn::space_info,
    open_read: conn::open_read,
    read: conn::read,
    read_ahead: conn::read_ahead,
    read_close: conn::read_close,
    open_write: conn::open_write,
    write: conn::write,
    position: conn::position,
    commit: conn::commit,
    abort: conn::abort,
    upload: conn::upload,
    download: conn::download,
    key_generate: conn::key_generate,
    key_import: conn::key_import,
    key_describe: conn::key_describe,
};

/// `nvr_get`: the table. The shim and the library come from one commit,
/// so there is no version to check.
#[unsafe(no_mangle)]
pub extern "C" fn nvr_get() -> *const NvrTable {
    &raw const TABLE
}
