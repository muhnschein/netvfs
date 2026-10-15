// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Rust side of netvfs's backend interface (`src/core/backend.h`,
//! `types.h`, `error.h`; design §3): the values a backend works with, the
//! async [`Backend`], [`ReadHandle`] and [`WriteHandle`] traits that the
//! Rust protocol crates implement, the callbacks a call hands to them,
//! [`CancelToken`] (C-9) and [`Status`] (XC-21, XC-24). No I/O.
//!
//! [`abi`] holds the C data types of `netvfs_bridge_ffi.h`, written once
//! for both C ABIs that carry them (netvfs-bridge's and netvfs-backend's).
#![forbid(unsafe_code)]

pub mod abi;
mod backend;
mod cancel;
pub mod status;
mod types;

pub use backend::{Backend, ListSink, NoHandle, Progress, Prompter, ReadHandle, Sink, Source, WriteHandle};
pub use cancel::CancelToken;
pub use status::{ErrorName, Status};
pub use types::{
    Attributes, Capabilities, Capability, Credentials, Disposition, Entry, EntryFlags, EntryType,
    ListOptions, Params, Prompt, PromptRequest, RenameMode, ServerIdentity, SpaceInfo, Value, ValueMap,
    WriteOptions,
};
pub use zeroize::Zeroizing;
