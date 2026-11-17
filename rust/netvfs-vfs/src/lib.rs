// SPDX-License-Identifier: LGPL-2.1-or-later
//! Rust side of netvfs's backend interface (`src/core/backend.h`, `types.h`, `error.h`): the values
//! a backend works with, the async [`Backend`], [`ReadHandle`] and [`WriteHandle`] traits the Rust
//! protocol crates implement, the callbacks a call hands to them, [`CancelToken`], [`Status`]. No
//! I/O.
//! [`abi`] holds the C data types of `netvfs_bridge_ffi.h`, shared by both C ABIs (netvfs-bridge's
//! and netvfs-backend's).
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
