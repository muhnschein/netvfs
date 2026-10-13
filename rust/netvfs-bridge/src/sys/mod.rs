// SPDX-License-Identifier: LGPL-2.1-or-later
//! The libc calls of the bridge, each wrapped in a safe function. The only
//! module with `unsafe` (besides `ffi`); every block says why it is sound.
#![allow(unsafe_code)]

pub mod inotify;
pub mod lock;
