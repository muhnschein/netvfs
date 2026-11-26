// SPDX-License-Identifier: LGPL-2.1-or-later
//! The kind of network the phone uses: [`classify`] Connman's services, [`connman`] client. Core reaches it through [`NetworkSource`].

pub mod classify;
pub mod connman;

use crate::core::LocalFuture;

/// The network, as the core asks for it.
pub trait NetworkSource {
    /// `GetNetwork`'s answer now: `wifi`, `ethernet`, `mobile`, `other`, `none` or `unknown`.
    fn kind(&self) -> LocalFuture<'_, String>;
}
