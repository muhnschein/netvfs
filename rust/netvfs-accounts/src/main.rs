// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-accounts: see the library.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(netvfs_accounts::run())
}
