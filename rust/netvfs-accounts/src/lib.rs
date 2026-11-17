// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-accounts: the bridge's only access to the accounts database, installed setgid
//! `privileged`. One request per run; the answer goes to stdout in the format netvfs-bridge reads.
//! No Qt, GLib or libaccounts: SQLite plus a small session-bus client. Confined set-id or not,
//! so tests run confined too.

pub mod db;
pub mod dbus;
pub mod gvariant;
pub mod policy;
pub mod qvariant;
pub mod sandbox;
pub mod serve;
pub mod store;
pub mod wire;

#[allow(clippy::print_stderr)]
fn report(message: &str) {
    eprintln!("netvfs-accounts: {message}");
}

/// Confines, serves the request, writes the answer; returns the exit status.
#[must_use]
pub fn run() -> u8 {
    use std::io::Write;

    sandbox::close_inherited_descriptors();
    sandbox::reset_process_state();
    let set_id = sandbox::running_set_id();
    if set_id && sandbox::prepare_set_id_process().is_none() {
        report("the user has no home folder");
        return 1;
    }
    let env = db::Environment::from_process();
    // Set-id: session bus below the runtime folder, never abstract.
    let bus = dbus::session_bus(set_id, &sandbox::runtime_dir());
    let abstract_bus = matches!(bus, Some(dbus::Address::Abstract(_)));
    let _filesystem = sandbox::restrict_filesystem(&env.database_folders(), abstract_bus);
    let _syscalls = sandbox::restrict_syscalls();

    let arguments: Vec<String> =
        std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let served = serve::serve(&arguments, &env, &SystemOwner);
    if !sandbox::drop_set_id_group() {
        report("cannot drop the group");
        return 1;
    }
    if let Some(change) = &served.change {
        let announced = bus
            .ok_or_else(|| std::io::Error::other("no session bus"))
            .and_then(|b| dbus::announce(change, &b));
        if let Err(e) = announced {
            report(&format!("cannot announce the change: {e}"));
        }
    }
    let mut stdout = std::io::stdout().lock();
    u8::from(stdout.write_all(&served.answer).and_then(|()| stdout.flush()).is_err())
}

/// The user `privileged` from passwd.
#[derive(Debug)]
pub struct SystemOwner;

impl db::PrivilegedOwner for SystemOwner {
    fn privileged_ids(&self) -> Option<(u32, u32)> {
        sandbox::privileged_ids()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_owner_is_the_user_privileged() {
        assert_eq!(db::PrivilegedOwner::privileged_ids(&SystemOwner), sandbox::privileged_ids());
    }
}
