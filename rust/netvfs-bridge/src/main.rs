// SPDX-License-Identifier: LGPL-2.1-or-later
//! `/usr/libexec/netvfs/netvfs-bridge [--listen ADDRESS] <consumer-id>`
//! (SPEC-v2 XB-2).
//!
//! Started by systemd user socket activation (`netvfs-bridge@<id>.socket`,
//! `Accept=no`): the listening socket is fd 3 (the `systemd:` address), so
//! the rendezvous stays exactly the socket systemd created in the
//! consumer's folder (XB-4). `--listen unix:path=…` replaces it for
//! development and tests.
//!
//! Threads (design §3.1): the main thread loads the C ABI, creates the Qt
//! application and runs its event loop (T1); the bridge itself runs on
//! `nvb-rt`, a current-thread tokio runtime, and ends the Qt loop when it
//! is done (idle exit, XB-2). Exit codes: 0 after the idle exit, 1 on a
//! failure, 2 for a usage error.

use netvfs_bridge::config::{Env, load_consumer};
use netvfs_bridge::ffi::Ffi;
use netvfs_bridge::log::{self, Logger};
use netvfs_bridge::server::ListenAddress;
use netvfs_bridge::{Config, Deps};
use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

/// The name of the runtime thread.
const RUNTIME_THREAD: &str = "nvb-rt";
/// Where systemd hands over the listening socket.
const DEFAULT_LISTEN: &str = "systemd:";
/// The application name of the Qt application.
const APP_NAME: &str = "netvfs-bridge";

/// The command line: where to listen and the consumer.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    listen: String,
    consumer: String,
}

/// `[--listen ADDRESS] <consumer-id>`; `None` for anything else.
fn parse_args(args: Vec<OsString>) -> Option<Args> {
    let args: Vec<String> = args.into_iter().map(OsString::into_string).collect::<Result<_, _>>().ok()?;
    match args.as_slice() {
        [consumer] => Some(Args { listen: DEFAULT_LISTEN.to_owned(), consumer: consumer.clone() }),
        [flag, listen, consumer] if flag == "--listen" => {
            Some(Args { listen: listen.clone(), consumer: consumer.clone() })
        }
        _ => None,
    }
}

fn usage() -> ExitCode {
    // Nothing else to do when stderr is gone.
    drop(writeln!(std::io::stderr(), "usage: netvfs-bridge [--listen DBUS-ADDRESS] <consumer-id>"));
    ExitCode::from(2)
}

fn fail(message: std::fmt::Arguments<'_>) -> ExitCode {
    log::critical(message);
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let Some(args) = parse_args(std::env::args_os().skip(1).collect()) else { return usage() };
    let env = Env::from_process();
    log::init(Logger::new(Some(&args.consumer), env.logging_rules().as_deref()));
    let consumer = match load_consumer(&env, &args.consumer) {
        Ok(consumer) => consumer,
        Err(status) => return fail(format_args!("{}", status.message)),
    };
    let listen = match ListenAddress::parse(&args.listen) {
        Ok(listen) => listen,
        Err(status) => return fail(format_args!("{}", status.message)),
    };
    let ffi = match Ffi::load() {
        Ok(ffi) => ffi,
        Err(e) => return fail(format_args!("Cannot load the backends: {e}")),
    };
    if let Err(status) = ffi.init(APP_NAME) {
        return fail(format_args!("Cannot start the backends: {}", status.message));
    }
    let config = Config::new(&env, consumer);
    let deps = Deps::system(ffi, listen, &env);
    let bridge = std::thread::Builder::new().name(RUNTIME_THREAD.to_owned()).spawn(move || {
        let code = netvfs_bridge::serve(config, deps);
        ffi.quit(0); // queued: also ends a loop that has not started yet
        code
    });
    let code = match bridge {
        Ok(bridge) => {
            if let Err(status) = ffi.run() {
                log::critical(format_args!("The Qt loop failed: {}", status.message));
            }
            bridge.join().unwrap_or(ExitCode::FAILURE)
        }
        Err(e) => fail(format_args!("Cannot start the runtime thread: {e}")),
    };
    if let Err(status) = ffi.shutdown() {
        log::warning(format_args!("Cannot shut the backends down: {}", status.message));
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Option<Args> {
        parse_args(args.iter().map(OsString::from).collect())
    }

    #[test]
    fn command_line() {
        assert_eq!(parse(&["app"]), Some(Args { listen: "systemd:".to_owned(), consumer: "app".to_owned() }));
        assert_eq!(
            parse(&["--listen", "unix:path=/x", "app"]),
            Some(Args { listen: "unix:path=/x".to_owned(), consumer: "app".to_owned() })
        );
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["a", "b"]), None);
        assert_eq!(parse(&["--other", "x", "app"]), None);
        assert_eq!(parse(&["--listen", "x"]), None);
        assert_eq!(parse(&["--listen", "x", "app", "more"]), None);
        assert_eq!(usage(), ExitCode::from(2));
        assert_eq!(fail(format_args!("x")), ExitCode::FAILURE);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            assert_eq!(parse_args(vec![OsString::from_vec(vec![0xff])]), None);
        }
    }
}
