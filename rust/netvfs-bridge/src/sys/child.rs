// SPDX-License-Identifier: LGPL-2.1-or-later
//! Test support (feature `testing`): between `fork` and `exec` of started processes. A child dies with the thread that started it (`PR_SET_PDEATHSIG`); a bridge started like systemd finds its socket at fd 3.

use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// SIGKILLs the child of `command` when the spawning thread ends, so no child outlives its test. Spawn from the test's own thread, not a pool thread.
pub fn kill_with_parent(command: &mut Command) -> &mut Command {
    let parent = std::process::id();
    let pre_exec = move || {
        // SAFETY: prctl is async-signal-safe, no pointers; runs in the child between fork and exec.
        super::check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) })?;
        // SAFETY: getppid takes nothing and cannot fail.
        let ppid = unsafe { libc::getppid() };
        // Parent died before the call above: nobody would kill us.
        if u32::try_from(ppid).ok() != Some(parent) {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
        Ok(())
    };
    // SAFETY: closure calls only async-signal-safe functions and does not allocate.
    unsafe { command.pre_exec(pre_exec) }
}

/// Places `listener` at fd 3 ([`super::listen::LISTEN_FDS_START`]) of the child, without close-on-exec, as systemd does. `LISTEN_PID` and `LISTEN_FDS` are the caller's business.
pub fn place_listener(command: &mut Command, listener: OwnedFd) -> &mut Command {
    let target = super::listen::LISTEN_FDS_START;
    let pre_exec = move || move_to(listener.as_raw_fd(), target);
    // SAFETY: `move_to` calls only dup2 and fcntl (async-signal-safe); closure owns the open descriptor.
    unsafe { command.pre_exec(pre_exec) }
}

/// `dup2(fd, target)`; if `fd == target`, clears close-on-exec (dup2 leaves it set).
fn move_to(fd: RawFd, target: RawFd) -> io::Result<()> {
    if fd == target {
        // SAFETY: fcntl on an open descriptor; F_SETFD 0 clears FD_CLOEXEC.
        super::check(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) })?;
    } else {
        // SAFETY: dup2 on an open descriptor; the copy has no close-on-exec.
        super::check(unsafe { libc::dup2(fd, target) })?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    fn cloexec(fd: RawFd) -> bool {
        // SAFETY: test only; descriptor owned by the test.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags, -1);
        flags & libc::FD_CLOEXEC != 0
    }

    #[test]
    fn moves_a_descriptor_without_cloexec() {
        let (a, _b) = UnixStream::pair().unwrap();
        let (c, _d) = UnixStream::pair().unwrap();
        assert!(cloexec(a.as_raw_fd()));
        move_to(a.as_raw_fd(), c.as_raw_fd()).unwrap();
        assert!(!cloexec(c.as_raw_fd()));
        assert!(cloexec(a.as_raw_fd()));
        move_to(a.as_raw_fd(), a.as_raw_fd()).unwrap();
        assert!(!cloexec(a.as_raw_fd()));
        let closed = a.as_fd().try_clone_to_owned().unwrap();
        let raw = closed.as_raw_fd();
        drop(closed);
        assert!(move_to(raw, raw).is_err());
        assert!(move_to(raw, c.as_raw_fd()).is_err());
    }

    /// Waits up to 10 s for `child`, then kills it: whether it ended by itself, and how.
    fn ended(child: &mut Child) -> (bool, std::process::ExitStatus) {
        let end = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        while Instant::now() < end {
            if let Some(status) = child.try_wait().unwrap() {
                return (true, status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        (false, child.wait().unwrap())
    }

    #[test]
    fn a_child_dies_with_the_thread_that_started_it() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut child = std::thread::spawn(|| {
            kill_with_parent(Command::new("sleep").arg("60").stdin(Stdio::null())).spawn().unwrap()
        })
        .join()
        .unwrap();
        let (by_itself, status) = ended(&mut child);
        assert!(by_itself, "still running");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn the_listener_is_fd_3() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "echo here >&3"]).stdin(Stdio::null());
        place_listener(&mut command, OwnedFd::from(theirs));
        let mut child = kill_with_parent(&mut command).spawn().unwrap();
        drop(command);
        assert_eq!(ended(&mut child), (true, std::process::ExitStatus::default()));
        let mut got = String::new();
        io::Read::read_to_string(&mut &ours, &mut got).unwrap();
        assert_eq!(got, "here\n");
    }
}
