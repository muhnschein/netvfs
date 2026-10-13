// SPDX-License-Identifier: LGPL-2.1-or-later
//! Tests only (feature "probe"): applies one part of the confinement to this
//! fresh process and checks what it still allows, as the C++ tests did in a
//! forked child. The exit status is the number of the first check that
//! failed, 0 if none did; 77 when the kernel has no Landlock, 99 when it has
//! no seccomp. Usage: `netvfs-accounts-probe <part> [paths...]`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use netvfs_accounts::sandbox;

const NO_LANDLOCK: i32 = 77;
const NO_SECCOMP: i32 = 99;
/// fchmodat2 (Linux 6.6), the same number on every architecture.
const FCHMODAT2: libc::c_long = 452;

/// The number of the first check that failed, 0 if none did.
#[derive(Default)]
struct Checks {
    count: i32,
    failed: i32,
}

impl Checks {
    fn check(&mut self, ok: bool) {
        self.count = self.count.saturating_add(1);
        if !ok && self.failed == 0 {
            self.failed = self.count;
            report(&format!("check {} failed", self.count));
        }
    }
}

/// Writes a check's failure to stderr. The exit status carries the result;
/// the message only helps whoever runs the probe by hand.
#[allow(clippy::print_stderr)]
fn report(message: &str) {
    eprintln!("probe: {message}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fails_with(result: i64, error: i32) -> bool {
    result == -1 && errno() == error
}

fn c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap_or_default()
}

fn descriptors(check: &mut Checks, inherited: i32) {
    // SAFETY: querying a descriptor.
    check.check(unsafe { libc::fcntl(inherited, libc::F_GETFD) } != -1);
    sandbox::close_inherited_descriptors();
    // Closed by the caller, /dev/null by now (Rust's runtime).
    let null = std::fs::metadata("/dev/null").ok();
    for fd in [0, 2] {
        // SAFETY: an all-zero stat is a valid value to overwrite.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is writable.
        let ok = unsafe { libc::fstat(fd, &raw mut st) } == 0;
        check.check(
            ok && st.st_mode & libc::S_IFMT == libc::S_IFCHR
                && null.as_ref().is_some_and(|n| n.rdev() == st.st_rdev),
        );
    }
    // SAFETY: querying a descriptor.
    check.check(fails_with(i64::from(unsafe { libc::fcntl(inherited, libc::F_GETFD) }), libc::EBADF));
}

fn process_state(check: &mut Checks) {
    // SAFETY: plain process-state calls.
    unsafe {
        libc::umask(0);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut blocked);
        libc::sigaddset(&raw mut blocked, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &raw const blocked, std::ptr::null_mut());
        let mut size = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut size);
        size.rlim_cur = size.rlim_max.min(4096);
        libc::setrlimit(libc::RLIMIT_FSIZE, &raw const size);
    }
    sandbox::reset_process_state();
    // SAFETY: plain process-state queries.
    unsafe {
        check.check(libc::umask(0o022) == 0o077);
        let mut action: libc::sigaction = std::mem::zeroed();
        check.check(
            libc::sigaction(libc::SIGTERM, std::ptr::null(), &raw mut action) == 0
                && action.sa_sigaction == libc::SIG_DFL,
        );
        let mut now: libc::sigset_t = std::mem::zeroed();
        check.check(
            libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &raw mut now) == 0
                && libc::sigismember(&raw const now, libc::SIGUSR1) == 0,
        );
        let mut size = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        check
            .check(libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut size) == 0 && size.rlim_cur == size.rlim_max);
    }
}

fn syscalls(check: &mut Checks, dir: &Path) -> i32 {
    if !sandbox::restrict_syscalls() {
        return NO_SECCOMP;
    }
    let file = c(&dir.join("file"));
    let other = c(&dir.join("other"));
    let folder = c(&dir.join("folder"));
    // SAFETY: syscalls on valid, NUL-terminated paths and plain values.
    unsafe {
        let argv = [c"false".as_ptr(), std::ptr::null()];
        check.check(fails_with(i64::from(libc::execv(c"/bin/false".as_ptr(), argv.as_ptr())), libc::EPERM));
        check.check(fails_with(i64::from(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)), libc::EPERM));
        check.check(fails_with(i64::from(libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)), libc::EPERM));
        check.check(fails_with(i64::from(libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0)), libc::EPERM));
        check.check(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) >= 0);
        let mut pair = [0; 2];
        check.check(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) == 0);
        check.check(fails_with(i64::from(libc::unshare(libc::CLONE_NEWUSER)), libc::EPERM));
        check.check(fails_with(libc::syscall(libc::SYS_bpf, 0, 0, 0), libc::EPERM));
        // No file with a setuid or setgid bit, however it is made.
        let fd = libc::open(file.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600);
        check.check(fd >= 0);
        check.check(fails_with(i64::from(libc::fchmod(fd, 0o2755)), libc::EPERM));
        check.check(fails_with(i64::from(libc::chmod(file.as_ptr(), 0o4755)), libc::EPERM));
        check.check(fails_with(
            i64::from(libc::fchmodat(libc::AT_FDCWD, file.as_ptr(), 0o2700, 0)),
            libc::EPERM,
        ));
        check.check(libc::chmod(file.as_ptr(), 0o640) == 0);
        check.check(fails_with(
            i64::from(libc::open(other.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o2755)),
            libc::EPERM,
        ));
        // Without O_CREAT the mode is unused, whatever a raw syscall passes.
        check.check(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, file.as_ptr(), libc::O_RDONLY, 0o6755) >= 0,
        );
        check.check(fails_with(i64::from(libc::mkdir(folder.as_ptr(), 0o2755)), libc::EPERM));
        // The *at calls themselves (glibc uses the old ones where they exist).
        check.check(fails_with(
            libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, folder.as_ptr(), 0o2755),
            libc::EPERM,
        ));
        check.check(fails_with(
            libc::syscall(libc::SYS_mknodat, libc::AT_FDCWD, other.as_ptr(), libc::S_IFREG | 0o4644, 0),
            libc::EPERM,
        ));
        check.check(fails_with(
            libc::syscall(FCHMODAT2, libc::AT_FDCWD, file.as_ptr(), 0o2700, 0),
            libc::EPERM,
        ));
        check.check(fails_with(i64::from(libc::creat(other.as_ptr(), 0o2755)), libc::EPERM));
        check.check(libc::mkdir(folder.as_ptr(), 0o700) == 0);
        check.check(fails_with(
            i64::from(libc::open(folder.as_ptr(), libc::O_TMPFILE | libc::O_WRONLY, 0o2755)),
            libc::EPERM,
        ));
        check.check(fails_with(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0), libc::EPERM));
        // clone3 and openat2 fail with ENOSYS, so that glibc falls back.
        check.check(fails_with(libc::syscall(435, 0, 0), libc::ENOSYS));
        check.check(fails_with(libc::syscall(437, 0, 0, 0, 0), libc::ENOSYS));
    }
    // Threads still start.
    check.check(std::thread::spawn(|| true).join().unwrap_or(false));
    0
}

fn filesystem(check: &mut Checks, allowed: &Path, denied: &Path) -> i32 {
    let restriction =
        sandbox::restrict_filesystem(&[allowed.to_owned(), PathBuf::from("/nonexistent/accounts")], false);
    if restriction.abi == 0 {
        return NO_LANDLOCK;
    }
    check.check(restriction.enforced);
    let created = c(&allowed.join("accounts.db-wal"));
    let secret = c(&denied.join("secret"));
    let outside = c(&denied.join("planted"));
    // SAFETY: syscalls on valid, NUL-terminated paths and plain values.
    unsafe {
        // The database folder: create, write, truncate, remove.
        let fd = libc::open(created.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600);
        check.check(fd >= 0);
        check.check(libc::write(fd, b"x".as_ptr().cast(), 1) == 1);
        check.check(libc::ftruncate(fd, 0) == 0);
        check.check(libc::unlink(created.as_ptr()) == 0);
        // Anything else: read-only system folders, nothing beyond them.
        check.check(libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) >= 0);
        check.check(libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) >= 0);
        check.check(fails_with(i64::from(libc::open(secret.as_ptr(), libc::O_RDONLY)), libc::EACCES));
        check.check(fails_with(
            i64::from(libc::open(outside.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600)),
            libc::EACCES,
        ));
        let argv = [c"false".as_ptr(), std::ptr::null()];
        check.check(fails_with(i64::from(libc::execv(c"/bin/false".as_ptr(), argv.as_ptr())), libc::EACCES));
        if restriction.abi >= 4 {
            let tcp = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let local = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(2),
                sin_port: 1u16.to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be() },
                sin_zero: [0; 8],
            };
            let size = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(16);
            check.check(fails_with(
                i64::from(libc::connect(tcp, std::ptr::addr_of!(local).cast(), size)),
                libc::EACCES,
            ));
        }
        if restriction.abi >= 6 {
            check.check(fails_with(i64::from(libc::kill(libc::getppid(), 0)), libc::EPERM));
        }
    }
    0
}

fn set_id_environment(check: &mut Checks) {
    // SAFETY: the probe runs one check per process and has one thread.
    unsafe {
        std::env::set_var("HOME", "/tmp/someone-else");
        std::env::set_var("ACCOUNTS", "/tmp/evil");
        std::env::set_var("LANG", "fi_FI.UTF-8");
    }
    // SAFETY: valid rlimit structs.
    let before = unsafe {
        let mut core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_CORE, &raw mut core);
        // A core limit of its own to drop (the soft limit may start at 0).
        let open = libc::rlimit { rlim_cur: core.rlim_max, rlim_max: core.rlim_max };
        libc::setrlimit(libc::RLIMIT_CORE, &raw const open);
        core
    };
    check.check(before.rlim_max != 0);
    let removed = sandbox::prepare_set_id_process();
    check.check(
        removed.as_ref().is_some_and(|r| r.iter().any(|n| n == "ACCOUNTS") && !r.iter().any(|n| n == "LANG")),
    );
    // The real uid's home, not the caller's.
    check.check(
        std::env::var_os("HOME").is_some_and(|h| h != "/tmp/someone-else" && Path::new(&h).is_absolute()),
    );
    check.check(std::env::var_os("ACCOUNTS").is_none());
    check.check(std::env::var_os("LANG").is_some_and(|l| l == "fi_FI.UTF-8"));
    check.check(std::env::var_os("PATH").is_none());
    // SAFETY: a valid rlimit struct.
    let after = unsafe {
        let mut core = libc::rlimit { rlim_cur: 1, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_CORE, &raw mut core);
        core
    };
    check.check(after.rlim_cur == 0 && after.rlim_max == before.rlim_max);
}

/// `set_id`: started from a setgid copy of the probe, so that there is a
/// group to drop.
fn group(check: &mut Checks, set_id: bool) {
    if set_id {
        // SAFETY: plain id calls.
        check.check(sandbox::running_set_id() && unsafe { libc::getegid() != libc::getgid() });
    }
    check.check(sandbox::drop_set_id_group());
    // SAFETY: plain id calls.
    unsafe {
        let (mut r, mut e, mut s) = (1, 1, 1);
        check.check(
            libc::getresgid(&raw mut r, &raw mut e, &raw mut s) == 0
                && r == libc::getgid()
                && e == r
                && s == r,
        );
    }
}

fn main() {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let part = args.first().and_then(|p| p.to_str()).unwrap_or_default().to_owned();
    let path = |i: usize| args.get(i).cloned().unwrap_or_default();
    let mut checks = Checks::default();
    let status = match part.as_str() {
        "descriptors" => {
            descriptors(&mut checks, path(1).to_str().and_then(|s| s.parse().ok()).unwrap_or(3));
            0
        }
        "process-state" => {
            process_state(&mut checks);
            0
        }
        "syscalls" => syscalls(&mut checks, &path(1)),
        "filesystem" => filesystem(&mut checks, &path(1), &path(2)),
        "set-id-environment" => {
            set_id_environment(&mut checks);
            0
        }
        "group" => {
            group(&mut checks, path(1) == Path::new("set-id"));
            0
        }
        _ => 2,
    };
    std::process::exit(if status != 0 { status } else { checks.failed });
}
