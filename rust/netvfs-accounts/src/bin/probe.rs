// SPDX-License-Identifier: LGPL-2.1-or-later
//! Tests only (feature "probe"): applies one part of the confinement to this process and checks
//! what it still allows. Exit status is the number of the first failed check, 0 if none; 77 without
//! Landlock, 99 without seccomp. Stdout says how many checks ran. Usage: `netvfs-accounts-probe
//! <part> [arguments...]`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::{Path, PathBuf};

use netvfs_accounts::sandbox;

/// ASan runs only (`--cfg netvfs_asan`): LeakSanitizer cannot stop the confined probe (no ptrace).
#[cfg(netvfs_asan)]
#[unsafe(no_mangle)]
extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

const NO_LANDLOCK: i32 = 77;
const NO_SECCOMP: i32 = 99;
/// fchmodat2 (Linux 6.6), same number on every architecture.
const FCHMODAT2: libc::c_long = 452;
fn setresgid() -> i64 {
    #[cfg(target_arch = "arm")]
    let nr = i64::from(libc::SYS_setresgid32);
    #[cfg(not(target_arch = "arm"))]
    let nr = libc::SYS_setresgid;
    nr
}

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

    fn fails(&mut self, result: i64, error: i32) {
        let actual = error_of(result);
        self.check(actual == error);
    }
}

#[allow(clippy::print_stderr)]
fn report(message: &str) {
    eprintln!("probe: {message}");
}

/// Stdout count: the test compares it so a part that skips its checks does not pass.
#[allow(clippy::print_stdout)]
fn ran(checks: &Checks) {
    println!("ran {}", checks.count);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn error_of(result: i64) -> i32 {
    if result == -1 { errno() } else { 0 }
}

fn c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap_or_default()
}

fn descriptors(check: &mut Checks, inherited: i32) {
    // SAFETY: querying a descriptor.
    check.check(unsafe { libc::fcntl(inherited, libc::F_GETFD) } != -1);
    sandbox::close_inherited_descriptors();
    let null = std::fs::metadata("/dev/null").map(|m| (m.mode() & libc::S_IFMT, m.rdev())).ok();
    for fd in [0, 2] {
        // SAFETY: an all-zero stat is a valid value to overwrite.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is writable; a descriptor not open leaves the zeros, no device.
        unsafe { libc::fstat(fd, &raw mut st) };
        check.check(Some((st.st_mode & libc::S_IFMT, st.st_rdev)) == null);
    }
    // SAFETY: querying a descriptor.
    check.fails(i64::from(unsafe { libc::fcntl(inherited, libc::F_GETFD) }), libc::EBADF);
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
        action.sa_sigaction = libc::SIG_IGN;
        libc::sigaction(libc::SIGTERM, std::ptr::null(), &raw mut action);
        check.check(action.sa_sigaction == libc::SIG_DFL);
        let mut now: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&raw mut now);
        libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &raw mut now);
        check.check(libc::sigismember(&raw const now, libc::SIGUSR1) == 0);
        let mut size = libc::rlimit { rlim_cur: 0, rlim_max: 1 };
        libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut size);
        check.check(size.rlim_cur == size.rlim_max);
    }
}

/// clone(2) with namespace `flags` and CLONE_SIGHAND without CLONE_VM: the kernel refuses (EINVAL)
/// before making anything, so only the filter's EPERM shows it saw the flags.
fn clone_refused(flags: libc::c_int) -> i64 {
    // SAFETY: a clone(2) with plain values; a child exits below.
    let result = unsafe {
        libc::syscall(libc::SYS_clone, libc::c_long::from(flags | libc::CLONE_SIGHAND), 0, 0, 0, 0)
    };
    if result == 0 {
        // SAFETY: ends the child without running anything of the parent's.
        unsafe { libc::_exit(0) };
    }
    result
}

fn syscalls(check: &mut Checks, dir: &Path) -> i32 {
    if !sandbox::restrict_syscalls() {
        return NO_SECCOMP;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    check.check(status.lines().find_map(|l| l.strip_prefix("Seccomp:")).map(str::trim) == Some("2"));
    let file = c(&dir.join("file"));
    let other = c(&dir.join("other"));
    let folder = c(&dir.join("folder"));
    // SAFETY: syscalls on valid, NUL-terminated paths and plain values.
    unsafe {
        let argv = [c"false".as_ptr(), std::ptr::null()];
        check.fails(i64::from(libc::execv(c"/bin/false".as_ptr(), argv.as_ptr())), libc::EPERM);
        check.fails(i64::from(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)), libc::EPERM);
        check.fails(i64::from(libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0)), libc::EPERM);
        check.fails(i64::from(libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0)), libc::EPERM);
        check.check(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) >= 0);
        let mut pair = [0; 2];
        check.check(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) == 0);
        check.fails(i64::from(libc::unshare(libc::CLONE_NEWUSER)), libc::EPERM);
        check.fails(libc::syscall(libc::SYS_bpf, 0, 0, 0), libc::EPERM);
    }
    for namespace in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ] {
        check.fails(clone_refused(namespace), libc::EPERM);
    }
    check.fails(clone_refused(0), libc::EINVAL);
    // SAFETY: as above.
    unsafe {
        let fd = libc::open(file.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600);
        check.check(fd >= 0);
        check.fails(i64::from(libc::fchmod(fd, 0o2755)), libc::EPERM);
        check.fails(i64::from(libc::chmod(file.as_ptr(), 0o4755)), libc::EPERM);
        check.fails(i64::from(libc::fchmodat(libc::AT_FDCWD, file.as_ptr(), 0o2700, 0)), libc::EPERM);
        check.check(libc::chmod(file.as_ptr(), 0o640) == 0);
        check.fails(
            i64::from(libc::open(other.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o2755)),
            libc::EPERM,
        );
        // Without O_CREAT the mode is unused, whatever a raw syscall passes.
        check.check(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, file.as_ptr(), libc::O_RDONLY, 0o6755) >= 0,
        );
        check.check(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, file.as_ptr(), libc::O_WRONLY, 0o6755) >= 0,
        );
        check.fails(i64::from(libc::mkdir(folder.as_ptr(), 0o2755)), libc::EPERM);
        // The *at calls themselves (glibc uses the old ones where they exist).
        check.fails(libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, folder.as_ptr(), 0o2755), libc::EPERM);
        check.fails(
            libc::syscall(libc::SYS_mknodat, libc::AT_FDCWD, other.as_ptr(), libc::S_IFREG | 0o4644, 0),
            libc::EPERM,
        );
        check.fails(libc::syscall(FCHMODAT2, libc::AT_FDCWD, file.as_ptr(), 0o2700, 0), libc::EPERM);
        check.fails(i64::from(libc::creat(other.as_ptr(), 0o2755)), libc::EPERM);
        check.check(libc::mkdir(folder.as_ptr(), 0o700) == 0);
        // O_DIRECTORY is part of O_TMPFILE but alone creates nothing.
        check.check(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, folder.as_ptr(), libc::O_DIRECTORY, 0o6755) >= 0,
        );
        check.fails(
            i64::from(libc::open(folder.as_ptr(), libc::O_TMPFILE | libc::O_WRONLY, 0o2755)),
            libc::EPERM,
        );
        check.fails(libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0), libc::EPERM);
        check.fails(libc::syscall(435, 0, 0), libc::ENOSYS);
        check.fails(libc::syscall(437, 0, 0, 0, 0), libc::ENOSYS);
    }
    check.check(std::thread::spawn(|| true).join().unwrap_or(false));
    0
}

/// `allowed`: database folder. `denied`: test-made `secret` file, `empty` folder, `file` and FIFO
/// `fifo` (writable paths of their own). `bus`: abstract socket the test listens on.
/// `abstract_bus`: helper with an abstract session bus.
fn filesystem(check: &mut Checks, allowed: &Path, denied: &Path, bus: &Path, abstract_bus: bool) -> i32 {
    // With descriptor 0 free, the ruleset is descriptor 0: still one.
    // SAFETY: closing stdin, which the probe does not read.
    unsafe { libc::close(0) };
    let writable = [
        allowed.to_owned(),
        PathBuf::from("/nonexistent/accounts"),
        denied.join("file"),
        denied.join("fifo"),
    ];
    let restriction = sandbox::restrict_filesystem(&writable, abstract_bus);
    if restriction.abi == 0 {
        return NO_LANDLOCK;
    }
    check.check(restriction.enforced);
    let created = c(&allowed.join("accounts.db-wal"));
    let at = |name: &str| c(&denied.join(name));
    let [secret, empty, file, fifo] = ["secret", "empty", "file", "fifo"].map(at);
    let [planted, folder, char_device, block_device, socket, pipe, link] =
        ["planted", "folder", "char", "block", "socket", "pipe", "link"].map(at);
    let denied = c(denied);
    let argv = [c"false".as_ptr(), std::ptr::null()];
    // SAFETY: syscalls on valid, NUL-terminated paths and plain values.
    unsafe {
        let fd = libc::open(created.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600);
        check.check(fd >= 0);
        check.check(libc::write(fd, b"x".as_ptr().cast(), 1) == 1);
        check.check(libc::ftruncate(fd, 0) == 0);
        check.check(libc::unlink(created.as_ptr()) == 0);
        check.check(libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY) >= 0);
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        check.check(libc::write(null, b"x".as_ptr().cast(), 1) == 1);
        check.check(libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY) >= 0);
        // Each ABI 1 right is refused beyond them; a device also before the capability check
        // (EPERM, as non-root).
        check.fails(i64::from(libc::open(secret.as_ptr(), libc::O_RDONLY)), libc::EACCES);
        check.fails(i64::from(libc::open(secret.as_ptr(), libc::O_WRONLY)), libc::EACCES);
        check.fails(i64::from(libc::open(denied.as_ptr(), libc::O_DIRECTORY)), libc::EACCES);
        check.fails(i64::from(libc::execv(c"/bin/false".as_ptr(), argv.as_ptr())), libc::EACCES);
        check.fails(
            i64::from(libc::open(planted.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600)),
            libc::EACCES,
        );
        check.fails(i64::from(libc::mkdir(folder.as_ptr(), 0o700)), libc::EACCES);
        check.fails(i64::from(libc::rmdir(empty.as_ptr())), libc::EACCES);
        check.fails(i64::from(libc::unlink(secret.as_ptr())), libc::EACCES);
        check.fails(i64::from(libc::mknod(char_device.as_ptr(), libc::S_IFCHR, 0)), libc::EACCES);
        check.fails(i64::from(libc::mknod(block_device.as_ptr(), libc::S_IFBLK, 0)), libc::EACCES);
        check.fails(i64::from(libc::mknod(socket.as_ptr(), libc::S_IFSOCK, 0)), libc::EACCES);
        check.fails(i64::from(libc::mkfifo(pipe.as_ptr(), 0o600)), libc::EACCES);
        check.fails(i64::from(libc::symlink(c"secret".as_ptr(), link.as_ptr())), libc::EACCES);
        // Writable non-folders get a database folder's file rights: FIFO opened without waiting for
        // a writer, file truncated (ABI 3).
        check.check(libc::open(fifo.as_ptr(), libc::O_NONBLOCK) >= 0);
        check.check(libc::truncate(file.as_ptr(), 0) == 0);
        if restriction.abi >= 4 {
            let tcp = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let local = libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(2),
                sin_port: 1u16.to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be() },
                sin_zero: [0; 8],
            };
            let size = libc::socklen_t::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(16);
            check.fails(i64::from(libc::connect(tcp, std::ptr::addr_of!(local).cast(), size)), libc::EACCES);
        }
        if restriction.abi >= 6 {
            check.fails(i64::from(libc::kill(libc::getppid(), 0)), libc::EPERM);
        }
    }
    if restriction.abi >= 6 {
        // Test's abstract socket is out of reach unless the bus is one.
        let connected = SocketAddr::from_abstract_name(bus.as_os_str().as_bytes())
            .and_then(|address| UnixStream::connect_addr(&address));
        check.check(connected.err().and_then(|e| e.raw_os_error()) == (!abstract_bus).then_some(libc::EPERM));
    }
    0
}

/// `home`: real uid's passwd home. `runtime`: XDG_RUNTIME_DIR expected when the caller sets none,
/// empty for none.
fn set_id_environment(check: &mut Checks, home: &Path, runtime: &Path) {
    // SAFETY: one check per process, one thread.
    unsafe {
        std::env::set_var("HOME", "/tmp/someone-else");
        std::env::set_var("ACCOUNTS", "/tmp/evil");
        std::env::set_var("LANG", "fi_FI.UTF-8");
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/caller-runtime");
    }
    // SAFETY: valid rlimit structs.
    let before = unsafe {
        let mut core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_CORE, &raw mut core);
        let open = libc::rlimit { rlim_cur: core.rlim_max, rlim_max: core.rlim_max };
        libc::setrlimit(libc::RLIMIT_CORE, &raw const open);
        core
    };
    check.check(before.rlim_max != 0);
    let removed = sandbox::prepare_set_id_process();
    check.check(removed.is_some());
    let removed = removed.unwrap_or_default();
    check.check(removed.contains(&String::from("ACCOUNTS")));
    check.check(removed.contains(&String::from("HOME")));
    check.check(!removed.contains(&String::from("LANG")));
    check.check(std::env::var_os("HOME").is_some_and(|h| h == home.as_os_str()));
    check.check(std::env::var_os("ACCOUNTS").is_none());
    check.check(std::env::var_os("LANG").is_some_and(|l| l == "fi_FI.UTF-8"));
    check.check(std::env::var_os("PATH").is_none());
    // SAFETY: a valid rlimit struct.
    let after = unsafe {
        let mut core = libc::rlimit { rlim_cur: 1, rlim_max: 0 };
        libc::getrlimit(libc::RLIMIT_CORE, &raw mut core);
        core
    };
    check.check(after.rlim_cur == 0);
    check.check(after.rlim_max == before.rlim_max);
    check.check(std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|r| r == "/tmp/caller-runtime"));
    // SAFETY: as above.
    unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
    check.check(sandbox::prepare_set_id_process().is_some());
    check.check(std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_default() == runtime);
}

/// `set_id`: started from a setgid probe copy, so there is a group to drop.
fn group(check: &mut Checks, set_id: bool) {
    if set_id {
        check.check(sandbox::running_set_id());
        // SAFETY: plain id calls.
        check.check(unsafe { libc::getegid() != libc::getgid() });
    }
    check.check(sandbox::drop_set_id_group());
    // SAFETY: plain id calls.
    unsafe {
        let (mut r, mut e, mut s) = (libc::gid_t::MAX, libc::gid_t::MAX, libc::gid_t::MAX);
        libc::getresgid(&raw mut r, &raw mut e, &raw mut s);
        check.check([r, e, s] == [libc::getgid(); 3]);
    }
}

/// Refused setresgid is reported also when every gid is already the real one: the seccomp filter
/// fails it with EPERM.
fn group_refused(check: &mut Checks) {
    let mut filter = sandbox::Filter::default();
    filter.load_number();
    filter.on(setresgid(), sandbox::Filter::DENY);
    filter.ret(sandbox::Filter::ALLOW);
    let program = filter.instructions();
    let program = libc::sock_fprog {
        len: u16::try_from(program.len()).unwrap_or_default(),
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: prctl with plain values; the program outlives the call.
    unsafe {
        check.check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        check.check(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
                std::ptr::addr_of!(program),
            ) == 0,
        );
    }
    check.check(!sandbox::drop_set_id_group());
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
        "filesystem" => {
            filesystem(&mut checks, &path(1), &path(2), &path(3), path(4) == Path::new("abstract-bus"))
        }
        "set-id-environment" => {
            set_id_environment(&mut checks, &path(1), &path(2));
            0
        }
        "group" => {
            group(&mut checks, path(1) == Path::new("set-id"));
            0
        }
        "group-refused" => {
            group_refused(&mut checks);
            0
        }
        _ => 2,
    };
    ran(&checks);
    std::process::exit(if status != 0 { status } else { checks.failed });
}
