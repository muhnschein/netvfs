// SPDX-License-Identifier: LGPL-2.1-or-later
//! The confinement of netvfs-accounts (SPEC-v2 XB-2a), which any process of
//! the user can start with the group `privileged`, and the process state of a
//! set-id start. In `main()`, before anything else: `close_inherited_descriptors()`,
//! `reset_process_state()`, `prepare_set_id_process()`, then
//! `restrict_filesystem()` and `restrict_syscalls()`. After the database
//! work: `drop_set_id_group()`.
//!
//! Landlock and seccomp are best-effort: the Jolla Phone 2026 kernel (6.12)
//! has seccomp but no Landlock, a later kernel may have both.
//!
//! The one module with `unsafe`: every call into libc is here.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const RUNTIME_ROOT: &str = "/run/user";
/// Signals 1 to 64 (glibc's `NSIG` is 65).
const NSIG: i32 = 65;

fn warn(what: &str) {
    eprintln!("netvfs-accounts: {what}: {}", std::io::Error::last_os_error());
}

fn c_path(path: &Path) -> Option<CString> {
    CString::new(path.as_os_str().as_bytes()).ok()
}

/// The real uid.
#[must_use]
pub fn uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

/// `/run/user/<uid>`, the uid's own runtime folder.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    Path::new(RUNTIME_ROOT).join(uid().to_string())
}

/// `CLOCK_MONOTONIC` as seconds and nanoseconds, as libaccounts-glib stamps
/// its change signals.
#[must_use]
pub fn monotonic_time() -> (u64, u32) {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid timespec to write.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (u64::try_from(ts.tv_sec).unwrap_or(0), u32::try_from(ts.tv_nsec).unwrap_or(0))
}

// ---- descriptors and process state ----

/// Closes every inherited descriptor but 0, 1 and 2. Those are open already:
/// Rust's runtime opens /dev/null on any the caller closed before `main()`
/// (or aborts), so that no file the helper opens becomes its stdout; the
/// probe's `descriptors` test checks that it still does.
pub fn close_inherited_descriptors() {
    close_from(3);
}

/// Closes every descriptor from `lowest` on, by what /proc lists (also
/// before `close_range()`, Linux 5.9).
fn close_from(lowest: i32) {
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else { return };
    let open: Vec<i32> = entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd >= lowest)
        .collect();
    for fd in open {
        // SAFETY: closing a descriptor nothing in this process uses; the
        // listing's own one is already closed (EBADF, ignored).
        unsafe { libc::close(fd) };
    }
}

/// umask 077, default signal handlers and an empty signal mask, and the file
/// size soft limit raised to the hard one (a caller's small limit would cut
/// the attention write short).
pub fn reset_process_state() {
    // SAFETY: plain process-state calls on valid arguments.
    unsafe {
        // The tightest mask: nothing the helper creates is readable by others.
        libc::umask(0o077);
        // A caller's handlers do not survive exec, but ignored signals and
        // the mask do (Rust's runtime also ignores SIGPIPE).
        for sig in 1..NSIG {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                libc::signal(sig, libc::SIG_DFL); // EINVAL for glibc's own signals
            }
        }
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
        let mut size = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_FSIZE, &mut size) == 0 {
            size.rlim_cur = size.rlim_max;
            libc::setrlimit(libc::RLIMIT_FSIZE, &size);
        }
    }
}

// ---- set-id ----

/// The kernel started this process with `AT_SECURE` (set-id exec).
#[must_use]
pub fn running_set_id() -> bool {
    // SAFETY: getauxval only reads the auxiliary vector.
    unsafe { libc::getauxval(libc::AT_SECURE) != 0 }
}

/// Variables of the caller kept in a set-id process: locale, time zone, the
/// runtime folder and the session bus. Everything else could make the
/// privileged process use another database (HOME, XDG_*_HOME, ACCOUNTS) or
/// behave as its caller chose.
#[must_use]
pub fn kept_in_set_id_process(name: &OsStr) -> bool {
    let name = name.as_bytes();
    name.starts_with(b"LC_")
        || [&b"LANG"[..], b"LANGUAGE", b"TZ", b"XDG_RUNTIME_DIR", b"DBUS_SESSION_BUS_ADDRESS"].contains(&name)
}

/// The home folder of `uid` in passwd.
fn home_of(uid: u32) -> Option<PathBuf> {
    // SAFETY: sysconf has no preconditions.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![0u8; usize::try_from(suggested).ok().filter(|n| *n > 0).unwrap_or(16384)];
    // SAFETY: an all-zero passwd is a valid value to overwrite.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the buffers outlive the call, sizes as given.
    let status =
        unsafe { libc::getpwuid_r(uid, &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut result) };
    if status != 0 || result.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into `buffer`, NUL-terminated by getpwuid_r.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    dir.to_bytes().starts_with(b"/").then(|| PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
}

/// The uid and gid of the user `privileged`.
#[must_use]
pub fn privileged_ids() -> Option<(u32, u32)> {
    let mut buffer = vec![0u8; 16384];
    // SAFETY: as in home_of.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: as in home_of; the name is a constant C string.
    let status = unsafe {
        libc::getpwnam_r(
            b"privileged\0".as_ptr().cast(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    (status == 0 && !result.is_null()).then_some((entry.pw_uid, entry.pw_gid))
}

fn owned_directory(path: &Path, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && m.uid() == uid)
}

/// First thing in `main()` of a set-id process: removes the variables not
/// kept (returns their names), sets HOME to the home folder of the real uid
/// (passwd), and a missing XDG_RUNTIME_DIR to /run/user/<uid> when that is
/// the uid's folder. The soft core limit becomes 0: a core file would be the
/// user's and hold memory of the `privileged` group. `None` when the real
/// uid has no home folder.
#[must_use]
pub fn prepare_set_id_process() -> Option<Vec<String>> {
    let removed: Vec<_> =
        std::env::vars_os().map(|(name, _)| name).filter(|n| !kept_in_set_id_process(n)).collect();
    for name in &removed {
        std::env::remove_var(name);
    }
    let mut core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid rlimit structs.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_CORE, &mut core) == 0 {
            core.rlim_cur = 0;
            libc::setrlimit(libc::RLIMIT_CORE, &core);
        }
    }
    let runtime = runtime_dir();
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() && owned_directory(&runtime, uid()) {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }
    let home = home_of(uid())?;
    std::env::set_var("HOME", home);
    Some(removed.iter().map(|n| n.to_string_lossy().into_owned()).collect())
}

/// Gives up the group of a set-id start for good: real, effective and saved
/// gid become the real one. False if any of them is still another.
#[must_use]
pub fn drop_set_id_group() -> bool {
    // SAFETY: plain id calls on valid pointers.
    unsafe {
        let real = libc::getgid();
        let (mut r, mut e, mut s) = (0, 0, 0);
        libc::setresgid(real, real, real) == 0
            && libc::getresgid(&mut r, &mut e, &mut s) == 0
            && r == real
            && e == real
            && s == real
    }
}

// ---- Landlock ----

/// `<linux/landlock.h>` as of ABI 7; the target's headers predate it.
pub mod landlock {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    pub const REFER: u64 = 1 << 13; // ABI 2
    pub const TRUNCATE: u64 = 1 << 14; // ABI 3
    pub const IOCTL_DEV: u64 = 1 << 15; // ABI 5

    pub const NET_BIND_TCP: u64 = 1 << 0; // ABI 4
    pub const NET_CONNECT_TCP: u64 = 1 << 1; // ABI 4

    pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0; // ABI 6
    pub const SCOPE_SIGNAL: u64 = 1 << 1; // ABI 6

    pub const ABI1_FS: u64 = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    /// What a rule on a file (not a folder) may allow.
    pub const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

    pub const READ_ONLY: u64 = READ_FILE | READ_DIR;
    /// The database folder: SQLite creates, truncates and removes its -wal
    /// and -shm files there.
    pub const READ_WRITE: u64 =
        READ_FILE | READ_DIR | WRITE_FILE | TRUNCATE | MAKE_REG | REMOVE_FILE | MAKE_DIR;

    pub const CREATE_RULESET_VERSION: u32 = 1 << 0;
    pub const RULE_PATH_BENEATH: i32 = 1;

    #[repr(C)]
    pub(super) struct RulesetAttr {
        pub(super) handled_access_fs: u64,
        pub(super) handled_access_net: u64, // ABI 4
        pub(super) scoped: u64,             // ABI 6
    }

    #[repr(C, packed)]
    pub(super) struct PathBeneathAttr {
        pub(super) allowed_access: u64,
        pub(super) parent_fd: i32,
    }
}

/// The Landlock ABI versions this code knows; it uses what the kernel offers
/// of them: 1 files, 2 renames and links across folders, 3 truncation, 4 TCP,
/// 5 device ioctls, 6 abstract unix sockets and signals beyond the sandbox,
/// 7 audit logging of denials (on by default, nothing to set).
pub const LANDLOCK_NEWEST_ABI: i32 = 7;

/// What a ruleset handles (restricts) with a kernel of Landlock ABI `abi`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LandlockAccess {
    pub fs: u64,
    pub net: u64,
    pub scoped: u64,
}

/// Each version's rights up to `abi`; newer ones are unknown to it. With
/// `allow_abstract_sockets` (a test's session bus may be one) the abstract
/// socket scope stays off.
#[must_use]
pub fn landlock_access(abi: i32, allow_abstract_sockets: bool) -> LandlockAccess {
    use landlock as l;
    const LEVELS: [(i32, LandlockAccess); 6] = [
        (1, LandlockAccess { fs: l::ABI1_FS, net: 0, scoped: 0 }),
        (2, LandlockAccess { fs: l::REFER, net: 0, scoped: 0 }),
        (3, LandlockAccess { fs: l::TRUNCATE, net: 0, scoped: 0 }),
        (4, LandlockAccess { fs: 0, net: l::NET_BIND_TCP | l::NET_CONNECT_TCP, scoped: 0 }),
        (5, LandlockAccess { fs: l::IOCTL_DEV, net: 0, scoped: 0 }),
        (6, LandlockAccess { fs: 0, net: 0, scoped: l::SCOPE_SIGNAL | l::SCOPE_ABSTRACT_UNIX_SOCKET }),
    ];
    let mut access = LandlockAccess::default();
    for (level, adds) in LEVELS {
        if level > abi {
            break;
        }
        access.fs |= adds.fs;
        access.net |= adds.net;
        access.scoped |= adds.scoped;
    }
    if allow_abstract_sockets {
        access.scoped &= !l::SCOPE_ABSTRACT_UNIX_SOCKET;
    }
    access
}

/// The outcome of `restrict_filesystem()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilesystemRestriction {
    /// The kernel's Landlock ABI, 0 without Landlock.
    pub abi: i32,
    pub enforced: bool,
}

/// Syscalls added since Linux 5.1 have one number on every architecture.
mod nr {
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;
    pub const OPEN_TREE: i64 = 428;
    pub const MOVE_MOUNT: i64 = 429;
    pub const FSOPEN: i64 = 430;
    pub const FSCONFIG: i64 = 431;
    pub const FSMOUNT: i64 = 432;
    pub const FSPICK: i64 = 433;
    pub const CLONE3: i64 = 435;
    pub const OPENAT2: i64 = 437;
    pub const MOUNT_SETATTR: i64 = 442;
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const LANDLOCK_ADD_RULE: i64 = 445;
    pub const LANDLOCK_RESTRICT_SELF: i64 = 446;
    pub const FCHMODAT2: i64 = 452;
}

/// One Landlock rule below `path`, for what of `access` the ruleset handles.
/// A missing path needs no rule.
fn allow_beneath(ruleset: i32, handled: u64, path: &Path, mut access: u64) {
    let Some(c) = c_path(path) else { return };
    // SAFETY: a NUL-terminated path; the descriptor is closed below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return;
    }
    // SAFETY: an all-zero stat is a valid value to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open, `st` is writable.
    if unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        access &= landlock::FILE_RIGHTS;
    }
    let rule = landlock::PathBeneathAttr { allowed_access: access & handled, parent_fd: fd };
    // SAFETY: the rule outlives the call; the kernel copies it.
    let added = unsafe {
        libc::syscall(
            nr::LANDLOCK_ADD_RULE,
            ruleset,
            landlock::RULE_PATH_BENEATH,
            std::ptr::addr_of!(rule),
            0u32,
        )
    };
    if added != 0 {
        warn(&format!("Landlock rule for {}", path.display()));
    }
    // SAFETY: closing the descriptor opened above.
    unsafe { libc::close(fd) };
}

/// Folders the build adds to the confinement: where coverage counters go.
fn build_folders() -> Vec<PathBuf> {
    option_env!("NETVFS_RUST_COVERAGE_DIR").map(PathBuf::from).into_iter().collect()
}

/// Landlock: reads only below the system folders (/usr, /etc, /lib*, /proc)
/// and the uid's runtime folder; reads and writes only below `writable` and
/// /dev/null; executes nothing; with ABI 4 connects and binds no TCP port;
/// with ABI 6 signals no process and connects to no abstract unix socket
/// outside the sandbox (unless `allow_abstract_sockets`). Without Landlock
/// nothing happens and `enforced` is false; a kernel that has it but refuses
/// the rules is reported on stderr.
#[must_use]
pub fn restrict_filesystem(writable: &[PathBuf], allow_abstract_sockets: bool) -> FilesystemRestriction {
    let mut result = FilesystemRestriction::default();
    // SAFETY: the version query takes no attribute.
    let abi = unsafe {
        libc::syscall(
            nr::LANDLOCK_CREATE_RULESET,
            std::ptr::null::<landlock::RulesetAttr>(),
            0usize,
            landlock::CREATE_RULESET_VERSION,
        )
    };
    if abi <= 0 {
        return result; // ENOSYS: not built; EOPNOTSUPP: not enabled at boot
    }
    result.abi = i32::try_from(abi).unwrap_or(LANDLOCK_NEWEST_ABI);
    let handled = landlock_access(result.abi, allow_abstract_sockets);
    // An older kernel takes the larger struct as long as its unknown fields
    // are zero.
    let attr = landlock::RulesetAttr {
        handled_access_fs: handled.fs,
        handled_access_net: handled.net,
        scoped: handled.scoped,
    };
    // SAFETY: `attr` outlives the call and its size is passed.
    let ruleset = unsafe {
        libc::syscall(
            nr::LANDLOCK_CREATE_RULESET,
            std::ptr::addr_of!(attr),
            std::mem::size_of::<landlock::RulesetAttr>(),
            0u32,
        )
    };
    let Ok(ruleset) = i32::try_from(ruleset) else { return result };
    if ruleset < 0 {
        warn("Landlock ruleset");
        return result;
    }
    let fs = handled.fs;
    for system in ["/usr", "/etc", "/lib", "/lib64", "/proc", "/dev/urandom", "/dev/random"] {
        allow_beneath(ruleset, fs, Path::new(system), landlock::READ_ONLY);
    }
    allow_beneath(ruleset, fs, Path::new("/dev/null"), landlock::READ_FILE | landlock::WRITE_FILE);
    // The uid's own runtime folder (the session bus), never XDG_RUNTIME_DIR:
    // the caller sets that.
    allow_beneath(ruleset, fs, &runtime_dir(), landlock::READ_ONLY);
    for dir in writable.iter().chain(&build_folders()) {
        allow_beneath(ruleset, fs, dir, landlock::READ_WRITE);
    }
    // SAFETY: prctl and the ruleset descriptor from above.
    result.enforced = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::syscall(nr::LANDLOCK_RESTRICT_SELF, ruleset, 0u32) == 0
    };
    if !result.enforced {
        warn("Landlock");
    }
    // SAFETY: closing the ruleset descriptor.
    unsafe { libc::close(ruleset) };
    result
}

// ---- seccomp ----

/// seccomp-bpf, assembled.
#[derive(Debug, Default)]
pub struct Filter {
    program: Vec<libc::sock_filter>,
}

mod bpf {
    /// BPF_LD | BPF_W | BPF_ABS (both 0) | 0x20.
    pub const LD_W_ABS: u16 = 0x20;
    pub const JMP_JEQ_K: u16 = 0x05 | 0x10;
    pub const JMP_JGE_K: u16 = 0x05 | 0x30;
    pub const JMP_JSET_K: u16 = 0x05 | 0x40;
    pub const RET_K: u16 = 0x06;
    // struct seccomp_data
    pub const NR: u32 = 0;
    pub const ARCH: u32 = 4;
    pub const ARGS: u32 = 16;
}

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

#[allow(clippy::cast_sign_loss)]
const fn errno_action(e: i32) -> u32 {
    SECCOMP_RET_ERRNO | (e as u32 & SECCOMP_RET_DATA)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const fn number(nr: i64) -> u32 {
    nr as u32
}

impl Filter {
    pub const ALLOW: u32 = SECCOMP_RET_ALLOW;
    pub const DENY: u32 = errno_action(libc::EPERM);
    pub const NO_SYS: u32 = errno_action(libc::ENOSYS);

    fn stmt(&mut self, code: u16, k: u32) {
        self.program.push(libc::sock_filter { code, jt: 0, jf: 0, k });
    }

    pub fn jump(&mut self, code: u16, k: u32, jt: u8, jf: u8) {
        self.program.push(libc::sock_filter { code, jt, jf, k });
    }

    pub fn load_number(&mut self) {
        self.stmt(bpf::LD_W_ABS, bpf::NR);
    }

    pub fn load_arch(&mut self) {
        self.stmt(bpf::LD_W_ABS, bpf::ARCH);
    }

    /// The low 32 bits of an argument (all targets are little-endian).
    pub fn load_argument(&mut self, i: u32) {
        self.stmt(bpf::LD_W_ABS, bpf::ARGS + 8 * i);
    }

    pub fn ret(&mut self, action: u32) {
        self.stmt(bpf::RET_K, action);
    }

    /// With the number loaded: `action` for syscall `nr`.
    pub fn on(&mut self, nr: i64, action: u32) {
        self.jump(bpf::JMP_JEQ_K, number(nr), 0, 1);
        self.ret(action);
    }

    /// With the number loaded: EPERM for `nr` when argument `i` has any of
    /// `bits`; the number is loaded again afterwards.
    pub fn deny_argument_bits(&mut self, nr: i64, i: u32, bits: u32) {
        self.jump(bpf::JMP_JEQ_K, number(nr), 0, 4);
        self.load_argument(i);
        self.jump(bpf::JMP_JSET_K, bits, 0, 1);
        self.ret(Self::DENY);
        self.load_number();
    }

    /// With the number loaded: EPERM for `nr` when it creates a file (flags
    /// in argument `flags`) whose mode (argument `mode`) has any of `bits`.
    /// Without O_CREAT or O_TMPFILE the mode is unused and may be garbage.
    #[allow(clippy::cast_sign_loss)]
    pub fn deny_created_mode_bits(&mut self, nr: i64, flags: u32, mode: u32, bits: u32) {
        self.jump(bpf::JMP_JEQ_K, number(nr), 0, 6);
        self.load_argument(flags);
        self.jump(bpf::JMP_JSET_K, (libc::O_CREAT | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32, 0, 3);
        self.load_argument(mode);
        self.jump(bpf::JMP_JSET_K, bits, 0, 1);
        self.ret(Self::DENY);
        self.load_number();
    }

    /// With the number loaded: EPERM for `nr` unless argument `i` is `value`.
    pub fn deny_argument_other_than(&mut self, nr: i64, i: u32, value: u32) {
        self.jump(bpf::JMP_JEQ_K, number(nr), 0, 4);
        self.load_argument(i);
        self.jump(bpf::JMP_JEQ_K, value, 1, 0);
        self.ret(Self::DENY);
        self.load_number();
    }

    #[must_use]
    pub fn instructions(&self) -> &[libc::sock_filter] {
        &self.program
    }

    fn install(&self) -> bool {
        let Ok(len) = u16::try_from(self.program.len()) else { return false };
        let program = libc::sock_fprog { len, filter: self.program.as_ptr().cast_mut() };
        // SAFETY: the program outlives the call; the kernel copies it.
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
                std::ptr::addr_of!(program),
            ) == 0
        }
    }
}

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_003e); // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: Option<u32> = Some(0xc000_00b7); // AUDIT_ARCH_AARCH64
#[cfg(all(target_arch = "arm", target_endian = "little"))]
const NATIVE_ARCH: Option<u32> = Some(0x4000_0028); // AUDIT_ARCH_ARM
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    all(target_arch = "arm", target_endian = "little")
)))]
const NATIVE_ARCH: Option<u32> = None;

/// Syscalls the helper never needs and that would widen what code run
/// inside it could do with the group.
fn denied_syscalls() -> Vec<i64> {
    let mut list = vec![
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        nr::OPEN_TREE,
        nr::MOVE_MOUNT,
        nr::FSOPEN,
        nr::FSCONFIG,
        nr::FSMOUNT,
        nr::FSPICK,
        nr::MOUNT_SETATTR,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        nr::IO_URING_SETUP,
        nr::IO_URING_ENTER,
        nr::IO_URING_REGISTER,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        libc::SYS_fanotify_init,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_syslog,
    ];
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    list.push(libc::SYS_kexec_file_load);
    #[cfg(target_arch = "x86_64")]
    list.extend([libc::SYS_uselib, libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_modify_ldt]);
    list
}

const NEW_NAMESPACES: i32 = libc::CLONE_NEWNS
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP;
const SET_ID_BITS: u32 = libc::S_ISUID | libc::S_ISGID;

/// The filter `restrict_syscalls()` installs, for the native architecture.
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn syscall_filter(native_arch: u32) -> Filter {
    let mut f = Filter::default();
    f.load_arch();
    f.jump(bpf::JMP_JEQ_K, native_arch, 1, 0);
    f.ret(Filter::DENY); // another ABI's numbers would mean other syscalls
    f.load_number();
    if cfg!(target_arch = "x86_64") {
        f.jump(bpf::JMP_JGE_K, 0x4000_0000, 0, 1); // x32
        f.ret(Filter::DENY);
    }
    for nr in denied_syscalls() {
        f.on(nr, Filter::DENY);
    }
    // Arguments behind a pointer are out of the filter's sight.
    f.on(nr::CLONE3, Filter::NO_SYS);
    f.on(nr::OPENAT2, Filter::NO_SYS);
    f.deny_argument_bits(libc::SYS_clone, 0, NEW_NAMESPACES as u32);
    f.deny_argument_other_than(libc::SYS_socket, 0, libc::AF_UNIX as u32);
    f.deny_argument_other_than(libc::SYS_socketpair, 0, libc::AF_UNIX as u32);
    f.deny_argument_bits(libc::SYS_fchmod, 1, SET_ID_BITS);
    f.deny_argument_bits(libc::SYS_fchmodat, 2, SET_ID_BITS);
    f.deny_argument_bits(nr::FCHMODAT2, 2, SET_ID_BITS);
    f.deny_created_mode_bits(libc::SYS_openat, 2, 3, SET_ID_BITS);
    f.deny_argument_bits(libc::SYS_mkdirat, 2, SET_ID_BITS);
    f.deny_argument_bits(libc::SYS_mknodat, 2, SET_ID_BITS);
    #[cfg(target_arch = "x86_64")]
    {
        f.deny_argument_bits(libc::SYS_chmod, 1, SET_ID_BITS);
        f.deny_created_mode_bits(libc::SYS_open, 1, 2, SET_ID_BITS);
        f.deny_argument_bits(libc::SYS_creat, 1, SET_ID_BITS);
        f.deny_argument_bits(libc::SYS_mkdir, 1, SET_ID_BITS);
        f.deny_argument_bits(libc::SYS_mknod, 1, SET_ID_BITS);
    }
    f.ret(Filter::ALLOW);
    f
}

/// no_new_privs and a seccomp filter that fails these with EPERM: exec,
/// ptrace, sockets other than `AF_UNIX`, new namespaces, mounts, modules,
/// kexec, BPF, `io_uring`, userfaultfd, perf, keyrings, file handles; and any
/// chmod, open, mkdir or mknod that would set a setuid or setgid bit (a file
/// of the group `privileged` left behind with it would hand the group to
/// anyone). clone3 and openat2 fail with ENOSYS so that glibc falls back to
/// clone and openat, whose arguments the filter can see. False when the
/// kernel or the architecture has no seccomp.
#[must_use]
pub fn restrict_syscalls() -> bool {
    let Some(arch) = NATIVE_ARCH else { return false };
    let filter = syscall_filter(arch);
    // SAFETY: prctl with constant arguments.
    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0;
    if !no_new_privs || !filter.install() {
        warn("seccomp");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_levels() {
        let widens = |smaller: u64, larger: u64| smaller != larger && (smaller & larger) == smaller;
        let levels: Vec<_> = (0..=LANDLOCK_NEWEST_ABI + 2).map(|abi| landlock_access(abi, false)).collect();
        assert_eq!(levels[0], LandlockAccess::default());
        assert!(levels[1].fs != 0 && levels[1].net == 0 && levels[1].scoped == 0);
        assert!(widens(levels[1].fs, levels[2].fs)); // renames and links
        assert!(widens(levels[2].fs, levels[3].fs)); // truncation
        assert_eq!(levels[4].fs, levels[3].fs); // TCP
        assert!(levels[3].net == 0 && levels[4].net != 0);
        assert!(widens(levels[4].fs, levels[5].fs)); // device ioctls
        assert!(levels[5].scoped == 0 && levels[6].scoped != 0); // signals, abstract sockets
        for level in &levels[7..] {
            assert_eq!(*level, levels[6]);
        }
        let abstract_bus = landlock_access(LANDLOCK_NEWEST_ABI, true);
        assert!(widens(abstract_bus.scoped, levels[6].scoped) && abstract_bus.scoped != 0);
        assert_eq!(landlock_access(5, true), levels[5]);
        assert_eq!(levels[1].fs, landlock::ABI1_FS);
        assert_eq!(levels[6].net, landlock::NET_BIND_TCP | landlock::NET_CONNECT_TCP);
    }

    #[test]
    fn set_id_environment() {
        for kept in
            ["LANG", "LANGUAGE", "LC_ALL", "LC_TIME", "TZ", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]
        {
            assert!(kept_in_set_id_process(OsStr::new(kept)), "{kept}");
        }
        for removed in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "ACCOUNTS",
            "AG_PROVIDERS",
            "NETVFS_ACCOUNTS_HELPER",
            "LD_PRELOAD",
            "PATH",
            "LANGX",
            "XLANG",
            "",
        ] {
            assert!(!kept_in_set_id_process(OsStr::new(removed)), "{removed}");
        }
    }

    #[test]
    fn filter_shape() {
        let f = syscall_filter(0x1234);
        let program = f.instructions();
        // The architecture first, allow last.
        assert_eq!((program[0].code, program[0].k), (bpf::LD_W_ABS, bpf::ARCH));
        assert_eq!((program[1].code, program[1].k), (bpf::JMP_JEQ_K, 0x1234));
        assert_eq!((program[2].code, program[2].k), (bpf::RET_K, Filter::DENY));
        let last = program[program.len() - 1];
        assert_eq!((last.code, last.k), (bpf::RET_K, Filter::ALLOW));
        assert!(program.len() < 4096);
        assert_eq!(Filter::DENY, 0x0005_0000 | 1);
        assert_eq!(Filter::NO_SYS, 0x0005_0000 | 38);
    }

    #[test]
    fn process_helpers() {
        assert!(runtime_dir().starts_with(RUNTIME_ROOT));
        let (a, _) = monotonic_time();
        let (b, _) = monotonic_time();
        assert!(b >= a);
        assert!(!running_set_id());
        assert!(drop_set_id_group());
        assert!(home_of(uid()).is_some());
        assert!(home_of(u32::MAX - 7).is_none());
    }
}
