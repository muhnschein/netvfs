// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs 0.4's C++ tst_bridgeunits peer* cases, with a fake /proc in a
// temporary folder.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    COMPARE_CHUNK_BYTES, Environment, File, OwnedFd, Path, PathBuf, PeerChecker, PeerCredentials, Status,
    parse_fdinfo_pid, parse_start_time, read_fully, same_content, system_boot_ticks_now, uptime_ticks,
};
use crate::test_support::{TempDir, write_file};
use netvfs_bridge_proto::ErrorName;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

/// A fake /proc.
#[derive(Clone)]
struct FakeProc(Arc<TempDir>);

impl FakeProc {
    fn new() -> Self {
        Self(Arc::new(TempDir::new()))
    }

    fn root(&self) -> PathBuf {
        self.0.path().to_path_buf()
    }

    fn add_process(&self, pid: i32, exe: &Path, start_time: i64) {
        let base = self.root().join(pid.to_string());
        std::fs::create_dir_all(&base).unwrap();
        drop(std::fs::remove_file(base.join("exe")));
        std::os::unix::fs::symlink(exe, base.join("exe")).unwrap();
        self.set_start_time(pid, start_time);
    }

    fn set_start_time(&self, pid: i32, start_time: i64) {
        // Field 22 is starttime; comm with spaces and parentheses on purpose.
        let mut stat = format!("{pid} (we (ird) name) S");
        for _ in 4..=21 {
            stat.push_str(" 0");
        }
        stat = format!("{stat} {start_time} 0 0\n");
        write_file(&self.root().join(pid.to_string()).join("stat"), stat.as_bytes());
    }

    fn set_pidfd(&self, fd: i32, pid: i32) {
        let info = format!("pos:\t0\nflags:\t02000002\nPid:\t{pid}\n");
        write_file(&self.root().join("self/fdinfo").join(fd.to_string()), info.as_bytes());
    }
}

fn dev_null() -> OwnedFd {
    File::open("/dev/null").unwrap().into()
}

fn fake_environment(proc: &FakeProc, uid: u32, pid: i32, with_pidfd: bool) -> Environment {
    Environment {
        proc_root: proc.root(),
        own_uid: 4242,
        credentials: Box::new(move |_| Some(PeerCredentials { pid, uid, pidfd: with_pidfd.then(dev_null) })),
        open_pidfd: Box::new(|_| None),
        boot_ticks_now: Box::new(|| Some(100_000)),
        after_exe_read: None,
    }
}

fn socket() -> (UnixStream, UnixStream) {
    UnixStream::pair().unwrap()
}

fn check(exe: &Path, env: Environment) -> Result<(), Status> {
    let (a, _b) = socket();
    PeerChecker::with_environment(exe, env).check(a.as_fd())
}

fn denied(r: Result<(), Status>) -> bool {
    matches!(r, Err(s) if s.name == ErrorName::PermissionDenied)
}

use std::os::fd::AsFd as _;

fn this_exe() -> PathBuf {
    std::env::current_exe().unwrap()
}

#[test]
fn uid() {
    let proc = FakeProc::new();
    let exe = this_exe();
    proc.add_process(100, &exe, 50);
    check(&exe, fake_environment(&proc, 4242, 100, false)).unwrap();
    assert!(denied(check(&exe, fake_environment(&proc, 1000, 100, false))));
    assert!(denied(check(&exe, fake_environment(&proc, 0, 100, false))));
    let mut none = fake_environment(&proc, 4242, 100, false);
    none.credentials = Box::new(|_| None);
    let err = check(&exe, none).unwrap_err();
    assert_eq!(err.message, "no peer credentials");
    // pid 0 or negative: no process.
    assert!(denied(check(&exe, fake_environment(&proc, 4242, 0, false))));
    let err = check(&exe, fake_environment(&proc, 1000, 100, false)).unwrap_err();
    assert_eq!(err.message, "peer uid 1000 is not the bridge's uid");
}

#[test]
fn executable() {
    let proc = FakeProc::new();
    let dir = TempDir::new();
    let registered = dir.path().join("harbour-app");
    let other = dir.path().join("other-app");
    write_file(&registered, b"a");
    write_file(&other, b"b");
    proc.add_process(100, &registered, 50);
    proc.add_process(101, &other, 50);
    check(&registered, fake_environment(&proc, 4242, 100, false)).unwrap();
    assert!(denied(check(&registered, fake_environment(&proc, 4242, 101, false))));
    let missing = check(&dir.path().join("missing"), fake_environment(&proc, 4242, 100, false));
    assert_eq!(missing.unwrap_err().message, "the registered executable cannot be read");
    // A process that is gone.
    let gone = check(&registered, fake_environment(&proc, 4242, 555, false));
    assert_eq!(gone.unwrap_err().message, "peer process 555 is gone");
    // exe unreadable (dangling link).
    proc.add_process(102, &dir.path().join("deleted"), 50);
    let unreadable = check(&registered, fake_environment(&proc, 4242, 102, false));
    assert_eq!(unreadable.unwrap_err().message, "cannot read the executable of peer 102");
}

#[test]
fn executable_copy() {
    // XB-5: Sailjail (firejail --private-bin) runs a copy of the registered
    // executable from a tmpfs. Larger than one comparison chunk.
    let proc = FakeProc::new();
    let dir = TempDir::new();
    let mut content = b"\x7fELF".to_vec();
    content.extend(std::iter::repeat_n(b'x', 200 * 1024));
    let registered = dir.path().join("usr/bin/harbour-app");
    let copy = dir.path().join("run/firejail/bin/harbour-app");
    write_file(&registered, &content);
    write_file(&copy, &content);
    let mut last_byte = content.clone();
    *last_byte.last_mut().unwrap() = b'y';
    write_file(&dir.path().join("same-size"), &last_byte);
    // Differs in the second chunk only.
    let mut second_chunk = content.clone();
    second_chunk[COMPARE_CHUNK_BYTES + 1] = b'z';
    write_file(&dir.path().join("second-chunk"), &second_chunk);
    write_file(&dir.path().join("shorter"), &content[..content.len() - 1]);
    let mut longer = content.clone();
    longer.push(b'x');
    write_file(&dir.path().join("longer"), &longer);
    std::fs::create_dir_all(dir.path().join("folder")).unwrap();
    proc.add_process(100, &copy, 50);
    proc.add_process(101, &dir.path().join("same-size"), 50);
    proc.add_process(102, &dir.path().join("shorter"), 50);
    proc.add_process(103, &dir.path().join("longer"), 50);
    proc.add_process(104, &dir.path().join("folder"), 50);
    proc.add_process(105, &dir.path().join("second-chunk"), 50);

    let a = std::fs::metadata(&registered).unwrap();
    let b = std::fs::metadata(&copy).unwrap();
    assert_ne!(a.ino(), b.ino());
    check(&registered, fake_environment(&proc, 4242, 100, false)).unwrap();
    for pid in [101, 102, 103, 104, 105] {
        assert!(denied(check(&registered, fake_environment(&proc, 4242, pid, false))), "pid {pid}");
    }
    assert_eq!(
        check(&registered, fake_environment(&proc, 4242, 101, false)).unwrap_err().message,
        "peer 101 runs another executable"
    );
}

#[test]
fn copy_pid_reuse() {
    let proc = FakeProc::new();
    let dir = TempDir::new();
    let registered = dir.path().join("harbour-app");
    let copy = dir.path().join("copy/harbour-app");
    let other = dir.path().join("other-app");
    write_file(&registered, b"the app");
    write_file(&copy, b"the app");
    write_file(&other, b"another");
    proc.add_process(100, &other, 50);
    // The pid was reused by a process running a copy while exe was open.
    let mut env = fake_environment(&proc, 4242, 100, false);
    let (p, c) = (proc.clone(), copy.clone());
    env.after_exe_read = Some(Box::new(move || p.add_process(100, &c, 51)));
    assert!(denied(check(&registered, env)));
    // The content comes from the file opened inside the start time window,
    // not from a second look at /proc/<pid>/exe.
    proc.add_process(100, &other, 50);
    let mut env = fake_environment(&proc, 4242, 100, false);
    let (p, c) = (proc.clone(), copy.clone());
    env.after_exe_read = Some(Box::new(move || p.add_process(100, &c, 50)));
    assert!(denied(check(&registered, env)));
    // And the other way round: the copy that was open is accepted.
    proc.add_process(100, &copy, 50);
    let mut env = fake_environment(&proc, 4242, 100, false);
    env.after_exe_read = Some(Box::new(move || proc.add_process(100, &other, 50)));
    check(&registered, env).unwrap();
}

#[test]
fn pid_reuse() {
    let proc = FakeProc::new();
    let exe = this_exe();
    proc.add_process(100, &exe, 50);
    // The pid was reused while exe was read: another start time afterwards.
    let mut env = fake_environment(&proc, 4242, 100, false);
    let p = proc.clone();
    env.after_exe_read = Some(Box::new(move || p.set_start_time(100, 51)));
    assert_eq!(check(&exe, env).unwrap_err().message, "peer pid 100 was reused");
    // A process started after the check began cannot be the peer.
    proc.set_start_time(100, 200_000);
    assert_eq!(
        check(&exe, fake_environment(&proc, 4242, 100, false)).unwrap_err().message,
        "peer pid 100 was reused"
    );
    proc.set_start_time(100, 100_001);
    assert!(denied(check(&exe, fake_environment(&proc, 4242, 100, false))));
    proc.set_start_time(100, 100_000);
    check(&exe, fake_environment(&proc, 4242, 100, false)).unwrap();
    // Without a clock only the before/after comparison applies.
    proc.set_start_time(100, 200_000);
    let mut env = fake_environment(&proc, 4242, 100, false);
    env.boot_ticks_now = Box::new(|| None);
    check(&exe, env).unwrap();
}

#[test]
fn pidfd() {
    let proc = FakeProc::new();
    let exe = this_exe();
    proc.add_process(100, &exe, 50);
    // pidfd_open() path: the pidfd must still name pid 100 after the reads.
    let opened = Arc::new(AtomicI32::new(-1));
    let with_pidfd = |alive_pid: i32| {
        let mut env = fake_environment(&proc, 4242, 100, false);
        let o = Arc::clone(&opened);
        env.open_pidfd = Box::new(move |pid| {
            assert_eq!(pid, 100);
            let fd = dev_null();
            o.store(fd.as_raw_fd(), Ordering::SeqCst);
            Some(fd)
        });
        let (p, o) = (proc.clone(), Arc::clone(&opened));
        env.after_exe_read = Some(Box::new(move || p.set_pidfd(o.load(Ordering::SeqCst), alive_pid)));
        env
    };
    check(&exe, with_pidfd(100)).unwrap();
    // The process exited.
    assert_eq!(check(&exe, with_pidfd(-1)).unwrap_err().message, "peer process 100 exited during the check");
    // SO_PEERPIDFD: the pidfd from the credentials is used, pidfd_open is
    // not. A fresh /proc without its fdinfo: not alive.
    let proc = FakeProc::new();
    proc.add_process(100, &exe, 50);
    let mut env = fake_environment(&proc, 4242, 100, true);
    env.open_pidfd = Box::new(|_| panic!("pidfd_open must not be called"));
    assert!(denied(check(&exe, env)));
}

#[test]
fn real_process() {
    // The real /proc and SO_PEERCRED on a socketpair: this test process.
    let (a, _b) = socket();
    PeerChecker::new(this_exe()).check(a.as_fd()).unwrap();
    assert!(denied(PeerChecker::new("/bin/sh").check(a.as_fd())));
    // A copy at another inode (Sailjail's private-bin), through the real
    // /proc/self/exe.
    let dir = TempDir::new();
    let copy = dir.path().join("copy");
    std::fs::copy(this_exe(), &copy).unwrap();
    let checker = PeerChecker::new(&copy);
    assert_eq!(checker.executable(), copy.as_path());
    checker.check(a.as_fd()).unwrap();
    assert!(format!("{checker:?}").contains("proc_root"));
    assert_eq!(Environment::default().proc_root, Path::new("/proc"));
}

#[test]
fn proc_file_parsers() {
    assert_eq!(parse_start_time(b"1 (a) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 77 0\n"), Some(77));
    assert_eq!(parse_start_time(b"1 (a b) c) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 78\n"), Some(78));
    assert_eq!(parse_start_time(b"1 (a) S 0 0"), None);
    assert_eq!(parse_start_time(b"no parenthesis"), None);
    assert_eq!(parse_start_time(b"1 (a)"), None);
    assert_eq!(parse_start_time(b"1 (a) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 x 0"), None);
    assert_eq!(parse_fdinfo_pid(b"pos:\t0\nPid:\t42\n"), Some(42));
    assert_eq!(parse_fdinfo_pid(b"Pid:\t-1\n"), Some(-1));
    assert_eq!(parse_fdinfo_pid(b"pos:\t0\n"), None);
    assert_eq!(parse_fdinfo_pid(b"\xff"), None);
}

#[test]
fn uptime_in_ticks() {
    assert_eq!(uptime_ticks("12.29 5.00\n", 100), Some(1229));
    assert_eq!(uptime_ticks("12.5 1", 100), Some(1250));
    assert_eq!(uptime_ticks("12 1", 100), Some(1200));
    assert_eq!(uptime_ticks("0.50 1", 100), Some(50));
    assert_eq!(uptime_ticks("0 1", 100), Some(0));
    assert_eq!(uptime_ticks("1.1234567899 1", 1_000_000_000), Some(1_123_456_789));
    assert_eq!(uptime_ticks("1.000000001 1", 1_000_000_000), Some(1_000_000_001));
    assert_eq!(uptime_ticks("x.5 1", 100), None);
    assert_eq!(uptime_ticks("1.x 1", 100), None);
    assert_eq!(uptime_ticks("-1.5 1", 100), None);
    assert_eq!(uptime_ticks("1.-5 1", 100), None);
    assert_eq!(uptime_ticks("99999999999999999.5", 1000), None);
    let now = system_boot_ticks_now().unwrap();
    assert!(now > 0);
}

#[test]
fn chunked_reads() {
    let dir = TempDir::new();
    let path = dir.path().join("f");
    write_file(&path, &[7u8; 10]);
    let mut f = File::open(&path).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(read_fully(&mut f, &mut buf).unwrap(), 4);
    let mut big = [0u8; 16];
    assert_eq!(read_fully(&mut f, &mut big).unwrap(), 6);
    assert_eq!(read_fully(&mut f, &mut big).unwrap(), 0);
    assert_eq!(read_fully(&mut f, &mut []).unwrap(), 0);
    let folder = File::open(dir.path()).unwrap();
    assert!(!same_content(folder, File::open(&path).unwrap()));
    assert!(same_content(File::open(&path).unwrap(), File::open(&path).unwrap()));
}
