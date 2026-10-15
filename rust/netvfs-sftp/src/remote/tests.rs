// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects, reason = "tests")]

use super::*;
use crate::fake::{Action, Fake, Node, Rule};
use crate::proto::{
    Extension, FX_BAD_MESSAGE, FX_NO_SUCH_FILE, FX_OK, FX_PERMISSION_DENIED, FXF_TRUNC, FXP_ATTRS,
    FXP_EXTENDED, FXP_EXTENDED_REPLY, FXP_LSTAT, FXP_MKDIR, FXP_OPEN, FXP_OPENDIR, FXP_READDIR, FXP_READLINK,
    FXP_REALPATH, FXP_REMOVE, FXP_RENAME, FXP_RMDIR, FXP_SETSTAT, FXP_STAT, FXP_SYMLINK,
};

fn cancel() -> CancelToken {
    CancelToken::new()
}

fn err<T: std::fmt::Debug>(r: Result<T, Status>) -> (ErrorName, String) {
    let e = r.unwrap_err();
    (e.name, e.message)
}

fn named(name: ErrorName, message: &str) -> (ErrorName, String) {
    (name, message.to_owned())
}

/// Collects batches; stops after `stop_after` batches when given.
#[derive(Default)]
struct Collect {
    batches: Vec<Vec<Entry>>,
    stop_after: Option<usize>,
}

impl ListSink for Collect {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.batches.push(batch.to_vec());
        self.stop_after.is_none_or(|n| self.batches.len() < n)
    }
}

impl Collect {
    fn names(&self) -> Vec<String> {
        self.batches.iter().flatten().map(|e| display(&e.name)).collect()
    }
}

fn base_capabilities() -> BTreeSet<Capability> {
    [
        Capability::ReadHandles,
        Capability::EfficientRanges,
        Capability::WriteResume,
        Capability::PosixModes,
        Capability::SetModified,
        Capability::SetModifiedOnUpload,
        Capability::Symlinks,
        Capability::NativeNoReplace,
    ]
    .into()
}

fn version(extensions: &[(&str, &str)]) -> ServerVersion {
    ServerVersion {
        version: 3,
        extensions: extensions
            .iter()
            .map(|(n, d)| Extension { name: n.as_bytes().to_vec(), data: d.as_bytes().to_vec() })
            .collect(),
    }
}

/// Waits until the server holds no open handle (CLOSE may be detached).
async fn no_open_handles(fake: &Fake) {
    for _ in 0..500 {
        if fake.open_handles() == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("{} handles stay open", fake.open_handles());
}

#[test]
fn extensions_need_their_version() {
    let all = Extensions::of(&version(&crate::fake::ALL_EXTENSIONS));
    assert_eq!(
        all,
        Extensions {
            posix_rename: true,
            statvfs: true,
            fsync: true,
            hardlink: true,
            limits: true,
            users_groups: true,
            copy_data: true
        }
    );
    let wrong = Extensions::of(&version(&[
        ("posix-rename@openssh.com", "2"),
        ("statvfs@openssh.com", "1"),
        ("fsync@openssh.com", "2"),
        ("hardlink@openssh.com", ""),
        ("limits@openssh.com", "2"),
        ("users-groups-by-id@openssh.com", "0"),
        ("copy-data", "2"),
    ]));
    assert_eq!(wrong, Extensions::default());
}

#[test]
fn chunks_follow_the_limits() {
    assert_eq!(chunk(None), FALLBACK_CHUNK);
    assert_eq!(chunk(Some(0)), FALLBACK_CHUNK);
    assert_eq!(chunk(Some(1)), 1);
    assert_eq!(chunk(Some(u64::from(MAX_CHUNK))), MAX_CHUNK);
    assert_eq!(chunk(Some(u64::from(MAX_CHUNK) + 1)), MAX_CHUNK);
    assert_eq!(chunk(Some(u64::MAX)), MAX_CHUNK);
}

#[test]
fn entries_from_attributes() {
    let attrs = Attrs {
        size: Some(12),
        ids: Some((1000, 100)),
        permissions: Some(0o104_755),
        times: Some((1_700_000_000, 1_600_000_000)),
    };
    let e = entry_from(&attrs, b"f");
    assert_eq!(e.kind, EntryType::File);
    assert_eq!(e.mode, Some(0o4755));
    assert_eq!(e.size, Some(12));
    assert_eq!(e.atime_ms, Some(1_700_000_000_000));
    assert_eq!(e.mtime_ms, Some(1_600_000_000_000));
    assert_eq!((e.uid, e.gid), (Some(1000), Some(100)));
    assert_eq!(e.flags, EntryFlags::NONE);
    assert_eq!(e.ctime_ms, None);

    let kinds = [
        (Some(0o040_755), EntryType::Directory),
        (Some(0o120_777), EntryType::Symlink),
        (Some(0o020_644), EntryType::Special),
        (Some(0o060_644), EntryType::Special),
        (Some(0o010_644), EntryType::Special),
        (Some(0o140_644), EntryType::Special),
        (Some(0o644), EntryType::Unknown),
        (None, EntryType::Unknown),
    ];
    for (mode, kind) in kinds {
        assert_eq!(kind_of(&Attrs { permissions: mode, ..Attrs::default() }), kind, "{mode:?}");
    }
    let bare = entry_from(&Attrs::default(), b"caf\xe9");
    assert_eq!(bare.flags, EntryFlags::NAME_NOT_UTF8);
    assert_eq!((bare.mode, bare.size, bare.mtime_ms, bare.uid), (None, None, None, None));
}

#[test]
fn attribute_checks() {
    check_attributes(&Attributes::default()).unwrap();
    check_attributes(&Attributes {
        mode: Some(0o7777),
        mtime_ms: Some(0),
        atime_ms: Some(4_294_967_295_999),
    })
    .unwrap();
    assert_eq!(
        err(check_attributes(&Attributes { mode: Some(0o10_000), ..Attributes::default() })),
        named(ErrorName::Internal, "Invalid mode 10000")
    );
    let times = named(ErrorName::Internal, "SFTP cannot store times before 1970 or after 2106");
    for ms in [-1000, 4_294_967_296_000, i64::MIN] {
        assert_eq!(err(check_attributes(&Attributes { mtime_ms: Some(ms), ..Attributes::default() })), times);
        assert_eq!(err(check_attributes(&Attributes { atime_ms: Some(ms), ..Attributes::default() })), times);
    }
    // Less than a second before 1970 rounds to 0.
    check_attributes(&Attributes { mtime_ms: Some(-999), ..Attributes::default() }).unwrap();
}

#[test]
fn space_in_bytes() {
    let s = Statvfs { bsize: 4096, frsize: 1024, blocks: 100, bfree: 40, bavail: 30 };
    assert_eq!(space_from(&s), SpaceInfo { free: Some(30_720), total: Some(102_400), used: Some(61_440) });
    let s = Statvfs { bsize: 512, frsize: 0, blocks: 10, bfree: 11, bavail: 1 };
    assert_eq!(space_from(&s), SpaceInfo { free: Some(512), total: Some(5120), used: None });
    let s = Statvfs { bsize: 0, frsize: u64::MAX, blocks: 2, bfree: 0, bavail: 2 };
    let max = i64::MAX.unsigned_abs();
    assert_eq!(space_from(&s), SpaceInfo { free: Some(max), total: Some(max), used: Some(max) });
}

#[tokio::test]
async fn new_learns_limits_home_and_owners() {
    let fake = Fake::new();
    fake.state().limits.max_read = 70_000;
    fake.state().limits.max_write = 1_000_000;
    let remote = fake.remote().await;
    assert_eq!(remote.chunks(), Chunks { read: 70_000, write: MAX_CHUNK });
    assert_eq!(remote.home(), b"/home/u");
    assert_eq!(remote.extensions(), &Extensions::of(&version(&crate::fake::ALL_EXTENSIONS)));
    let mut all = base_capabilities();
    all.extend([
        Capability::Hardlinks,
        Capability::Ownership,
        Capability::SpaceInfo,
        Capability::AtomicReplace,
        Capability::ServerCopy,
    ]);
    assert_eq!(remote.capabilities().flags, all);
    assert_eq!(remote.capabilities().checksum_algorithms, Vec::<String>::new());
    assert_eq!(fake.kinds(), ["limits@openssh.com", "REALPATH", "STAT", "users-groups-by-id@openssh.com"]);
    assert_eq!(fake.requests(FXP_REALPATH)[0].strings, [b".".to_vec()]);
    assert_eq!(fake.requests(FXP_STAT)[0].strings, [b"/home/u".to_vec()]);
    let owners = &fake.requests(FXP_EXTENDED)[1].strings;
    assert_eq!(owners, &[1000u32.to_be_bytes().to_vec(), 100u32.to_be_bytes().to_vec()]);
}

#[tokio::test]
async fn without_extensions_only_the_base_capabilities() {
    let fake = Fake::new().with_extensions(&[]);
    let remote = fake.remote().await;
    assert_eq!(remote.chunks(), Chunks { read: FALLBACK_CHUNK, write: FALLBACK_CHUNK });
    assert_eq!(remote.capabilities().flags, base_capabilities());
    assert_eq!(fake.kinds(), ["REALPATH"]);
}

#[tokio::test]
async fn new_fails_on_a_broken_limits_reply_and_a_lost_connection() {
    let fake = Fake::new();
    fake.rule(Rule::ext("limits@openssh.com", Action::Status(FX_FAILURE, "no")));
    let (client, v) = fake.client().await;
    let e = Remote::new(client, &v, 0o755, &cancel()).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::ProtocolError, "limits: no"));

    let fake = Fake::new();
    fake.rule(Rule::new(FXP_REALPATH, Action::Hangup));
    let (client, v) = fake.client().await;
    let e = Remote::new(client, &v, 0o755, &cancel()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);

    let fake = Fake::new();
    let (client, v) = fake.client().await;
    let c = cancel();
    c.cancel();
    let e = Remote::new(client, &v, 0o755, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
}

#[tokio::test]
async fn a_server_without_a_start_folder_resolves_against_its_own() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_REALPATH, Action::Status(FX_FAILURE, "no")));
    fake.file("/home/u/f", b"x");
    let mut remote = fake.remote().await;
    assert_eq!(remote.home(), b"");
    assert_eq!(remote.resolve(b"").unwrap(), b".");
    assert_eq!(remote.resolve(b"f").unwrap(), b"f");
    // Ownership is still detected, with `.` for the start folder.
    assert!(remote.capabilities().has(Capability::Ownership));
    assert_eq!(fake.requests(FXP_STAT)[0].strings, [b".".to_vec()]);
    assert_eq!(remote.stat(b"f", true, &cancel()).await.unwrap().size, Some(1));
    assert_eq!(fake.requests(FXP_STAT)[1].strings, [b"f".to_vec()]);
}

#[tokio::test]
async fn owners_are_named_once_per_id() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"");
    let mut remote = fake.remote().await;
    let a = remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!((a.owner.as_str(), a.group.as_str()), ("alice", "users"));
    // Known from the start folder: no further request.
    assert_eq!(fake.requests(FXP_EXTENDED).len(), 2);

    fake.state().uid = 2000;
    fake.state().users.insert(2000, "bob");
    let b = remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!((b.owner.as_str(), b.group.as_str()), ("bob", "users"));
    let asked = fake.requests(FXP_EXTENDED);
    assert_eq!(asked.len(), 3);
    // Only the unknown uid; no gid.
    assert_eq!(asked[2].strings, [2000u32.to_be_bytes().to_vec(), Vec::new()]);
    remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!(fake.requests(FXP_EXTENDED).len(), 3);

    // An id without a name stays unnamed, and is not asked for again.
    fake.state().uid = 3000;
    let c = remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!((c.owner.as_str(), c.uid), ("", Some(3000)));
    remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!(fake.requests(FXP_EXTENDED).len(), 4);
}

#[tokio::test]
async fn the_owner_cache_is_bounded() {
    let mut cache = HashMap::new();
    let ids: Vec<u32> = (0..u32::try_from(MAX_CACHED_NAMES).unwrap()).collect();
    let (last, ids) = ids.split_last().unwrap();
    remember(&mut cache, ids, ids.iter().map(|i| i.to_string().into_bytes()).collect());
    assert_eq!(cache.len(), ids.len());
    // The one that fills it to the bound joins the others.
    remember(&mut cache, &[*last], vec![last.to_string().into_bytes()]);
    assert_eq!(cache.len(), MAX_CACHED_NAMES);
    assert_eq!(cache[&7], "7");
    remember(&mut cache, &[99_999], vec![b"x\xff".to_vec()]);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache[&99_999], "x\u{fffd}");
}

#[tokio::test]
async fn no_ownership_when_the_names_cannot_be_had() {
    let fake = Fake::new();
    fake.rule(Rule::ext("users-groups-by-id@openssh.com", Action::Status(FX_FAILURE, "no")));
    fake.file("/home/u/a", b"");
    let mut remote = fake.remote().await;
    assert!(!remote.capabilities().has(Capability::Ownership));
    let a = remote.stat(b"a", true, &cancel()).await.unwrap();
    assert_eq!((a.owner.as_str(), a.uid), ("", Some(1000)));
    assert_eq!(fake.requests(FXP_EXTENDED).len(), 2);

    // A malformed answer counts as none.
    let fake = Fake::new();
    fake.rule(Rule::ext(
        "users-groups-by-id@openssh.com",
        Action::Reply(FXP_EXTENDED_REPLY, vec![0, 0, 0, 9]),
    ));
    assert!(!fake.remote().await.capabilities().has(Capability::Ownership));
}

#[tokio::test]
async fn stat_and_lstat() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"12345");
    fake.link("/home/u/l", "f");
    fake.link("/home/u/dangling", "nowhere");
    let mut remote = fake.remote().await;
    let c = cancel();
    let f = remote.stat(b"l", true, &c).await.unwrap();
    assert_eq!(
        (f.name.as_slice(), f.kind, f.size, f.mode),
        (&b"l"[..], EntryType::File, Some(5), Some(0o644))
    );
    assert_eq!((f.mtime_ms, f.atime_ms), (Some(2_000_000), Some(1_500_000)));
    let l = remote.stat(b"/home/u/l", false, &c).await.unwrap();
    assert_eq!((l.kind, l.size), (EntryType::Symlink, Some(1)));
    assert_eq!(fake.requests(FXP_LSTAT)[0].strings, [b"/home/u/l".to_vec()]);
    assert_eq!(
        err(remote.stat(b"dangling", true, &c).await),
        named(ErrorName::NotFound, "/home/u/dangling: not found")
    );
    assert_eq!(remote.stat(b"dangling", false, &c).await.unwrap().kind, EntryType::Symlink);
    assert_eq!(err(remote.stat(b"a/../b", true, &c).await).0, ErrorName::InvalidName);
    // LSTAT alone tells a link.
    assert_eq!(fake.requests(FXP_READLINK), []);
}

#[tokio::test]
async fn list_in_batches_without_dots() {
    let fake = Fake::new();
    fake.state().batch = 3;
    for name in ["a", "b", "c", "d", "e"] {
        fake.file(&format!("/home/u/d/{name}"), name.as_bytes());
    }
    fake.dir("/home/u/d");
    fake.dir("/home/u/d/sub");
    fake.file("/home/u/d/sub/deeper", b"");
    let mut remote = fake.remote().await;
    let mut sink = Collect::default();
    remote
        .list(b"d", ListOptions { batch_size: 2, resolve_symlink_types: false }, &mut sink, &cancel())
        .await
        .unwrap();
    assert_eq!(sink.names(), ["a", "b", "c", "d", "e", "sub"]);
    // The server sends ".", "..", "a" | "b", "c", "d" | "e", "sub": a
    // batch never waits for the next reply, and holds at most 2.
    let sizes: Vec<usize> = sink.batches.iter().map(Vec::len).collect();
    assert_eq!(sizes, [1, 2, 1, 2]);
    let sub = &sink.batches[3][1];
    assert_eq!((sub.kind, sub.owner.as_str(), sub.group.as_str()), (EntryType::Directory, "alice", "users"));
    assert_eq!(fake.requests(FXP_OPENDIR)[0].strings, [b"/home/u/d".to_vec()]);
    assert_eq!(fake.requests(FXP_READDIR).len(), 4);
    assert_eq!(fake.open_handles(), 0);

    let mut sink = Collect::default();
    remote
        .list(b"d", ListOptions { batch_size: 0, resolve_symlink_types: false }, &mut sink, &cancel())
        .await
        .unwrap();
    assert_eq!(sink.batches.len(), 6, "batch size 0 counts as 1");
}

#[tokio::test]
async fn list_resolves_symlink_targets_on_request() {
    let fake = Fake::new();
    fake.dir("/home/u/d");
    fake.dir("/home/u/d/sub");
    fake.link("/home/u/d/to-dir", "sub");
    fake.link("/home/u/d/to-file", "/home/u/f");
    fake.link("/home/u/d/dangling", "nowhere");
    fake.file("/home/u/f", b"");
    let mut remote = fake.remote().await;
    let options = ListOptions { batch_size: 100, resolve_symlink_types: true };
    let mut sink = Collect::default();
    remote.list(b"d", options, &mut sink, &cancel()).await.unwrap();
    let got: Vec<(String, EntryType, EntryType, EntryFlags)> = sink
        .batches
        .concat()
        .into_iter()
        .map(|e| (display(&e.name), e.kind, e.target_kind, e.flags))
        .collect();
    assert_eq!(
        got,
        [
            ("dangling".to_owned(), EntryType::Symlink, EntryType::Unknown, EntryFlags::TARGET_UNKNOWN),
            ("sub".to_owned(), EntryType::Directory, EntryType::Unknown, EntryFlags::NONE),
            ("to-dir".to_owned(), EntryType::Symlink, EntryType::Directory, EntryFlags::NONE),
            ("to-file".to_owned(), EntryType::Symlink, EntryType::File, EntryFlags::NONE),
        ]
    );
    let stats: Vec<Vec<u8>> =
        fake.requests(FXP_STAT).into_iter().skip(1).map(|l| l.strings[0].clone()).collect();
    assert_eq!(
        stats,
        [b"/home/u/d/dangling".to_vec(), b"/home/u/d/to-dir".to_vec(), b"/home/u/d/to-file".to_vec()]
    );

    // Without the option nothing is stat'ed.
    let before = fake.requests(FXP_STAT).len();
    let mut sink = Collect::default();
    remote.list(b"d", ListOptions::default(), &mut sink, &cancel()).await.unwrap();
    assert_eq!(fake.requests(FXP_STAT).len(), before);
    assert!(
        sink.batches
            .concat()
            .iter()
            .all(|e| e.target_kind == EntryType::Unknown && e.flags == EntryFlags::NONE)
    );
}

#[tokio::test]
async fn list_resolves_at_most_512_targets() {
    let fake = Fake::new();
    fake.dir("/home/u/d");
    fake.file("/home/u/f", b"");
    for i in 0..=MAX_SYMLINK_RESOLUTIONS {
        fake.link(&format!("/home/u/d/l{i:04}"), "/home/u/f");
    }
    let mut remote = fake.remote().await;
    let mut sink = Collect::default();
    let options = ListOptions { batch_size: 1000, resolve_symlink_types: true };
    remote.list(b"d", options, &mut sink, &cancel()).await.unwrap();
    let entries = sink.batches.concat();
    assert_eq!(entries.len(), 513);
    assert!(entries[..512].iter().all(|e| e.target_kind == EntryType::File && e.flags == EntryFlags::NONE));
    assert_eq!(
        (entries[512].target_kind, entries[512].flags),
        (EntryType::Unknown, EntryFlags::TARGET_UNKNOWN)
    );
    assert_eq!(fake.requests(FXP_STAT).len(), 1 + 512);
}

#[tokio::test]
async fn list_stops_when_the_sink_says_so() {
    let fake = Fake::new();
    fake.state().batch = 2;
    fake.dir("/home/u/d");
    for name in ["a", "b", "c", "d", "e"] {
        fake.file(&format!("/home/u/d/{name}"), b"");
    }
    let mut remote = fake.remote().await;
    let mut sink = Collect { stop_after: Some(1), ..Collect::default() };
    let options = ListOptions { batch_size: 1, resolve_symlink_types: false };
    let e = remote.list(b"d", options, &mut sink, &cancel()).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Canceled, "The listing was stopped"));
    assert_eq!(sink.names(), ["a"]);
    assert_eq!(fake.requests(FXP_READDIR).len(), 2);
    no_open_handles(&fake).await;
}

#[tokio::test]
async fn list_failures() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    fake.dir("/home/u/d");
    let mut remote = fake.remote().await;
    let c = cancel();
    let mut sink = Collect::default();
    assert_eq!(
        err(remote.list(b"f", ListOptions::default(), &mut sink, &c).await),
        named(ErrorName::NotADirectory, "/home/u/f is not a folder")
    );
    assert_eq!(
        err(remote.list(b"missing", ListOptions::default(), &mut sink, &c).await),
        named(ErrorName::NotFound, "/home/u/missing: not found")
    );
    fake.rule(Rule::new(FXP_READDIR, Action::Status(FX_PERMISSION_DENIED, "denied")).once());
    assert_eq!(
        err(remote.list(b"d", ListOptions::default(), &mut sink, &c).await),
        named(ErrorName::PermissionDenied, "/home/u/d: permission denied")
    );
    no_open_handles(&fake).await;
    // A lost connection is not followed by a STAT.
    fake.rule(Rule::new(FXP_OPENDIR, Action::Hangup));
    let stats = fake.requests(FXP_STAT).len();
    assert_eq!(
        err(remote.list(b"f", ListOptions::default(), &mut sink, &c).await).0,
        ErrorName::ConnectionLost
    );
    assert_eq!(fake.requests(FXP_STAT).len(), stats);
    assert_eq!(sink.batches.len(), 0);
}

struct CancelOnFirst(CancelToken);

impl ListSink for CancelOnFirst {
    fn entries(&mut self, _: &[Entry]) -> bool {
        self.0.cancel();
        true
    }
}

#[tokio::test]
async fn list_is_canceled_between_replies() {
    let fake = Fake::new();
    fake.dir("/home/u/d");
    let mut remote = fake.remote().await;
    let c = cancel();
    fake.file("/home/u/d/a", b"");
    let e = remote.list(b"d", ListOptions::default(), &mut CancelOnFirst(c.clone()), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(fake.requests(FXP_READDIR).len(), 1);
}

#[tokio::test]
async fn make_dir() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.make_dir(b"new", false, &c).await.unwrap();
    assert_eq!(fake.node("/home/u/new"), Some(Node::Dir { mode: 0o750, mtime: 7000 }));
    assert_eq!(
        fake.requests(FXP_MKDIR)[0].attrs,
        Some(Attrs { permissions: Some(0o750), ..Attrs::default() })
    );
    remote.make_dir(b"new", false, &c).await.unwrap();
    assert_eq!(
        err(remote.make_dir(b"new", true, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/new exists")
    );
    assert_eq!(
        err(remote.make_dir(b"f", false, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/f exists and is not a folder")
    );
    assert_eq!(
        err(remote.make_dir(b"f", true, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/f exists")
    );
    assert_eq!(
        err(remote.make_dir(b"no/sub", false, &c).await),
        named(ErrorName::NotFound, "/home/u/no/sub: not found")
    );
    // A failure that leaves nothing there is reported as it is.
    fake.rule(Rule::new(FXP_MKDIR, Action::Status(FX_FAILURE, "quota")).once());
    assert_eq!(
        err(remote.make_dir(b"other", false, &c).await),
        named(ErrorName::ProtocolError, "/home/u/other: quota")
    );
}

#[tokio::test]
async fn remove_file() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    fake.dir("/home/u/d");
    fake.link("/home/u/l", "d");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.remove_file(b"f", &c).await.unwrap();
    assert_eq!(fake.node("/home/u/f"), None);
    // A link to a folder is removed, not its target.
    remote.remove_file(b"l", &c).await.unwrap();
    assert_eq!(fake.node("/home/u/l"), None);
    assert!(fake.node("/home/u/d").is_some());
    assert_eq!(
        err(remote.remove_file(b"d", &c).await),
        named(ErrorName::IsADirectory, "/home/u/d is a folder")
    );
    assert_eq!(err(remote.remove_file(b"f", &c).await), named(ErrorName::NotFound, "/home/u/f: not found"));
    fake.rule(Rule::new(FXP_REMOVE, Action::Hangup));
    let before = fake.requests(FXP_LSTAT).len();
    assert_eq!(err(remote.remove_file(b"d", &c).await).0, ErrorName::ConnectionLost);
    assert_eq!(fake.requests(FXP_LSTAT).len(), before);
}

#[tokio::test]
async fn no_follow_up_request_after_a_timeout() {
    let fake = Fake::new();
    fake.dir("/home/u/d");
    let c = cancel();
    let (stream, _task) = fake.connect();
    let (r, w) = tokio::io::split(stream);
    let (client, version) =
        Client::start(r, w, async {}, std::time::Duration::from_millis(100), &c).await.unwrap();
    let mut remote = Remote::new(client, &version, 0o750, &c).await.unwrap();
    fake.rule(Rule::new(FXP_REMOVE, Action::Delay(std::time::Duration::from_millis(300))).once());
    let before = fake.requests(FXP_LSTAT).len();
    assert_eq!(err(remote.remove_file(b"d", &c).await).0, ErrorName::Timeout);
    assert_eq!(fake.requests(FXP_LSTAT).len(), before);
}

#[tokio::test]
async fn remove_dir() {
    let fake = Fake::new();
    fake.dir("/home/u/empty");
    fake.dir("/home/u/full");
    fake.file("/home/u/full/x", b"");
    fake.file("/home/u/f", b"");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.remove_dir(b"empty", &c).await.unwrap();
    assert_eq!(fake.node("/home/u/empty"), None);
    assert_eq!(
        err(remote.remove_dir(b"full", &c).await),
        named(ErrorName::DirectoryNotEmpty, "/home/u/full is not empty")
    );
    no_open_handles(&fake).await;
    assert_eq!(
        err(remote.remove_dir(b"f", &c).await),
        named(ErrorName::NotADirectory, "/home/u/f is not a folder")
    );
    assert_eq!(
        err(remote.remove_dir(b"empty", &c).await),
        named(ErrorName::NotFound, "/home/u/empty: not found")
    );
    // Permission denied is not looked into.
    fake.rule(Rule::new(FXP_RMDIR, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    let opened = fake.requests(FXP_OPENDIR).len();
    assert_eq!(
        err(remote.remove_dir(b"full", &c).await),
        named(ErrorName::PermissionDenied, "/home/u/full: permission denied")
    );
    assert_eq!(fake.requests(FXP_OPENDIR).len(), opened);
    // An empty folder that still fails keeps the server's failure.
    fake.dir("/home/u/busy");
    fake.rule(Rule::new(FXP_RMDIR, Action::Status(FX_FAILURE, "Device or resource busy")).once());
    assert_eq!(
        err(remote.remove_dir(b"busy", &c).await),
        named(ErrorName::ProtocolError, "/home/u/busy: Device or resource busy")
    );
    no_open_handles(&fake).await;
}

#[tokio::test]
async fn rename_without_replacing() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"A");
    fake.file("/home/u/b", b"B");
    let mut remote = fake.remote().await;
    let c = cancel();
    let lstats = fake.requests(FXP_LSTAT).len();
    assert_eq!(
        err(remote.rename(b"a", b"b", RenameMode::NoReplace, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/b exists")
    );
    // NativeNoReplace: RENAME first, the LSTAT only explains its failure.
    assert_eq!(fake.requests(FXP_RENAME).len(), 1);
    assert_eq!(fake.requests(FXP_LSTAT).len(), lstats + 1);
    assert_eq!(fake.data("/home/u/b"), Some(b"B".to_vec()));
    remote.rename(b"a", b"c", RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!((fake.data("/home/u/a"), fake.data("/home/u/c")), (None, Some(b"A".to_vec())));
    assert_eq!(fake.requests(FXP_RENAME)[1].strings, [b"/home/u/a".to_vec(), b"/home/u/c".to_vec()]);
    assert_eq!(fake.requests(FXP_LSTAT).len(), lstats + 1);
    assert_eq!(
        err(remote.rename(b"a", b"d", RenameMode::NoReplace, &c).await),
        named(ErrorName::NotFound, "/home/u/a: not found")
    );
    // A failure with nothing at the target stays as it is.
    fake.rule(Rule::new(FXP_RENAME, Action::Status(FX_FAILURE, "cross-device")).once());
    assert_eq!(
        err(remote.rename(b"c", b"e", RenameMode::NoReplace, &c).await),
        named(ErrorName::ProtocolError, "/home/u/c: cross-device")
    );
}

#[tokio::test]
async fn rename_replacing_with_posix_rename() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"A");
    fake.file("/home/u/b", b"B");
    fake.dir("/home/u/d");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.rename(b"a", b"b", RenameMode::Replace, &c).await.unwrap();
    assert_eq!((fake.data("/home/u/a"), fake.data("/home/u/b")), (None, Some(b"A".to_vec())));
    let posix: Vec<_> =
        fake.requests(FXP_EXTENDED).into_iter().filter(|l| l.ext == "posix-rename@openssh.com").collect();
    assert_eq!(posix[0].strings, [b"/home/u/a".to_vec(), b"/home/u/b".to_vec()]);
    assert_eq!(fake.requests(FXP_REMOVE), []);
    assert_eq!(fake.requests(FXP_RENAME), []);
    assert_eq!(
        err(remote.rename(b"b", b"d", RenameMode::Replace, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/d is a folder")
    );
    // The same path is left alone.
    remote.rename(b"b", b"/home/u/b", RenameMode::Replace, &c).await.unwrap();
    assert_eq!(fake.data("/home/u/b"), Some(b"A".to_vec()));
    // A new name needs no target.
    remote.rename(b"b", b"n", RenameMode::Replace, &c).await.unwrap();
    assert_eq!(fake.data("/home/u/n"), Some(b"A".to_vec()));
    assert_eq!(
        err(remote.rename(b"b", b"n", RenameMode::Replace, &c).await),
        named(ErrorName::NotFound, "/home/u/b: not found")
    );
    // A target the server will not show: its answer, nothing renamed.
    fake.rule(Rule::new(FXP_LSTAT, Action::Status(FX_PERMISSION_DENIED, "no")).on("/home/u/x").once());
    assert_eq!(
        err(remote.rename(b"n", b"x", RenameMode::Replace, &c).await),
        named(ErrorName::PermissionDenied, "/home/u/x: permission denied")
    );
    assert_eq!(fake.data("/home/u/n"), Some(b"A".to_vec()));
    assert_eq!(fake.node("/home/u/x"), None);
}

#[tokio::test]
async fn rename_replacing_a_hard_link_of_the_same_file_leaves_one_name() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"A");
    fake.file("/home/u/b", b"A");
    // rename(2) of two links of one file succeeds and changes nothing.
    fake.rule(Rule::ext("posix-rename@openssh.com", Action::Status(FX_OK, "")).once());
    let mut remote = fake.remote().await;
    remote.rename(b"a", b"b", RenameMode::Replace, &cancel()).await.unwrap();
    assert_eq!((fake.node("/home/u/a"), fake.data("/home/u/b")), (None, Some(b"A".to_vec())));
    assert_eq!(fake.requests(FXP_REMOVE)[0].strings, [b"/home/u/a".to_vec()]);
}

#[tokio::test]
async fn rename_replacing_without_posix_rename_removes_first() {
    let fake = Fake::new().with_extensions(&[]);
    fake.file("/home/u/a", b"A");
    fake.file("/home/u/b", b"B");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.rename(b"a", b"b", RenameMode::Replace, &c).await.unwrap();
    assert_eq!((fake.data("/home/u/a"), fake.data("/home/u/b")), (None, Some(b"A".to_vec())));
    assert_eq!(fake.kinds()[1..], ["LSTAT", "REMOVE", "RENAME"]);
    fake.take_log();
    remote.rename(b"b", b"c", RenameMode::Replace, &c).await.unwrap();
    assert_eq!(fake.kinds(), ["LSTAT", "RENAME"]);
    // A failed REMOVE stops the rename.
    fake.file("/home/u/d", b"D");
    fake.rule(Rule::new(FXP_REMOVE, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    assert_eq!(
        err(remote.rename(b"c", b"d", RenameMode::Replace, &c).await),
        named(ErrorName::PermissionDenied, "/home/u/d: permission denied")
    );
    assert_eq!(fake.data("/home/u/c"), Some(b"A".to_vec()));
}

#[tokio::test]
async fn set_attributes() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    let mut remote = fake.remote().await;
    let c = cancel();
    fake.take_log();
    // Checked before anything is sent.
    let bad = Attributes { mode: Some(0o170_644), mtime_ms: Some(1000), atime_ms: None };
    assert_eq!(
        err(remote.set_attributes(b"f", &bad, &c).await),
        named(ErrorName::Internal, "Invalid mode 170644")
    );
    assert_eq!(fake.kinds(), Vec::<String>::new());
    // Nothing to change: the entry must exist.
    remote.set_attributes(b"f", &Attributes::default(), &c).await.unwrap();
    assert_eq!(err(remote.set_attributes(b"g", &Attributes::default(), &c).await).0, ErrorName::NotFound);
    assert_eq!(fake.kinds(), ["STAT", "STAT"]);
    fake.take_log();

    remote
        .set_attributes(b"f", &Attributes { mode: Some(0o600), ..Attributes::default() }, &c)
        .await
        .unwrap();
    assert_eq!(
        fake.requests(FXP_SETSTAT)[0].attrs,
        Some(Attrs { permissions: Some(0o600), ..Attrs::default() })
    );
    assert_eq!(fake.kinds(), ["SETSTAT"]);
    fake.take_log();

    // One time keeps the other.
    remote
        .set_attributes(b"f", &Attributes { mtime_ms: Some(9_000_999), ..Attributes::default() }, &c)
        .await
        .unwrap();
    assert_eq!(fake.kinds(), ["STAT", "SETSTAT"]);
    assert_eq!(fake.requests(FXP_SETSTAT)[0].attrs.unwrap().times, Some((1500, 9000)));
    fake.take_log();
    remote
        .set_attributes(b"f", &Attributes { atime_ms: Some(42_000), ..Attributes::default() }, &c)
        .await
        .unwrap();
    assert_eq!(fake.requests(FXP_SETSTAT)[0].attrs.unwrap().times, Some((42, 9000)));
    fake.take_log();
    let both = Attributes { mode: Some(0o640), mtime_ms: Some(7000), atime_ms: Some(8000) };
    remote.set_attributes(b"f", &both, &c).await.unwrap();
    assert_eq!(fake.kinds(), ["SETSTAT"]);
    assert_eq!(
        fake.requests(FXP_SETSTAT)[0].attrs,
        Some(Attrs { permissions: Some(0o640), times: Some((8, 7)), ..Attrs::default() })
    );
    assert_eq!(
        fake.node("/home/u/f"),
        Some(Node::File { data: Vec::new(), mode: 0o640, mtime: 7, atime: 8 })
    );
    assert_eq!(
        err(remote
            .set_attributes(b"g", &Attributes { mtime_ms: Some(1), ..Attributes::default() }, &c)
            .await),
        named(ErrorName::NotFound, "/home/u/g: not found")
    );
}

#[tokio::test]
async fn set_times_without_a_known_time_uses_the_other() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    let remote = fake.remote().await;
    // The server reports no times.
    fake.rule(Rule::new(FXP_STAT, Action::Reply(FXP_ATTRS, vec![0, 0, 0, 0])).once());
    set_times(remote.client(), b"/home/u/f", Some(5000), None, Some(0o600), &cancel()).await.unwrap();
    let sent = fake.requests(FXP_SETSTAT)[0].attrs.unwrap();
    assert_eq!((sent.times, sent.permissions, sent.size), (Some((5, 5)), Some(0o600), None));
    fake.rule(Rule::new(FXP_STAT, Action::Reply(FXP_ATTRS, vec![0, 0, 0, 0])).once());
    set_times(remote.client(), b"/home/u/f", None, Some(7000), None, &cancel()).await.unwrap();
    assert_eq!(fake.requests(FXP_SETSTAT)[1].attrs.unwrap().times, Some((7, 7)));
    // Only the mode: no STAT, no times.
    let stats = fake.requests(FXP_STAT).len();
    set_times(remote.client(), b"/home/u/f", None, None, Some(0o644), &cancel()).await.unwrap();
    assert_eq!(fake.requests(FXP_STAT).len(), stats);
    assert_eq!(
        fake.requests(FXP_SETSTAT)[2].attrs,
        Some(Attrs { permissions: Some(0o644), ..Attrs::default() })
    );
}

#[tokio::test]
async fn read_link() {
    let fake = Fake::new();
    fake.link("/home/u/l", "../some/where");
    fake.file("/home/u/f", b"");
    let mut remote = fake.remote().await;
    let c = cancel();
    assert_eq!(remote.read_link(b"l", &c).await.unwrap(), b"../some/where");
    assert_eq!(
        err(remote.read_link(b"f", &c).await),
        named(ErrorName::InvalidName, "/home/u/f is not a symbolic link")
    );
    assert_eq!(err(remote.read_link(b"g", &c).await), named(ErrorName::NotFound, "/home/u/g: not found"));
    // A link the server cannot read keeps its failure.
    fake.rule(Rule::new(FXP_READLINK, Action::Status(FX_BAD_MESSAGE, "odd")).once());
    assert_eq!(err(remote.read_link(b"l", &c).await), named(ErrorName::ProtocolError, "/home/u/l: odd"));
}

#[tokio::test]
async fn make_symlink_sends_target_then_link() {
    let fake = Fake::new();
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.make_symlink(b"../t\xff", b"l", &c).await.unwrap();
    assert_eq!(fake.requests(FXP_SYMLINK)[0].strings, [b"../t\xff".to_vec(), b"/home/u/l".to_vec()]);
    assert_eq!(fake.node("/home/u/l"), Some(Node::Link { target: b"../t\xff".to_vec() }));
    assert_eq!(
        err(remote.make_symlink(b"x", b"l", &c).await),
        named(ErrorName::AlreadyExists, "/home/u/l exists")
    );
    for bad in [&b""[..], b"a\0b"] {
        assert_eq!(
            err(remote.make_symlink(bad, b"m", &c).await),
            named(ErrorName::InvalidName, "Invalid link target")
        );
    }
    assert_eq!(err(remote.make_symlink(b"x", b"..", &c).await).0, ErrorName::InvalidName);
    assert_eq!(fake.requests(FXP_SYMLINK).len(), 2);
    assert_eq!(
        err(remote.make_symlink(b"x", b"no/l", &c).await),
        named(ErrorName::NotFound, "/home/u/no/l: not found")
    );
}

#[tokio::test]
async fn make_hardlink() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"F");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.make_hardlink(b"f", b"g", &c).await.unwrap();
    assert_eq!(fake.data("/home/u/g"), Some(b"F".to_vec()));
    let sent = fake.requests(FXP_EXTENDED).into_iter().find(|l| l.ext == "hardlink@openssh.com").unwrap();
    assert_eq!(sent.strings, [b"/home/u/f".to_vec(), b"/home/u/g".to_vec()]);
    assert_eq!(
        err(remote.make_hardlink(b"f", b"g", &c).await),
        named(ErrorName::AlreadyExists, "/home/u/g exists")
    );
    assert_eq!(
        err(remote.make_hardlink(b"x", b"h", &c).await),
        named(ErrorName::NotFound, "/home/u/h: not found")
    );

    let fake = Fake::new().with_extensions(&[]);
    fake.file("/home/u/f", b"F");
    let mut remote = fake.remote().await;
    assert_eq!(
        err(remote.make_hardlink(b"f", b"g", &c).await),
        named(ErrorName::Unsupported, "The server cannot create hard links")
    );
    assert_eq!(fake.kinds(), ["REALPATH"]);
}

#[tokio::test]
async fn space_info() {
    let fake = Fake::new();
    let mut remote = fake.remote().await;
    let c = cancel();
    let space = remote.space_info(b"", &c).await.unwrap();
    assert_eq!(space, SpaceInfo { free: Some(500 * 4096), total: Some(1000 * 4096), used: Some(400 * 4096) });
    let sent = fake.requests(FXP_EXTENDED).into_iter().find(|l| l.ext == "statvfs@openssh.com").unwrap();
    assert_eq!(sent.strings, [b"/home/u".to_vec()]);
    assert_eq!(
        err(remote.space_info(b"none", &c).await),
        named(ErrorName::NotFound, "/home/u/none: not found")
    );
    fake.rule(Rule::ext("statvfs@openssh.com", Action::Reply(FXP_EXTENDED_REPLY, vec![1, 2, 3])).once());
    assert_eq!(
        err(remote.space_info(b"", &c).await),
        named(ErrorName::ProtocolError, "The server sent a malformed reply")
    );
    let fake = Fake::new().with_extensions(&[("limits@openssh.com", "1")]);
    let mut remote = fake.remote().await;
    assert_eq!(
        err(remote.space_info(b"", &c).await),
        named(ErrorName::Unsupported, "The server cannot report free space")
    );
}

#[tokio::test]
async fn write_failure_names_a_full_disk() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"");
    let remote = fake.remote().await;
    let c = cancel();
    let ext = *remote.extensions();
    let plain =
        Failure::Server(crate::proto::StatusReply { code: FX_FAILURE, message: "Failure".to_owned() });
    // 500 blocks of 4096 are free.
    let full = write_failure(remote.client(), &ext, b"/home/u/f", &plain, 500 * 4096 + 1, &c).await;
    assert_eq!(
        (full.name, full.message.as_str()),
        (ErrorName::NoSpace, "The server has no space left for /home/u/f")
    );
    let fits = write_failure(remote.client(), &ext, b"/home/u/f", &plain, 500 * 4096, &c).await;
    assert_eq!((fits.name, fits.message.as_str()), (ErrorName::ProtocolError, "/home/u/f: Failure"));
    let denied =
        Failure::Server(crate::proto::StatusReply { code: FX_PERMISSION_DENIED, message: String::new() });
    let asked = fake.requests(FXP_EXTENDED).len();
    assert_eq!(
        write_failure(remote.client(), &ext, b"/home/u/f", &denied, u64::MAX, &c).await.name,
        ErrorName::PermissionDenied
    );
    let without = Extensions { statvfs: false, ..ext };
    assert_eq!(
        write_failure(remote.client(), &without, b"/home/u/f", &plain, u64::MAX, &c).await.name,
        ErrorName::ProtocolError
    );
    let canceled = cancel();
    canceled.cancel();
    assert_eq!(
        write_failure(remote.client(), &ext, b"/home/u/f", &plain, u64::MAX, &canceled).await.name,
        ErrorName::ProtocolError
    );
    assert_eq!(fake.requests(FXP_EXTENDED).len(), asked);
    // statvfs failing keeps the write's failure.
    fake.rule(Rule::ext("statvfs@openssh.com", Action::Status(FX_FAILURE, "no")).once());
    assert_eq!(
        write_failure(remote.client(), &ext, b"/home/u/f", &plain, u64::MAX, &c).await.name,
        ErrorName::ProtocolError
    );
}

#[tokio::test]
async fn copy_with_copy_data() {
    let fake = Fake::new();
    fake.file("/home/u/src", b"0123456789");
    fake.state().nodes.insert(
        b"/home/u/src".to_vec(),
        Node::File { data: b"0123456789".to_vec(), mode: 0o4751, mtime: 1, atime: 1 },
    );
    fake.file("/home/u/longer", b"abcdefghijklmnopqrstuvwxyz");
    let mut remote = fake.remote().await;
    let c = cancel();
    remote.copy(b"src", b"new", false, RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!(fake.data("/home/u/new"), Some(b"0123456789".to_vec()));
    let opens = fake.requests(FXP_OPEN);
    assert_eq!(opens[0].pflags, Some(FXF_READ));
    assert_eq!(opens[1].pflags, Some(FXF_WRITE | FXF_CREAT | FXF_EXCL));
    // The permission bits without set-id bits.
    assert_eq!(opens[1].attrs, Some(Attrs { permissions: Some(0o751), ..Attrs::default() }));
    let copy = fake.requests(FXP_EXTENDED).into_iter().find(|l| l.ext == "copy-data").unwrap();
    assert_eq!(copy.offset, Some(0));
    assert_eq!(fake.requests(FXP_SETSTAT)[0].attrs, Some(Attrs { size: Some(10), ..Attrs::default() }));
    no_open_handles(&fake).await;

    assert_eq!(
        err(remote.copy(b"src", b"new", false, RenameMode::NoReplace, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/new exists")
    );
    // Replacing a longer file leaves the source's bytes only.
    remote.copy(b"src", b"longer", false, RenameMode::Replace, &c).await.unwrap();
    assert_eq!(fake.data("/home/u/longer"), Some(b"0123456789".to_vec()));
    assert_eq!(fake.requests(FXP_OPEN)[3].pflags, Some(FXF_WRITE | FXF_CREAT));
    assert!(fake.requests(FXP_OPEN).iter().all(|o| o.pflags.unwrap() & FXF_TRUNC == 0));
    // Onto itself: no truncation first, so the data stays.
    remote.copy(b"src", b"/home/u/src", false, RenameMode::Replace, &c).await.unwrap();
    assert_eq!(fake.data("/home/u/src"), Some(b"0123456789".to_vec()));
    no_open_handles(&fake).await;
}

#[tokio::test]
async fn copy_replaces_a_link_instead_of_writing_through_it() {
    let fake = Fake::new();
    fake.file("/home/u/src", b"S");
    fake.file("/home/u/other", b"O");
    fake.link("/home/u/l", "other");
    let mut remote = fake.remote().await;
    remote.copy(b"src", b"l", false, RenameMode::Replace, &cancel()).await.unwrap();
    assert_eq!(fake.data("/home/u/l"), Some(b"S".to_vec()));
    assert_eq!(fake.data("/home/u/other"), Some(b"O".to_vec()));
    assert_eq!(fake.requests(FXP_REMOVE)[0].strings, [b"/home/u/l".to_vec()]);
}

#[tokio::test]
async fn copy_refusals() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"F");
    fake.dir("/home/u/d");
    let mut remote = fake.remote().await;
    let c = cancel();
    assert_eq!(
        err(remote.copy(b"d", b"x", false, RenameMode::Replace, &c).await),
        named(ErrorName::IsADirectory, "/home/u/d is a folder")
    );
    assert_eq!(
        err(remote.copy(b"d", b"x", true, RenameMode::Replace, &c).await),
        named(ErrorName::Unsupported, "The server cannot copy folders")
    );
    assert_eq!(
        err(remote.copy(b"f", b"d", false, RenameMode::Replace, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/d is a folder")
    );
    assert_eq!(
        err(remote.copy(b"g", b"x", false, RenameMode::Replace, &c).await),
        named(ErrorName::NotFound, "/home/u/g: not found")
    );
    assert_eq!(
        err(remote.copy(b"f", b"no/x", false, RenameMode::Replace, &c).await),
        named(ErrorName::NotFound, "/home/u/no/x: not found")
    );
    fake.rule(Rule::new(FXP_LSTAT, Action::Status(FX_PERMISSION_DENIED, "no")).on("/home/u/y").once());
    assert_eq!(
        err(remote.copy(b"f", b"y", false, RenameMode::Replace, &c).await),
        named(ErrorName::PermissionDenied, "/home/u/y: permission denied")
    );
    assert_eq!(fake.node("/home/u/y"), None);
    assert!(fake.requests(FXP_EXTENDED).iter().all(|l| l.ext != "copy-data"));
    no_open_handles(&fake).await;

    let fake = Fake::new().with_extensions(&[]);
    fake.file("/home/u/f", b"F");
    let mut remote = fake.remote().await;
    assert_eq!(
        err(remote.copy(b"f", b"g", false, RenameMode::Replace, &c).await),
        named(ErrorName::Unsupported, "The server cannot copy files")
    );
    assert_eq!(fake.kinds(), ["REALPATH"]);
}

#[tokio::test]
async fn a_failed_copy_leaves_no_half_copy_behind() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"F");
    fake.file("/home/u/kept", b"K");
    fake.rule(Rule::ext("copy-data", Action::Status(FX_FAILURE, "disk")));
    let mut remote = fake.remote().await;
    let c = cancel();
    assert_eq!(
        err(remote.copy(b"f", b"new", false, RenameMode::NoReplace, &c).await),
        named(ErrorName::ProtocolError, "/home/u/new: disk")
    );
    assert_eq!(fake.node("/home/u/new"), None);
    // Replace: the target was there before; it is not removed.
    assert_eq!(
        err(remote.copy(b"f", b"kept", false, RenameMode::Replace, &c).await).0,
        ErrorName::ProtocolError
    );
    assert!(fake.node("/home/u/kept").is_some());
    no_open_handles(&fake).await;
    // An exclusive open that loses a race names the target.
    fake.state().rules.clear();
    fake.rule(Rule::new(FXP_OPEN, Action::Status(FX_FAILURE, "Failure")).on("/home/u/racy").once());
    fake.file("/home/u/racy", b"R");
    fake.rule(Rule::new(FXP_LSTAT, Action::Status(FX_NO_SUCH_FILE, "x")).on("/home/u/racy").once());
    assert_eq!(
        err(remote.copy(b"f", b"racy", false, RenameMode::NoReplace, &c).await),
        named(ErrorName::AlreadyExists, "/home/u/racy exists")
    );
    assert_eq!(fake.data("/home/u/racy"), Some(b"R".to_vec()));
    no_open_handles(&fake).await;
}
