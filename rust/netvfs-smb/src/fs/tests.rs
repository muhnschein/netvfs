// SPDX-License-Identifier: LGPL-2.1-or-later
use std::time::Duration;

use super::*;
use crate::fake::{self, FT, Peer, Req, chain as link, close_body, created_body, error, pair};
use crate::msg::flags;
use crate::wire::Writer;

const T: Duration = Duration::from_secs(5);
const TREE: Target = Target { tree_id: 3, encrypt: false };
const FID: FileId = [0x11; 16];
/// [`FT`] in ms.
const MS: i64 = 1_609_459_200_000;

async fn started() -> (Conn, Peer) {
    let (client, peer) = pair().await;
    let conn = Conn::start(client, T);
    conn.set_limits(1 << 20, true);
    conn.grant(64);
    (conn, peer)
}

/// The UTF-16 of `s`, for the life of the test process.
fn units(s: &str) -> &'static [u16] {
    Box::leak(s.encode_utf16().collect::<Vec<u16>>().into_boxed_slice())
}

fn set_info_body() -> Vec<u8> {
    vec![2, 0]
}

/// Answers a chain: one (status, body) per request, chained back.
async fn answer(peer: &mut Peer, reqs: &[Req], answers: Vec<(NtStatus, Vec<u8>)>) {
    assert_eq!(reqs.len(), answers.len());
    let msgs: Vec<Vec<u8>> = reqs
        .iter()
        .zip(answers)
        .map(|(r, (status, body))| {
            if status == NtStatus::SUCCESS || status == NtStatus::NO_MORE_FILES && !body.is_empty() {
                fake::response(r, status, &body, 1)
            } else {
                error(r, status, 1)
            }
        })
        .collect();
    peer.send(&link(msgs), false).await;
}

fn create_of(req: &Req) -> (u32, u32, u32, Vec<u16>) {
    let b = req.body();
    let access = u32::from_le_bytes(b[24..28].try_into().unwrap());
    let disposition = u32::from_le_bytes(b[36..40].try_into().unwrap());
    let options = u32::from_le_bytes(b[40..44].try_into().unwrap());
    let len = usize::from(u16::from_le_bytes(b[46..48].try_into().unwrap()));
    let name = b[56..56 + len].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    (access, disposition, options, name)
}

fn related_flags(reqs: &[Req]) -> Vec<bool> {
    reqs.iter().map(|r| r.header.flags & flags::RELATED_OPERATIONS != 0).collect()
}

#[tokio::test]
async fn stat_is_one_compound_round_trip() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, mut peer) = tokio::join!(stat(&conn, TREE, units(r"a\b"), &c), async {
        let reqs = peer.recv().await;
        let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
        assert_eq!(cmds, [Command::Create, Command::Close]);
        assert_eq!(related_flags(&reqs), [false, true]);
        assert_eq!(create_of(&reqs[0]), (0x0010_0080, 1, 0, units(r"a\b").to_vec()));
        assert_eq!(&reqs[1].body()[8..24], &RELATED_FILE_ID);
        assert!(reqs.iter().all(|r| r.header.tree_id == 3));
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x21, 42, FID)), (NtStatus::SUCCESS, close_body())],
        )
        .await;
        peer
    });
    let info = r.unwrap();
    assert_eq!((info.size, info.attributes, info.is_dir()), (42, 0x21, false));
    let e = info.entry(b"b".to_vec());
    assert_eq!(
        (e.kind, e.size, e.mtime_ms, e.atime_ms, e.ctime_ms),
        (EntryType::File, Some(42), Some(MS), Some(MS + 2), Some(MS + 1))
    );
    assert_eq!(e.flags, EntryFlags::READ_ONLY);
    let (r, ()) = tokio::join!(stat(&conn, TREE, units("x"), &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::OBJECT_NAME_NOT_FOUND, vec![]), (NtStatus::OBJECT_NAME_NOT_FOUND, vec![])],
        )
        .await;
    });
    assert_eq!(r, Err(Error::Status(NtStatus::OBJECT_NAME_NOT_FOUND)));
}

#[test]
fn entries_of_attributes() {
    let info = |a| Info { times: Times::default(), size: 7, attributes: a };
    let e = info(attributes::DIRECTORY | attributes::HIDDEN | attributes::SYSTEM).entry(b"d".to_vec());
    assert_eq!((e.kind, e.size), (EntryType::Directory, None));
    assert_eq!(e.flags, EntryFlags::HIDDEN.union(EntryFlags::SYSTEM));
    assert_eq!((e.mtime_ms, e.atime_ms, e.ctime_ms), (None, None, None));
    let e = info(attributes::REPARSE_POINT | attributes::DIRECTORY).entry(b"l".to_vec());
    assert_eq!((e.kind, e.size), (EntryType::Symlink, Some(7)));
    let e = info(attributes::NORMAL).entry(vec![0xED, 0xA0, 0x80]);
    assert_eq!((e.kind, e.flags), (EntryType::File, EntryFlags::NAME_NOT_UTF8));
    let big = Info { times: Times::default(), size: u64::MAX, attributes: 0 }.entry(vec![]);
    assert_eq!(big.size, Some(i64::MAX.unsigned_abs()));
    let d = DirEntry { name: vec![0xD800, u16::from(b'x')], times: Times::default(), size: 1, attributes: 0 };
    assert_eq!(dir_entry(&d).name, [0xED, 0xA0, 0x80, b'x']);
}

#[tokio::test]
async fn make_dir_and_an_existing_name() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, mut peer) = tokio::join!(make_dir(&conn, TREE, units("d"), true, &c), async {
        let reqs = peer.recv().await;
        assert_eq!(create_of(&reqs[0]), (0x0010_0080, 2, 1, units("d").to_vec()));
        assert_eq!(u32::from_le_bytes(reqs[0].body()[28..32].try_into().unwrap()), attributes::DIRECTORY);
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::SUCCESS, close_body())],
        )
        .await;
        peer
    });
    r.unwrap();
    let collision =
        vec![(NtStatus::OBJECT_NAME_COLLISION, vec![]), (NtStatus::OBJECT_NAME_COLLISION, vec![])];
    let (r, mut peer) = tokio::join!(make_dir(&conn, TREE, units("d"), true, &c), async {
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, collision.clone()).await;
        peer
    });
    assert_eq!(r, Err(Error::Status(NtStatus::OBJECT_NAME_COLLISION)));
    for (attrs, ok) in [(0x10, true), (0x20, false)] {
        let (r, p) = tokio::join!(make_dir(&conn, TREE, units("d"), false, &c), async {
            let reqs = peer.recv().await;
            answer(&mut peer, &reqs, collision.clone()).await;
            let reqs = peer.recv().await;
            assert_eq!(create_of(&reqs[0]).1, 1);
            answer(
                &mut peer,
                &reqs,
                vec![(NtStatus::SUCCESS, created_body(attrs, 0, FID)), (NtStatus::SUCCESS, close_body())],
            )
            .await;
            peer
        });
        peer = p;
        if ok {
            r.unwrap();
        } else {
            let e = r.unwrap_err();
            assert_eq!(e, local(ErrorName::AlreadyExists, "create folder: a file has the folder's name"));
        }
    }
}

#[tokio::test]
async fn remove_file_and_folder() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let ok3 = || {
        vec![
            (NtStatus::SUCCESS, created_body(0x20, 1, FID)),
            (NtStatus::SUCCESS, set_info_body()),
            (NtStatus::SUCCESS, close_body()),
        ]
    };
    let (r, mut peer) = tokio::join!(remove_file(&conn, TREE, units("f"), &c), async {
        let reqs = peer.recv().await;
        let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
        assert_eq!(cmds, [Command::Create, Command::SetInfo, Command::Close]);
        assert_eq!(related_flags(&reqs), [false, true, true]);
        assert_eq!(create_of(&reqs[0]), (0x0011_0080, 1, 0x40, units("f").to_vec()));
        let b = reqs[1].body();
        assert_eq!((b[2], b[3]), (1, 13));
        assert_eq!(b[32], 1);
        answer(&mut peer, &reqs, ok3()).await;
        peer
    });
    r.unwrap();
    let is_dir = vec![
        (NtStatus::FILE_IS_A_DIRECTORY, vec![]),
        (NtStatus::FILE_IS_A_DIRECTORY, vec![]),
        (NtStatus::FILE_IS_A_DIRECTORY, vec![]),
    ];
    let (r, mut peer) = tokio::join!(remove_file(&conn, TREE, units("d"), &c), async {
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, is_dir).await;
        peer
    });
    assert_eq!(r, Err(local(ErrorName::IsADirectory, "remove: a folder")));
    let (r, mut peer) = tokio::join!(remove_dir(&conn, TREE, units("d"), &c), async {
        let reqs = peer.recv().await;
        assert_eq!(create_of(&reqs[0]).2, options::DIRECTORY);
        answer(&mut peer, &reqs, ok3()).await;
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::OBJECT_NAME_NOT_FOUND, vec![]), (NtStatus::OBJECT_NAME_NOT_FOUND, vec![])],
        )
        .await;
        peer
    });
    r.unwrap();
    let (r, mut peer) = tokio::join!(remove_dir(&conn, TREE, units("d"), &c), async {
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, ok3()).await;
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::SUCCESS, close_body())],
        )
        .await;
        peer
    });
    assert_eq!(r, Err(local(ErrorName::DirectoryNotEmpty, "remove folder: the folder is not empty")));
    for (status, want) in [
        (NtStatus::DIRECTORY_NOT_EMPTY, Error::Status(NtStatus::DIRECTORY_NOT_EMPTY)),
        (NtStatus::NOT_A_DIRECTORY, local(ErrorName::NotADirectory, "remove folder: not a folder")),
    ] {
        let (r, p) = tokio::join!(remove_dir(&conn, TREE, units("d"), &c), async {
            let reqs = peer.recv().await;
            answer(&mut peer, &reqs, vec![(status, vec![]), (status, vec![]), (status, vec![])]).await;
            peer
        });
        peer = p;
        assert_eq!(r, Err(want));
    }
    let (r, ()) = tokio::join!(remove_dir(&conn, TREE, units("d"), &c), async {
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, ok3()).await;
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, vec![(NtStatus::ACCESS_DENIED, vec![]), (NtStatus::ACCESS_DENIED, vec![])])
            .await;
    });
    assert_eq!(r, Err(Error::Status(NtStatus::ACCESS_DENIED)));
}

#[tokio::test]
async fn rename_with_and_without_replace() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let ok3 = || {
        vec![
            (NtStatus::SUCCESS, created_body(0x20, 1, FID)),
            (NtStatus::SUCCESS, set_info_body()),
            (NtStatus::SUCCESS, close_body()),
        ]
    };
    let (r, mut peer) = tokio::join!(rename(&conn, TREE, units("a"), units(r"d\b"), false, &c), async {
        let reqs = peer.recv().await;
        assert_eq!(create_of(&reqs[0]), (0x0011_0080, 1, 0, units("a").to_vec()));
        let b = reqs[1].body();
        assert_eq!((b[2], b[3]), (1, 10));
        let info = &b[32..];
        assert_eq!(info[0], 0, "ReplaceIfExists");
        assert_eq!(u32::from_le_bytes(info[16..20].try_into().unwrap()), 6);
        assert_eq!(&info[20..26], &[b'd', 0, b'\\', 0, b'b', 0]);
        answer(&mut peer, &reqs, ok3()).await;
        peer
    });
    r.unwrap();
    let (r, mut peer) = tokio::join!(rename(&conn, TREE, units("a"), units("b"), true, &c), async {
        let reqs = peer.recv().await;
        assert_eq!(create_of(&reqs[0]).3, units("b").to_vec());
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::SUCCESS, close_body())],
        )
        .await;
        peer
    });
    assert_eq!(r, Err(local(ErrorName::AlreadyExists, "rename: the target is a folder")));
    for target_status in [NtStatus::SUCCESS, NtStatus::OBJECT_NAME_NOT_FOUND, NtStatus::OBJECT_PATH_NOT_FOUND]
    {
        let (r, p) = tokio::join!(rename(&conn, TREE, units("a"), units("b"), true, &c), async {
            let reqs = peer.recv().await;
            let body = if target_status == NtStatus::SUCCESS { created_body(0x20, 3, FID) } else { vec![] };
            answer(&mut peer, &reqs, vec![(target_status, body), (target_status, close_body())]).await;
            let reqs = peer.recv().await;
            assert_eq!(reqs[1].body()[32], 1, "ReplaceIfExists");
            answer(&mut peer, &reqs, ok3()).await;
            peer
        });
        peer = p;
        r.unwrap();
    }
    let (r, ()) = tokio::join!(rename(&conn, TREE, units("a"), units("b"), true, &c), async {
        let reqs = peer.recv().await;
        answer(&mut peer, &reqs, vec![(NtStatus::ACCESS_DENIED, vec![]), (NtStatus::ACCESS_DENIED, vec![])])
            .await;
    });
    assert_eq!(r, Err(Error::Status(NtStatus::ACCESS_DENIED)));
}

#[tokio::test]
async fn set_times_and_space() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let (r, mut peer) = tokio::join!(set_times(&conn, TREE, units("f"), Some(FT), None, &c), async {
        let reqs = peer.recv().await;
        assert_eq!(create_of(&reqs[0]).0, 0x0010_0100);
        let b = reqs[1].body();
        assert_eq!((b[2], b[3]), (1, 4));
        let info = &b[32..];
        assert_eq!(u64::from_le_bytes(info[16..24].try_into().unwrap()), FT);
        assert_eq!(u64::from_le_bytes(info[8..16].try_into().unwrap()), 0);
        answer(
            &mut peer,
            &reqs,
            vec![
                (NtStatus::SUCCESS, created_body(0x20, 1, FID)),
                (NtStatus::SUCCESS, set_info_body()),
                (NtStatus::SUCCESS, close_body()),
            ],
        )
        .await;
        peer
    });
    r.unwrap();
    let fs_body = |total: u64, avail: u64| {
        let mut w = Writer::new();
        w.u16(9).u16(72).u32(32).u64(total).u64(avail).u64(avail).u32(8).u32(512);
        w.into_vec()
    };
    let (r, mut peer) = tokio::join!(space_info(&conn, TREE, &[], &c), async {
        let reqs = peer.recv().await;
        let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
        assert_eq!(cmds, [Command::Create, Command::QueryInfo, Command::Close]);
        assert_eq!((reqs[1].body()[2], reqs[1].body()[3]), (2, 7));
        answer(
            &mut peer,
            &reqs,
            vec![
                (NtStatus::SUCCESS, created_body(0x10, 0, FID)),
                (NtStatus::SUCCESS, fs_body(1000, 250)),
                (NtStatus::SUCCESS, close_body()),
            ],
        )
        .await;
        peer
    });
    assert_eq!(
        r.unwrap(),
        SpaceInfo { free: Some(250 * 4096), total: Some(1000 * 4096), used: Some(750 * 4096) }
    );
    let (r, ()) = tokio::join!(space_info(&conn, TREE, &[], &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![
                (NtStatus::SUCCESS, created_body(0x10, 0, FID)),
                (NtStatus::SUCCESS, fs_body(10, u64::MAX / 8)),
                (NtStatus::SUCCESS, close_body()),
            ],
        )
        .await;
    });
    assert_eq!(r.unwrap(), SpaceInfo { free: Some(i64::MAX.unsigned_abs()), total: Some(40960), used: None });
}

/// Batches handed to the sink; `stop_after` batches, then `false`.
struct Batches {
    got: Vec<Vec<Vec<u8>>>,
    stop_after: usize,
}

impl ListSink for Batches {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.got.push(batch.iter().map(|e| e.name.clone()).collect());
        self.got.len() < self.stop_after
    }
}

fn dir_body(names: &[&str]) -> Vec<u8> {
    let mut records = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let n: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let end = n.len().saturating_add(104);
        let len = end.next_multiple_of(8);
        let mut r = vec![0u8; len];
        if i < names.len().saturating_sub(1) {
            r[..4].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        }
        r[24..32].copy_from_slice(&FT.to_le_bytes());
        r[40..48].copy_from_slice(&5u64.to_le_bytes());
        r[56..60].copy_from_slice(&0x20u32.to_le_bytes());
        r[60..64].copy_from_slice(&u32::try_from(n.len()).unwrap().to_le_bytes());
        r[104..end].copy_from_slice(&n);
        records.extend_from_slice(&r);
    }
    let mut w = Writer::new();
    w.u16(9).u16(72).u32(u32::try_from(records.len()).unwrap()).bytes(&records);
    w.into_vec()
}

#[tokio::test]
async fn list_leaves_out_names_that_are_no_entry_of_the_folder() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut sink = Batches { got: vec![], stop_after: usize::MAX };
    let names = [
        "first",
        ".",
        "..",
        "",
        "../../etc/passwd",
        "/etc/passwd",
        "sub/name",
        "trailing/",
        "nul\0name",
        "\0",
        "...",
        ".hidden",
    ];
    let (r, _peer) = tokio::join!(list(&conn, TREE, units("d"), 2, &mut sink, &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::SUCCESS, dir_body(&names))],
        )
        .await;
        let req = peer.recv_one().await;
        answer(&mut peer, &[req], vec![(NtStatus::SUCCESS, dir_body(&["last"]))]).await;
        let req = peer.recv_one().await;
        answer(&mut peer, &[req], vec![(NtStatus::NO_MORE_FILES, vec![])]).await;
        assert_eq!(peer.recv_one().await.command(), Command::Close);
        peer
    });
    r.unwrap();
    assert_eq!(
        sink.got,
        [vec![b"first".to_vec(), b"...".to_vec()], vec![b".hidden".to_vec(), b"last".to_vec()]]
    );
}

#[tokio::test]
async fn list_in_batches_and_close() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut sink = Batches { got: vec![], stop_after: usize::MAX };
    let (r, mut peer) = tokio::join!(list(&conn, TREE, units("d"), 2, &mut sink, &c), async {
        let reqs = peer.recv().await;
        let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
        assert_eq!(cmds, [Command::Create, Command::QueryDirectory]);
        assert_eq!(create_of(&reqs[0]), (0x0010_0081, 1, 1, units("d").to_vec()));
        assert_eq!(reqs[1].body()[3], 1, "RESTART_SCANS");
        answer(
            &mut peer,
            &reqs,
            vec![
                (NtStatus::SUCCESS, created_body(0x10, 0, FID)),
                (NtStatus::SUCCESS, dir_body(&[".", "..", "a", "b", "c"])),
            ],
        )
        .await;
        let req = peer.recv_one().await;
        assert_eq!(req.command(), Command::QueryDirectory);
        assert_eq!((req.body()[3], &req.body()[8..24]), (0, &FID[..]));
        answer(&mut peer, &[req], vec![(NtStatus::SUCCESS, dir_body(&["d"]))]).await;
        let req = peer.recv_one().await;
        answer(&mut peer, &[req], vec![(NtStatus::NO_MORE_FILES, vec![])]).await;
        let close = peer.recv_one().await;
        assert_eq!((close.command(), &close.body()[8..24]), (Command::Close, &FID[..]));
        peer
    });
    r.unwrap();
    assert_eq!(sink.got, [vec![b"a".to_vec(), b"b".to_vec()], vec![b"c".to_vec(), b"d".to_vec()]]);
    let mut sink = Batches { got: vec![], stop_after: 1 };
    let (r, mut peer) = tokio::join!(list(&conn, TREE, units("d"), 1, &mut sink, &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::SUCCESS, dir_body(&["a", "b"]))],
        )
        .await;
        assert_eq!(peer.recv_one().await.command(), Command::Close);
        peer
    });
    assert_eq!(r, Err(local(ErrorName::Canceled, "The listing was stopped")));
    assert_eq!(sink.got.len(), 1);
    let mut sink = Batches { got: vec![], stop_after: usize::MAX };
    let (r, ()) = tokio::join!(list(&conn, TREE, units("f"), 1, &mut sink, &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::NOT_A_DIRECTORY, vec![]), (NtStatus::NOT_A_DIRECTORY, vec![])],
        )
        .await;
    });
    assert_eq!(r, Err(local(ErrorName::NotADirectory, "list: not a folder")));
    assert!(sink.got.is_empty());
}

#[tokio::test]
async fn an_empty_folder_lists_nothing() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut sink = Batches { got: vec![], stop_after: usize::MAX };
    let (r, ()) = tokio::join!(list(&conn, TREE, &[], 5, &mut sink, &c), async {
        let reqs = peer.recv().await;
        answer(
            &mut peer,
            &reqs,
            vec![(NtStatus::SUCCESS, created_body(0x10, 0, FID)), (NtStatus::NO_MORE_FILES, vec![])],
        )
        .await;
        assert_eq!(peer.recv_one().await.command(), Command::Close);
    });
    r.unwrap();
    assert!(sink.got.is_empty());
}
