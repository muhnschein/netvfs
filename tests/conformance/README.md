# Backend conformance suite

`tst_conformance`: one QtTest set against every configured target (backend instance: provider, connection, credentials, base folder). Covers every `Backend` method and capability claim:

- reported capability: its tests pass;
- unreported capability: matching call returns `Unsupported`, no side effects (`unsupportedWithoutSideEffects` compares folder snapshot before/after).

Links only `libnetvfs` and QtTest; loads backends via `BackendLoader` (`NETVFS_BACKEND_PATH`, default build tree's `lib/netvfs/backends`).

## Running

No config: local backend in fresh temp folder, two targets, part of `make check-unit`:

| target | exercises |
|---|---|
| `local` | option `root`, relative paths below it, `NativeNoReplace` |
| `local-absolute` | default root `/`, absolute paths, `link()`+`unlink()` / stat-check fallback of `rename(NoReplace)` (`native_noreplace=false`) |

```sh
build/tests/conformance/tst_conformance                       # default targets
build/tests/conformance/tst_conformance renameFolders symlinks # some functions
NETVFS_CONFORMANCE_CONFIG=/path/config.json build/tests/conformance/tst_conformance
```

| variable | meaning |
|---|---|
| `NETVFS_CONFORMANCE_CONFIG` | JSON file with targets (below) |
| `NETVFS_CONFORMANCE_TARGETS` | comma-separated target names to run |
| `NETVFS_CONFORMANCE_HEAVY` | `0`: skip heavy cases; `1`: run even where expensive (4 GiB upload without `hostPath`); unset: where cheap |
| `NETVFS_CONFORMANCE_KEEP` | `1`: keep run folder |
| `NETVFS_BACKEND_PATH` | backend plugin folder |

`QTest::qExec` once per target; non-zero exit if any target failed. Each run works in `<baseDir>/run-<pid>-<ms>/<testFunction>/`, removed at end.

## Configuration

```json
{
  "targets": [
    {
      "name": "sftp-o103",
      "provider": "sftp",
      "host": "127.0.0.1",
      "port": 32768,
      "user": "alice",
      "options": { "host_key": "ssh-ed25519 AAAA..." },
      "connectTimeoutMs": 15000,
      "requestTimeoutMs": 60000,
      "secretEnv": "NETVFS_CONFORMANCE_SECRET",
      "trustOnFirstUse": true,
      "baseDir": "conformance",
      "hostPath": "/tmp/netvfs-sftp-it-1234/data/conformance",
      "listCount": 10000,
      "fifoStall": false,
      "stallProxy": {
        "port": 32769,
        "options": {},
        "engage": "docker exec netvfs-sftp-it-1234-o89 touch /tmp/hold",
        "release": "docker exec netvfs-sftp-it-1234-o89 rm -f /tmp/hold"
      },
      "restart": "docker restart netvfs-sftp-it-1234-o103",
      "skip": { "namesNormalization": "server normalises to NFC" }
    }
  ]
}
```

| key | meaning |
|---|---|
| `name` | label; name for `NETVFS_CONFORMANCE_TARGETS` (default: provider) |
| `provider`, `host`, `port`, `user`, `options`, `connectTimeoutMs`, `requestTimeoutMs` | `ConnectionParams`; `options` without `netvfs/<provider>/` prefix |
| `secretEnv` | env var holding secret; never secrets in file |
| `trustOnFirstUse` | without `options.host_key`: accept first identity seen (containers with fresh keys) |
| `baseDir` | backend path suite works below; `makePath` creates it |
| `hostPath` | same folder seen from host (bind mount): fast fixtures (10 000-entry listing), sparse > 4 GiB files via `ftruncate`, FIFO stalls |
| `listCount` | entries in `listBatches` (default 10 000) |
| `fifoStall` | FIFOs under `hostPath` stall backend (default true for `local` with `hostPath`) |
| `stallProxy` | same server via stalling proxy: `host`/`port`/`options` override target's; `engage`/`release` shell commands before/after each stalled call (empty: proxy stalls by itself once signed in) |
| `restart` | shell command restarting server; `keepAlive` then returns `ConnectionLost` |
| `skip` | test function → reason; skipped for this target |

## Stalls and cancel

- `cancelStalledFifo` (`fifoStall`): FIFO held open both ways; `download`, `ReadHandle::read`, `checksum`, `upload`, `WriteHandle::write` on it return `Canceled` within 2 s of `cancel()` from another thread. `stallTimeoutFifo`: request timeout ends same wait with `Timeout`.
- `cancelStalledProxy` (`stallProxy`): per blocking method (stat, lstat, list, makeDir, removeDir, rename, download, upload, keepAlive) fresh backend via proxy, `engage`, call, `cancel()` after 300 ms, `Canceled` within 2 s, `release`. Proxies: `tests/interop/sftp/docker/sftpproxy.py` (`--hold-file` holds SFTP replies; `--relay` whole SSH connection), `tests/interop/smb/server/flipproxy.py` (`stall` mode).

`tests/interop/sftp/run.sh` runs suite against OpenSSH 10.3p1 with `--relay` stall proxy, restart command (`restart-instance.sh`), bind-mounted `hostPath`: copy it to hook a container target in. `hostPath` needs server folder bind-mounted writable; without it fixtures go through backend and > 4 GiB case skips unless `NETVFS_CONFORMANCE_HEAVY=1`. Server limitation → `skip` with reason, never weaker test. Ephemeral host ports (`-p 127.0.0.1::PORT`), unique container prefix.

## What is covered

| function | gated by |
|---|---|---|
| `capabilities`, `cancelBeforeCall`, `keepAlive` | — |
| `entryFields`, `statAndLstat`, `listing` | `PosixModes`, `Ownership`, `ETags` for field checks |
| `listBatches` (batches ≤ batchSize, sink `false` → `Canceled`, cancel mid-listing) | — |
| `makeDir`, `removeFile`, `removeDir`, `removeTreeNative` | `RecursiveDelete` |
| `renameFiles`, `renameFolders`, `renameCaseOnly` | `CaseInsensitive` changes expectations |
| `namesUtf8`, `namesNormalization`, `namesNonUtf8`, `namesLong`, `namesWindowsInvalid` | `WindowsNames`, `maxNameBytes`; non-UTF-8 skips with the server's reason |
| `setAttributes` | `PosixModes`, `SetModified` |
| `symlinks`, `symlinkFolder`, `symlinkDangling`, `symlinkLoop`, `hardlinks` | `Symlinks`, `Hardlinks` |
| `readHandle`, `readHelper`, `downloadRanges` (ranges at EOF boundaries) | `ReadHandles` |
| `writeHandle`, `writeResume`, `handlesAfterDisconnect` (dispositions, modes, resume offsets) | `WriteResume`, `PosixModes` |
| `uploadDownload`, `uploadOptions`, `progressCancel` | `SetModifiedOnUpload`, `PosixModes` |
| `largeSparse` (files > 4 GiB) | heavy |
| `copy`, `checksum`, `spaceInfo` | `ServerCopy(Recursive)`, `Checksums`, `SpaceInfo` |
| `unsupportedWithoutSideEffects` | every unreported capability |
| `cancelStalledFifo`, `stallTimeoutFifo`, `cancelStalledProxy` | `fifoStall`, `stallProxy` |
