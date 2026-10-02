# Backend conformance suite (SPEC-v2 XT-1)

`tst_conformance` runs one set of QtTest functions against every configured
*target* (a backend instance: provider, connection parameters, credentials and
a base folder). It covers every `Backend` method and every capability claim:

- a capability the backend reports must pass its tests;
- a capability it does not report must make the matching call return
  `Unsupported` **without side effects** (`unsupportedWithoutSideEffects`
  compares a recursive snapshot of the test folder before and after).

The binary links only `libnetvfs` and QtTest and loads backends through
`BackendLoader` (`NETVFS_BACKEND_PATH`, defaulting to the build tree's
`lib/netvfs/backends`).

## Running

Without configuration it tests the local backend in a fresh temporary folder,
in two configurations, and is part of `make check-unit`:

| target | what it exercises |
|---|---|
| `local` | option `root`, relative paths below it, `NativeNoReplace` |
| `local-absolute` | default root `/`, absolute paths (L-1), the `link()`+`unlink()` / stat-check fallback of `rename(NoReplace)` (`native_noreplace=false`, L-3) |

```sh
build/tests/conformance/tst_conformance                       # default targets
build/tests/conformance/tst_conformance renameFolders symlinks # some functions
NETVFS_CONFORMANCE_CONFIG=/path/config.json build/tests/conformance/tst_conformance
```

Environment:

| variable | meaning |
|---|---|
| `NETVFS_CONFORMANCE_CONFIG` | JSON file with the targets (below) |
| `NETVFS_CONFORMANCE_TARGETS` | comma separated target names to run (others are ignored) |
| `NETVFS_CONFORMANCE_HEAVY` | `0`: skip heavy cases; `1`: run them even where expensive (upload 4 GiB without `hostPath`); unset: run where cheap |
| `NETVFS_CONFORMANCE_KEEP` | `1`: keep the run folder for inspection |
| `NETVFS_BACKEND_PATH` | where the backend plugins are |

The test object runs once per target (`QTest::qExec` per target); the exit code
is non-zero if any target failed. Every run works in
`<baseDir>/run-<pid>-<ms>/<testFunction>/` and removes the run folder at the end.

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
| `name` | label in the output and for `NETVFS_CONFORMANCE_TARGETS` (default: provider) |
| `provider`, `host`, `port`, `user`, `options`, `connectTimeoutMs`, `requestTimeoutMs` | `ConnectionParams`; `options` are the provider options without the `netvfs/<provider>/` prefix |
| `secretEnv` | environment variable holding the secret (never put secrets in the file) |
| `trustOnFirstUse` | without `options.host_key`, accept the identity seen on the first connect (containers with fresh keys) |
| `baseDir` | backend path the suite works below; created with `makePath` |
| `hostPath` | optional: the same folder as seen from the host (bind mount). Enables fast fixture creation (the 10 000-entry listing), sparse files > 4 GiB via `ftruncate`, and FIFO stalls |
| `listCount` | entries in `listBatches` (default 10 000; lower it only for very slow servers) |
| `fifoStall` | FIFOs created under `hostPath` stall the backend (default: true for `local` with a `hostPath`) |
| `stallProxy` | a second way into the same server through a stalling proxy: `host`/`port`/`options` override the target's parameters; `engage` / `release` are shell commands run before / after each stalled call (empty: the proxy stalls by itself once signed in) |
| `restart` | optional shell command that restarts the server; `keepAlive` must then return `ConnectionLost` |
| `skip` | test function → reason; the function is skipped for this target with that reason |

## Stalls and cancel (C-9, C-14)

- `cancelStalledFifo` (targets with `fifoStall`): the suite creates a FIFO and
  holds it open for reading and writing, so reads find no data and writes fill
  the pipe. `download`, `ReadHandle::read`, `checksum`, `upload` and
  `WriteHandle::write` on it must return `Canceled` within 2 s of `cancel()`
  from another thread. `stallTimeoutFifo` checks that the request timeout ends
  the same wait with `Timeout`.
- `cancelStalledProxy` (targets with `stallProxy`): for each blocking method
  (stat, lstat, list, makeDir, removeDir, rename, download, upload, keepAlive)
  a fresh backend connects through the proxy, `engage` runs, the call starts,
  `cancel()` follows after 300 ms and must end the call with `Canceled` within
  2 s; then `release` runs. Proxies: `tests/interop/sftp/docker/sftpproxy.py`
  (`--hold-file`), `tests/interop/smb/server/flipproxy.py` (`stall` mode), and
  the planned `httpstall.py` / `ftpstall.py`.

## Hooking a container target in (interop `run.sh`)

An interop script that already starts a server container writes a config and
runs the suite after its own driver:

```sh
conformance_config="$work/conformance.json"
cat > "$conformance_config" <<JSON
{ "targets": [ {
    "name": "webdav-apache",
    "provider": "webdav",
    "host": "127.0.0.1", "port": $port,
    "user": "alice", "secretEnv": "NETVFS_CONFORMANCE_SECRET",
    "options": { "tls": "https", "base_path": "/dav/" },
    "trustOnFirstUse": true,
    "baseDir": "conformance",
    "hostPath": "$work/data/conformance"
} ] }
JSON
mkdir -p "$work/data/conformance"
NETVFS_CONFORMANCE_SECRET="$password" NETVFS_CONFORMANCE_CONFIG="$conformance_config" \
    NETVFS_BACKEND_PATH="$build/lib/netvfs/backends" \
    "$build/tests/conformance/tst_conformance" || status=1
```

Notes:

- `hostPath` needs the server's folder bind-mounted from the host
  (`docker run -v "$work/data:/srv/data"`), writable by the server's user;
  leave it out if that is awkward: the suite then creates fixtures through the
  backend and skips the > 4 GiB case unless `NETVFS_CONFORMANCE_HEAVY=1`.
- Several targets (one per server flavour) go into one file; use `skip` with
  a reason for documented server limitations instead of weakening a test.
- Publish container ports to ephemeral host ports (`-p 127.0.0.1::PORT`) and
  name containers with a unique prefix, as `tests/interop/sftp/run.sh` does.

## What is covered

| function | SPEC | gated by |
|---|---|---|
| `capabilities`, `cancelBeforeCall`, `keepAlive` | XC-5, C-9, XC-20 | — |
| `entryFields`, `statAndLstat`, `listing` | XC-2, XC-6, XC-7 | `PosixModes`, `Ownership`, `ETags` for field checks |
| `listBatches` | XC-6: batches ≤ batchSize, sink `false` → `Canceled`, cancel mid-listing | — |
| `makeDir`, `removeFile`, `removeDir`, `removeTreeNative` | XC-8, XC-9 | `RecursiveDelete` |
| `renameFiles`, `renameFolders`, `renameCaseOnly` | XC-10 | `CaseInsensitive` changes expectations |
| `namesUtf8`, `namesNormalization`, `namesNonUtf8`, `namesLong`, `namesWindowsInvalid` | XC-4 | `WindowsNames`, `maxNameBytes`; non-UTF-8 skips with the server's reason |
| `setAttributes` | XC-11 | `PosixModes`, `SetModified` |
| `symlinks`, `symlinkFolder`, `symlinkDangling`, `symlinkLoop`, `hardlinks` | XC-12, XC-7 | `Symlinks`, `Hardlinks` |
| `readHandle`, `readHelper`, `downloadRanges` | XC-13, XC-14: ranges at EOF boundaries | `ReadHandles` |
| `writeHandle`, `writeResume`, `handlesAfterDisconnect` | XC-13, XC-23: dispositions, modes, resume offsets | `WriteResume`, `PosixModes` |
| `uploadDownload`, `uploadOptions`, `progressCancel` | XC-14 | `SetModifiedOnUpload`, `PosixModes` |
| `largeSparse` | files > 4 GiB | heavy |
| `copy`, `checksum`, `spaceInfo` | XC-17..XC-19 | `ServerCopy(Recursive)`, `Checksums`, `SpaceInfo` |
| `unsupportedWithoutSideEffects` | XT-1 | every unreported capability |
| `cancelStalledFifo`, `stallTimeoutFifo`, `cancelStalledProxy` | C-9, C-14 | `fifoStall`, `stallProxy` |
