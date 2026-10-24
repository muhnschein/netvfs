# Rust in netvfs

Two programs of the package netvfs-bridge and one library of the package
netvfs are written in Rust:

- `netvfs-accounts`, the setgid accounts helper (SPEC-v2 XB-2a): the
  requests `list`, `files <id>` and `attention <id> <state> [pin]`, a
  `QDataStream` answer on stdout, and the confinement of XB-2a. The process
  that holds the group `privileged` links libc, libgcc_s and libsqlite3
  only, no Qt, GLib, libaccounts or GIO modules, and every `unsafe` call is
  in one module (`sandbox.rs`).
- `netvfs-bridge` (SPEC-v2 §8a): the one netvfs process a sandboxed
  consumer can reach. Everything a consumer sends is decoded and
  checked in Rust: zbus as the peer-to-peer D-Bus server with the bridge's
  own inbound limits, the peer check, the argument validation (XSEC-7),
  consent, locations, questions and jobs. The bridge reaches the backends
  through `libnetvfs-bridge-ffi.so` (`src/bridge/ffi`, the C
  ABI of `netvfs_bridge_ffi.h`), which it loads with `dlopen` from
  `/usr/lib64/netvfs` and which exports one symbol. The binary links libc,
  libgcc_s and libm only; Qt and libnetvfs come with that library. Its
  protocol is the contract of `tests/bridge/contract`.
- `libnetvfs-rs.so`, the Rust backends (see "netvfs-backend"): C++ backend
  plugins load it with `dlopen` from `/usr/lib64/netvfs` and reach its
  backends through a C ABI of one table (`src/backends/rs/netvfs_rs.h`).
  Its providers: `sftp` (see "netvfs-sftp"), behind the SFTP plugin
  `libnetvfs-sftp.so`, `smb`, an SMB 3.1.1 client of its own (see
  "netvfs-smb"), behind the SMB plugin `libnetvfs-smb.so`, and `mem`, an
  in-memory backend for tests.

Everything else stays C++.

## Layout

| Path | What |
|---|---|
| `rust/Cargo.toml` | workspace: version, `rust-version`, lints, release profile |
| `rust/rust-toolchain.toml` | the pinned toolchain (1.95.0) |
| `rust/deny.toml` | cargo-deny: advisories, yanked crates, licences, sources |
| `rust/netvfs-accounts/src/db.rs` | the database libaccounts-glib would open, and reading it |
| `rust/netvfs-accounts/src/gvariant.rs` | the GVariant text format of stored values |
| `rust/netvfs-accounts/src/qvariant.rs`, `wire.rs` | the `QDataStream` answer |
| `rust/netvfs-accounts/src/policy.rs`, `store.rs`, `serve.rs` | XA-1/XA-4/XA-7 for the Files service, the three requests |
| `rust/netvfs-accounts/src/dbus.rs` | the `AccountChanged` signal after an attention write |
| `rust/netvfs-accounts/src/sandbox.rs` | descriptors, process state, set-id, Landlock, seccomp |
| `rust/netvfs-accounts/src/bin/probe.rs` | tests only: applies one part of the confinement and checks it |
| `rust/netvfs-bridge-proto/src/methods.rs` | `org.netvfs.Bridge1`: names, the method table (args.cpp order, lane, consent), signals, the served XML |
| `rust/netvfs-bridge-proto/src/errors.rs`, `limits.rs` | the 24 XC-21 error names; the XB-17, XB-12 and C-10 limits |
| `rust/netvfs-bridge-proto/src/wire.rs`, `proxy.rs`, `connect.rs`, `signals.rs` | wire types and the client (from lautta) |
| `rust/netvfs-bridge-proto/src/fake/` | tests only (feature `fake`): lautta's fake bridge, the golden-sequence replayer |
| `rust/netvfs-bridge-proto/org.netvfs.Bridge1.xml` | copy of the contract XML; `tests/contract.rs` keeps it equal |
| `rust/netvfs-vfs/` | what the bridge and the Rust backends share: the backend types (entries, capabilities, parameters, credentials), the async `Backend`, `ReadHandle` and `WriteHandle` traits, `CancelToken`, `Status` with its XC-21 `ErrorName`, and the `nvb_*` data types of both C ABIs (`abi.rs`: `#[repr(C)]` by hand, no bindgen, sizes and offsets pinned by tests); no `unsafe` |
| `rust/netvfs-bridge/src/ffi/raw.rs` | the table and handles of `libnetvfs-bridge-ffi.so`'s C ABI, over the data types of `netvfs_vfs::abi` |
| `rust/netvfs-bridge/src/ffi/loader.rs`, `mod.rs` | `dlopen` (`RTLD_NOW \| RTLD_LOCAL`, `/usr/lib64/netvfs/libnetvfs-bridge-ffi.so`, `NETVFS_BRIDGE_FFI` for tests); `Ffi`: init/run/post/quit on the Qt thread, URLs, `conn_new` |
| `rust/netvfs-bridge/src/ffi/conn.rs` | `Conn` and `Handle` (`!Send`, owner thread, T4), `CancelHandle` (any thread; shares a lock with `conn_free`) |
| `rust/netvfs-bridge/src/ffi/callback.rs` | the trampolines (list sink, walk, progress, `nvb_io`, establish hooks, discovery, `post`): panics caught, never into C++ (T7); connection calls refused inside a callback (T6) |
| `rust/netvfs-bridge/src/ffi/marshal.rs` | plain Rust values both ways: `ParamsBuf` (owns the `nvb_kv`/`nvb_bytes` arrays of a call), readers of C++'s blocks and callback arguments |
| `rust/netvfs-bridge/src/ffi/discovery.rs` | `Discovery` (XD-5), Qt thread only (T3) |
| `rust/netvfs-bridge/src/ffi/fake.rs` | tests only (feature `testing`): the fake backend's control table (`NETVFS_BRIDGE_FFI_FAKE`) |
| `rust/netvfs-bridge/src/main.rs` | the binary: `[--listen ADDRESS] <consumer-id>` (default `systemd:`, fd 3), the Qt loop on the main thread and the bridge on the thread `nvb-rt`, exit codes 0 (idle exit), 1, 2 (usage) |
| `rust/netvfs-bridge/src/server/` | the socket front: listener, peer check, one session per connection (zbus p2p server, EXTERNAL, fd passing), inbound limits (`inbound.rs`: 2 MiB, 2 descriptors), dispatch (`Peer`, `Introspect` and unknown members answered by the bridge itself), argument validation (`args.rs`, `paths.rs`), replies and signals (`encode.rs`), the outgoing FIFO and its byte budget (`flow.rs`, C-10) |
| `rust/netvfs-bridge/src/core/` | the task that owns the state: sessions, consent, quotas (XB-17), questions, discovery, `LocationsChanged` for connection states (`states.rs`, XB-12), the drive calls (`drives.rs`), the handlers of every method |
| `rust/netvfs-bridge/src/locations/`, `jobs/` | the locations a consumer may see, connection pools and lanes (XB-12), the worker threads that own the backend connections, the connection state of a location (`state.rs`), known hosts; the bodies of listings, walks, removals and transfers (`fdio.rs`: the consumer's descriptors, XB-11) |
| `rust/netvfs-bridge/src/accounts/` | `netvfs-accounts` as the bridge runs it, its answers (`qds.rs`), the `AccountChanged` watch |
| `rust/netvfs-bridge/src/drives/` | memory cards and USB drives (XB-20): which of UDisks2's block devices are listed (`classify.rs`, a pure function of `GetManagedObjects`'s answer, fuzzed by `udisks_objects`), the UDisks2 client on the system bus with its mount, unmount and watch of UDisks2's signals (`udisks.rs`) |
| `rust/netvfs-bridge/src/config.rs`, `consent.rs`, `prompt.rs`, `handoff.rs`, `log.rs` | consumer files and the environment, `bridge.conf` (Qt's INI format, `ini.rs`, with a `QLockFile`-compatible lock, `lockfile.rs`, saved as `QSaveFile` does, `savefile.rs`), the consent notification, the settings handoff, logging (`QT_LOGGING_RULES`) |
| `rust/netvfs-bridge/src/sys/` | the libc calls of the bridge: the listening socket, peer credentials and pidfd, descriptors, inotify, `flock`, a zbus message from a frame |
| `rust/netvfs-bridge/src/testing.rs`, `testutil.rs`, `bin/accounts_fake.rs` | tests only (features `testing`, `test-bins`): fixtures, a private bus, `netvfs-accounts-fake` |
| `src/bridge/rust/rust.pro` | the qmake target that builds both binaries with cargo (see "Build") |
| `rust/netvfs-backend/` | `libnetvfs-rs.so` (see "netvfs-backend"): `ffi/` the C ABI of `netvfs_rs.h`, `runtime.rs` the tokio runtime and the cancel cut, `erased.rs` the traits behind `dyn`, `providers.rs` the backends by provider name, `mem/` tests only (feature `testing`): the in-memory backend |
| `rust/netvfs-sftp/` | provider `sftp` (see "netvfs-sftp"): `policy.rs` the algorithm lists, `session.rs` the SSH transport, `auth.rs` signing in, `keys.rs` the key tools, `wire.rs`, `proto.rs` and `client.rs` the SFTP v3 client, `remote.rs` the file operations, `io.rs` transfers and handles, `backend.rs` the `Backend`; `fake.rs` and `testserver.rs` tests only |
| `src/backends/sftp/` | the SFTP plugin: a shim plugin of the Rust backends whose root object is the SSH key tools |
| `rust/netvfs-smb/` | provider `smb` (see "netvfs-smb"): `transport`, `msg/` (the MS-SMB2 codecs), `negotiate`, `auth` (sspi glue), `crypto` (the only user of RustCrypto), `conn` (credits, compounding, the receive task), `session`, `fs`, `files` (handles), `rpc` (srvsvc), `names`, `status`, `error`, `profile`, `backend` |
| `src/backends/rs/` | the C++ shim: `netvfs_rs.h`, the loader, `RsBackend`, `RsReadHandle`, `RsWriteHandle`, `RsKeyTools`, the conversions and callbacks; `rs.pro` builds the library with cargo |
| `rust/fuzz/` | cargo-fuzz targets (nightly, not in the workspace) |
| `rust/vendor/ssh-key/` | ssh-key 0.7.0-rc.11 with one change (see below; not in the workspace) |

Dependencies: `libc` and `rusqlite` (without the bundled SQLite: the system
libsqlite3 through pkg-config). The protocol crate: `netvfs-vfs` (for the
error names), `zbus` 5 (`tokio`, `p2p`), `tokio`, `serde`, `zeroize` and
`futures-lite` (already in zbus's tree);
`serde_json` and `sha2` only behind its test-only `fake` feature.
netvfs-bridge: the protocol crate, `netvfs-vfs`, `libc`, `zeroize`, `zbus` 5
(`tokio`, `p2p`, `bus-impl`), `tokio` and `futures-lite`. netvfs-vfs:
`tokio` (`sync` only) and `zeroize`. netvfs-backend: `netvfs-vfs`, `libc`,
`tokio` (`rt-multi-thread`, `time`, `sync`), `zeroize`, `netvfs-sftp`,
`netvfs-smb`; `sha2` only behind its test-only `testing` feature.
netvfs-sftp: `netvfs-vfs`, `russh` (exactly 0.64.1, default features off,
`ring` and `rsa`), `tokio`, `zeroize`, `data-encoding` and `pkcs8` (both
already in russh's tree). netvfs-smb: `netvfs-vfs`, `tokio` (`rt`, `net`,
`io-util`, `time`, `sync`), `zeroize`, `sspi` 0.23 (default features off)
and, in its `crypto` module only, `aes`, `aes-gcm`, `cmac`, `hmac`, `sha2`
and `getrandom`; `md-5` and `rc4` for one test.

russh reads and writes key files with `ssh-key` 0.7.0-rc.11, which netvfs
builds from `rust/vendor/ssh-key` (`[patch.crates-io]` in `rust/Cargo.toml`
and `rust/fuzz/Cargo.toml`). The copy is the crate as published plus one
line: in `src/private/ecdsa.rs`, `EcdsaPrivateKey::decode` accepts a
private scalar of at least 1 byte instead of 32, and the code after that
check left-pads a shorter scalar to the field size. OpenSSH stores the
scalar without leading zero bytes, so about one P-256 key in 256 that
ssh-keygen makes has a 31-byte scalar; with the change such keys import
(`rust/netvfs-sftp/testdata/keys/ecdsa256-short-scalar`, also
passphrase-encrypted). `README.netvfs.md` there gives the published
crate's checksum, the diff and the reason. The copy is excluded from the
workspace (format, clippy, tests), from cargo-mutants, from Sonar and from
Rust coverage.

`rust/deny.toml` allows an older second version of `syn`, `getrandom`
(0.2 and 0.3), `sha3`, `base64` and `generic-array`, each with its reason.
`generic-array` 0.14 comes in through sspi's `crypto-mac` 0.11 and through
the compat feature of `generic-array` 1, which russh uses.

`unsafe` is allowed in the helper's `sandbox`, in netvfs-bridge's `ffi`
and `sys` modules and in netvfs-backend's `ffi` module only (netvfs-smb
forbids it); every block says why it holds. The `ffi` module keeps the threading and ownership rules of
`src/bridge/ffi/netvfs_bridge_ffi.h` by its types: plain Rust values in,
`Result<_, Status>` out, every block C++ returns read and freed at once,
secrets passed as `Zeroizing` buffers without a copy on the Rust side.

## Toolchain

Rust 1.95, edition 2024: the rustc that `sailfishos/rust` merged next
(JB#64166). `rust-version` in `rust/Cargo.toml` is 1.95 and
`rust/rust-toolchain.toml` pins 1.95.0 for host builds, lints and tests, so
CI checks the compiler the SDK will ship. The weekly workflow
(`scheduled.yml`) runs the current stable's clippy too, so a toolchain bump
never comes as a surprise.

`tools/ci/check-lockfile.sh` fails on a lockfile cargo 1.95 cannot read or a
locked crate that needs a newer Rust; `make check-rust` runs it, plus
`cargo +1.95.0 check --locked`. Update dependencies with the pinned cargo
(`cd rust && cargo update -p <crate>`); the resolver (version 3) prefers
releases whose `rust-version` fits.

## Cross build

No SDK target ships rustc 1.95 yet, so the RPM job builds the Rust binaries
with the host's cargo against the SDK's own compiler and target sysroot,
and the spec installs them (the pattern of vuo's cross build and piirit's
prebuilt server):

| Step | Script |
|---|---|
| Lift `/opt/cross` (gcc 13 for `aarch64-meego-linux-gnu`, i486 binaries), the host libraries it loads and the target sysroot out of the pinned 5.2.0.15 SDK image; add the binutils names gcc looks for, a linker wrapper and an unversioned `libsqlite3.so` | `tools/ci/lift-sdk.sh <image> <target> <dir>` |
| `cargo build --release` for `aarch64-unknown-linux-gnu` with that linker, PIE, full RELRO, `-z now`, no executable stack; `libnetvfs-rs.so` the same way with its own profile (`--profile rs-release`, no PIE: a shared library) | `tools/ci/cross-build.sh <dir> rust/prebuilt` |
| The workspace's tests for the target under `qemu-aarch64-static`, against the target's glibc and SQLite (the confinement tests run natively only) | `tools/ci/cross-build.sh <dir> <out> test` |
| The cross-built helper's answers to `list` and `files` equal the host build's, byte for byte; the cross-built bridge starts and gets as far as loading its C ABI | `tools/ci/cross-smoke.sh <dir> rust/prebuilt/netvfs-accounts rust/prebuilt/netvfs-bridge` |
| NEEDED (the helper: libc, libgcc_s, libsqlite3; the bridge: libc, libgcc_s, libm), highest GLIBC symbol version (the target's glibc is the floor), PIE, RELRO, BIND_NOW, NX stack | `tools/ci/check-linked-libs.sh`, from `tools/ci/check-rpm.sh` on the packaged binaries |
| `libnetvfs-bridge-ffi.so`: exports only `nvb_ffi_get`, links libnetvfs, the GLIBC floor, RELRO, BIND_NOW, NX stack; the bridge loads it from where the package puts it, next to the backend folder libnetvfs searches | `tools/ci/check-ffi-lib.sh`, from `tools/ci/check-rpm.sh` (and from `make check-packaging` on the host build) |
| `libnetvfs-rs.so`: exports only `nvr_get`, links only libc, libgcc_s, libm, libpthread, libdl and the dynamic loader, the GLIBC floor, RELRO, BIND_NOW, NX stack; every plugin that uses it looks for it where the package puts it | `tools/ci/check-rs-lib.sh`, from `tools/ci/check-rpm.sh` and `make check-packaging` |

The host needs the i386 C library and qemu (`libc6-i386`,
`qemu-user-static`; `tools/ci/install-host-deps.sh`).
`tools/ci/build-rpm.sh` cross-builds by itself when `rust/prebuilt` is
empty, so a local RPM build is one command.

Since the spec only installs the binaries, OBS and Chum cannot rebuild
netvfs from the spec; netvfs ships no recipe for either. Once an SDK target
ships rustc 1.95, the cross job goes and the spec runs cargo again: the
qmake target (`src/bridge/rust/rust.pro`) builds with cargo whenever
`NETVFS_RUST_PREBUILT` is not set.

## Build

`src/bridge/rust/rust.pro` is a qmake aux target that runs one
`cargo build --release --locked` for `netvfs-bridge` and `netvfs-accounts`,
copies both into the build tree's `libexec/netvfs` (where the C++ tests run
them) and installs them to `/usr/libexec/netvfs`, so `make` builds them with
the C++ parts. qmake variables: `NETVFS_CARGO` (the cargo to run),
`NETVFS_RUST_TARGET` (a target triple), `NETVFS_CARGO_FLAGS` (extra flags),
`NETVFS_RUST_PREBUILT` (a folder with the binaries to install instead; the
RPM sets it to `rust/prebuilt`). `src/backends/rs/rs.pro` does the same for
`libnetvfs-rs.so` (see "netvfs-backend").

## netvfs-backend

`libnetvfs-rs.so` holds the Rust backends; C++ backend plugins are thin
shims over it (`src/backends/rs`), so libnetvfs, the bridge's C ABI and the
C++ tests see ordinary `Backend` objects. Its one C ABI is
`src/backends/rs/netvfs_rs.h`: `nvr_get()`, the library's only export,
returns a table of 38 functions over the `nvb_*` data types of
`netvfs_bridge_ffi.h`. No version handshake: the library and its plugins
ship in one package.

The crates:

- `netvfs-vfs`: the backend types and the async traits a backend
  implements (`Backend`, `ReadHandle`, `WriteHandle`), `CancelToken` and
  `Status`; shared with the bridge.
- `netvfs-backend`: the library (crate type `cdylib`, plus an `rlib` for its
  tests). `providers.rs` makes a backend by provider name; `erased.rs` puts
  the traits behind `dyn`; `ffi/` is the table: every result one `malloc`ed
  block that the table's `free` releases (and wipes, for key material),
  callbacks wrapped so that nothing unwinds into C, `catch_unwind` around
  every function (a panic is Internal "The Rust backend failed", detail
  `panic: <message>`).

**Profiles.** The binaries abort on a panic (`[profile.release]`), but the
library must unwind so that a panic reaches the table function that reports
it, and cargo sets `panic` per profile, not per package. So the library has
profiles of its own in `rust/Cargo.toml`: `rs-release` (the release
profile with `panic = "unwind"` and fat LTO) for the shipped library, and
`rs-test` (the dev profile with `panic = "unwind"`) for the C++ tests,
built `--features testing`. `src/backends/rs/rs.pro` runs `cargo build
--profile rs-release -p netvfs-backend --lib`, copies the library to the
build tree's `lib/netvfs` and installs it to `/usr/lib64/netvfs`;
`NETVFS_RUST_PREBUILT` installs the cross-built one instead.

**Loading.** The shim opens `/usr/lib64/netvfs/libnetvfs-rs.so` with
`RTLD_NOW | RTLD_LOCAL` the first time a plugin makes a backend (or uses the
key tools), and keeps it; `NETVFS_RS_LIB` names another file (tests).
Without the library `BackendFactory::create` fails with Internal "netvfs
Rust backends not installed" (with `dlerror()` as the detail), and the
backend loader passes that on.

**Threads.** One tokio runtime per process, made at the first call that
needs one, with two workers named `nvr-io-0` and `nvr-io-1` for background
protocol work. Every table function runs its call with `block_on` on the
caller's thread, and the callbacks it makes (listing sink, prompter,
progress, the local side of a transfer) run there too, before it returns. A
connection takes one call at a time, from any thread (C-8: a backend is used
by one thread at a time, not always the one that made it); its handles
share that rule. A call that overlaps another of the same connection, or is
made from inside one of its callbacks, returns Internal "The connection is
busy: one call at a time, none from a callback" instead of waiting.

**Cancel.** `cancel` works from any thread, also while a call runs: it
trips the connection's `CancelToken`, which wakes whatever the backend
awaits, and the backend ends the call with Canceled. A call that misses the
token is dropped 1 s after the cancel (`GRACE`) and returns Canceled, so the
2 s bound of C-9 holds anyway. Teardown (`disconnect`, `abort`, what
`conn_free` closes) runs even with the token tripped, with the same cut;
`reset_cancel` clears the token for the next call. On the C++ side
`RsBackend::cancel` also cancels a prompter that is waiting for an answer
(XC-22).

**The shim.** `RsBackend`, `RsReadHandle`, `RsWriteHandle` and `RsKeyTools`
convert both ways (`rsmarshal`) and wrap the C++ callback objects
(`rshooks`): what a callback throws stays on the C++ side, ends the callback
as a refusal and turns the call's result into Internal "A callback of the
Rust backend failed". A name that `Names` cannot encode is InvalidName
before it reaches Rust; the capabilities are fixed once `authenticate`
succeeds (XC-5). The shim itself refuses a read size that is negative or
more than one `QByteArray` holds, and a negative write length, as Internal
"Invalid range" and "Invalid length", as the local backend does. The
library's table maps a mistake of its caller to ProtocolError "Invalid
<what> from the plugin" or "Missing <what> from the plugin": a negative
offset, a length, size or mode below -1, an unknown option kind or
disposition, a missing pointer or callback. A handle that was closed,
committed or aborted is NULL on the C++ side, so a later call on it is
ProtocolError "Missing read handle from the plugin" (or "write handle"),
and its `position()` is -1. A local sink that cannot be written to (the
`nvb_io` write of a download fails) is NoSpace "Cannot write the local
file".

## netvfs-sftp

Provider `sftp` of `libnetvfs-rs.so`. The SFTP plugin `libnetvfs-sftp.so`
(`src/backends/sftp`) is a shim plugin like the test plugin of `mem`: its
backends are `RsBackend`s, and its root object is the SSH key tools
(`SshKeyTools`, through `RsKeyTools`), so the SSH code ships in the SFTP
package only (SPEC-sftp 5.1).

**SSH.** russh with `ring` as the crypto provider; netvfs has no
cryptography of its own and links no OpenSSL. The lists (`policy.rs`):

| List | Algorithms |
|---|---|
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256` (also as `@libssh.org`), and the client markers for ext-info and strict kex |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` |
| MACs | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` (unused with these ciphers) |
| Host keys | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`; no `ssh-rsa` signatures, DSA or certificates |
| Compression | `none` |

A server with nothing in common fails with SecurityPolicy "The server
offers no <list> algorithm this app accepts (it offers <its names>)". A
pinned key narrows the host-key list to its type (an RSA pin to both
`rsa-sha2-*`); a server that does not offer that type is connected to
once more without the restriction, so that the caller sees the key it
presents now. The session opens the `sftp` subsystem and nothing else: no
exec channel, and channels the server opens are refused.

**Sign-in** (`auth.rs`): `none` first to learn the methods, then the
configured one (`password`, `publickey` with the stored Ed25519 or ECDSA
key, or keyboard-interactive). Without a prompter the stored password
answers a keyboard-interactive round only as S-11 says and a partial
success is AuthFailed; with one, the stored password answers only a
password prompt and every other round is asked (XS-11). A key is never
sent as a password and a password never read as a key.

**Keys** (`keys.rs`): `generate` makes Ed25519 keys; `importKey` accepts
Ed25519 and ECDSA (P-256, P-384, P-521) in OpenSSH, PKCS#8 (also
encrypted) and SEC1 files. RSA and DSA keys, security keys, certificates,
public key lines, PuTTY files and PEM files encrypted with OpenSSL's
`Proc-Type: 4,ENCRYPTED` scheme are Unsupported, each with what to do
instead. ECDSA keys whose private scalar is shorter than the field size
import (see the `ssh-key` change above). Before a passphrase is
tried, the cost of the key derivation is bounded: bcrypt at most 1024
rounds, PBKDF2 at most 1,000,000 iterations, scrypt at most 64 MiB and
parallelism 4; a key beyond is Unsupported, whatever the passphrase.

**SFTP.** An own SFTP v3 client (`wire.rs`, `proto.rs`, `client.rs`):
requests matched to replies by id, each with the request timeout (C-14)
and the connection's cancel (C-9), abandoned ones bounded (C-10), packets
up to 256 KiB plus 1 KiB. Transfers keep 16 requests in flight, in chunks
of the server's `limits@openssh.com` up to 256 KiB (32 KiB without it);
read handles read ahead while reads are sequential, up to 4 MiB. What a
server offers sets the capabilities: AtomicReplace
(`posix-rename@openssh.com`), SpaceInfo (`statvfs@openssh.com`), Hardlinks
(`hardlink@openssh.com`), Ownership (`users-groups-by-id@openssh.com`),
ServerCopy (`copy-data`, files only); NativeNoReplace always (OpenSSH's
plain RENAME fails on an existing target); never Checksums (computed
locally), ServerCopyRecursive or AtomicPut. SYMLINK sends its arguments
in OpenSSH's order (target, then link). A listing leaves out names that
are empty, `.`, `..`, or contain `/` or NUL (`paths::is_entry_name`, XC-6),
and delivers the rest.

**Tests.** Unit tests against an SFTP server in memory (`fake.rs`) and an
SSH server in the test process (`testserver.rs`, russh's server with a
scripted sign-in and a proxy that stalls or cuts); `tests/openssh.rs`
against the SFTP interop containers (the algorithms each server
negotiates, read from its log; refusals; pins of each key type; sign-in
methods; capabilities per server; cancel and timeouts). Those need
`NETVFS_SFTP_INTEROP_CONFIG`, which `tests/interop/sftp/run.sh` sets (and
prints with `NETVFS_SFTP_SERVERS_ONLY=1`); without it they pass at once and
say they were skipped. The CI mutant jobs start the servers once per
shard; `tools/ci/rust-mutants.sh` starts them itself, and removes them at
the end, when netvfs-sftp's mutants run without the settings.

## netvfs-smb

Provider `smb` of `libnetvfs-rs.so`, and the SMB plugin
`libnetvfs-smb.so` (`src/backends/smb`) is a shim plugin like the test
plugin of `mem`. An SMB client of its own, for SMB 3.1.1 only: no SMB 1,
2.x or 3.0.x code, so a server without 3.1.1 is refused (SecurityPolicy,
"the server does not support SMB 3.1.1 ...").

**Security.** NEGOTIATE offers dialect 0x0311 alone, with the preauth
integrity context (SHA-512, a random 32-byte salt), the ciphers AES-128-GCM
and AES-256-GCM, and AES-128-CMAC signing; a response that picks anything
else, or lacks the preauth context, is refused. The profiles (`profile.rs`,
option `security_profile`):

| Profile | Signing | Encryption | Account |
|---|---|---|---|
| `strict` (default) | required | every request after SESSION_SETUP, and every response must be encrypted; a server without a common cipher is refused before SESSION_SETUP | NTLMv2 |
| `signed` | required | where the server marks the session or the share (ENCRYPT_DATA); marked without a cipher: refused | NTLMv2 |
| `guest` | none | none; a server that wants it: refused | NTLMSSP anonymous |

Any other value is SecurityPolicy. Outside `guest` a session the server
marks IS_GUEST or IS_NULL is refused (XM-1), and the final SESSION_SETUP
response must be signed with the new session's key (MS-SMB2 3.2.5.3.1),
which also proves the server knows the password. After that, a response
that is not encrypted (`strict`, or marked; error and interim responses
too) or not validly signed (`signed`; interim STATUS_PENDING responses
excepted, MS-SMB2 3.2.5.1.3) ends the connection; so does one for another
session, one that answers no outstanding request, a compressed frame or a
request.
Interim responses (STATUS_PENDING) are not verified on a signed,
unencrypted connection; at most 8 are accepted per request.
NTLMv2 and SPNEGO come from `sspi` (no Kerberos, no network of its own);
sspi checks the server's mechListMIC, and the user name `/GUEST`, for which
sspi skips that check, is refused, as is a password that sspi would take
for an NT hash (`$NTLM$`). The exported session key of the NTLM key
exchange (KEY_EXCH) is encrypted with sspi's own RC4; `tests/sspi_ntlm.rs`
pins sspi's output against RustCrypto's RC4.

**The crypto fence.** netvfs-smb implements no primitive: AES-GCM, CMAC,
HMAC-SHA256 and SHA-512 come from RustCrypto, and they are imported by one
module only, `crypto.rs`, which holds the MS-SMB2 glue: the preauth hash
chain, the SP800-108 key derivation (HMAC-SHA256, one block, labels with
their trailing NUL), CMAC signing and its constant-time verification, and
TRANSFORM_HEADER sealing and opening (AAD: header bytes 20 to 52; a
per-session nonce counter, and the session ends before it would wrap).
`tools/ci/check-crypto-fence.sh` (in `make check-rust`) fails if any
other source file of the crate names a RustCrypto crate or `getrandom`.
Every function of the module has known-answer tests (the Microsoft Open
Specifications vectors for 3.1.1, and a Wireshark AES-256-GCM capture) and
tests that one flipped bit of key, nonce, AAD, tag or signature fails; the
full-crate cargo-mutants run must catch every mutant of the module.

**Connection** (`conn.rs`). One TCP connection per backend, with one
session; every share is a tree of it. A receive task matches responses to
requests by message id; requests wait for credits (multi-credit READ and
WRITE, CreditCharge per 64 KiB), a STATUS_PENDING interim keeps a request
waiting (bounded), and a request whose caller goes away is sent a CANCEL,
its credits coming back with the final response. A namespace operation is
one compound of CREATE, the related requests and CLOSE (stat: CREATE and
CLOSE; rename, times and delete: SET_INFO; free space: QUERY_INFO; a
listing's first batch: QUERY_DIRECTORY). Keep-alive is ECHO. Every length
from the wire is checked against its cap before anything is allocated
(frames: what NEGOTIATE allows; READ and IOCTL output: what was asked
for).

**Files.** CREATE, CLOSE, READ, WRITE, FLUSH, QUERY_DIRECTORY, QUERY_INFO
and SET_INFO (times; rename with ReplaceIfExists, so AtomicReplace; delete
on close). Transfers and read handles keep up to 4 MiB in flight in chunks
of the server's maximum, at most 1 MiB (64 KiB without multi-credit).
Names are UTF-16LE on the wire and WTF-8 in netvfs (XC-4): a lone
surrogate keeps its three-byte form both ways. A listing leaves out names
that are empty, `.`, `..`, or contain `/` or NUL (`names::is_entry_name`,
XC-6), and delivers the rest. A DFS link is Unsupported
with the detail "DFS referral" (XM-9). NT statuses map to netvfs errors
as SPEC-smb 5 says (`status.rs`); during sign-in a refusal that is about
neither the credentials nor the share name is SecurityPolicy.

**Server mode.** Without option `share` the root lists the shares: IPC$
is connected at sign-in, and the list comes from srvsvc NetrShareEnum
level 1 over its pipe, in process (`rpc.rs`: DCE/RPC bind, request and
fragments, NDR decoding with every count and string capped). Saved names
(`shares`) come first; disk shares only, `$` shares with
`show_admin_shares`. At most four shares are connected at a time; the
least recently used is disconnected for a fifth, never one with open
handles (TooManyConnections).

**Tests.** Unit tests for every codec (and the refusal of each over-long
field), the crypto vectors and bit flips, NDR, names, the profile and
error tables, and the connection, session, file and backend logic against
a fake server in the test process (`fake.rs`); `tests/sspi_ntlm.rs` pins
sspi's NTLMv2 output against MS-NLMP 4.2.4 with RustCrypto's MD5 and RC4
(test only). `tests/samba.rs` runs the crate against the Samba containers
of `tests/interop/smb` (run.sh sets `NETVFS_INTEROP_SMB_*`; without them
the tests pass at once, saying so, and `tools/ci/rust-mutants.sh` starts
the servers itself for netvfs-smb's mutants): dialects, ciphers and profiles,
refusals, tampered replies through the flip proxy, stalls, a round trip
and server mode. `tests/windows.rs` does the same against Windows's own
server in the CI job "SMB against Windows" (M-T11). The C++ suites
(`tests/interop/smb`, the conformance suite's SMB targets) run through the
shim.

## Lints

Set once for the workspace in `rust/Cargo.toml`:

- clippy `all` and `pedantic` at deny, plus a picked nursery set
  (`significant_drop_in_scrutinee`, `significant_drop_tightening`,
  `redundant_clone`, `use_self`, ...) and restriction set (`map_err_ignore`,
  `assertions_on_result_states`, `dbg_macro`, `print_stdout`,
  `undocumented_unsafe_blocks`, `clone_on_ref_ptr`, ...);
- no panics and no silent overflow in shipped code: `unwrap_used`,
  `expect_used`, `panic`, `unwrap_in_result`, `indexing_slicing`,
  `arithmetic_side_effects`, `string_slice` (tests may unwrap, panic and
  index: `rust/clippy.toml`, and `allow` on test modules for the rest);
- rustc: `unsafe_code` denied except in the modules that talk to C (the
  helper's `sandbox`), `missing_docs`, `unused_qualifications`,
  `trivial_casts`, `unsafe_op_in_unsafe_fn`.

## Parity with libaccounts

The helper reads `accounts.db` as libaccounts-glib 1.27 (Sailfish OS 5.2)
stores it and converts values as libaccounts-qt 1.17 reads them; where the
host's 1.26/1.16 differ from these, the paths the helper uses do not. In
particular a setting whose text does not parse is a key without a value
(`got_account_setting`), and a credentials id is read as an `int`. An
attention write is one transaction in the style of libaccounts-glib, and the
signal is the one its writers send (`signal_account_changes`), from a bus
name of its own, as Sailjail requires.

## Tests

| What | Where | Run by |
|---|---|---|
| Format, clippy (the lints above), tests with `cargo nextest`, doc tests, lockfile, Rust 1.95 | `rust/` | `make check-rust` (part of `make check`; CI: profile `ci` of `rust/.config/nextest.toml`, no retries) |
| Golden tests: every answer byte for byte against the C++ helper, kept as a test-only reference (`referencehelper.cpp`), and read back with a C++ decoder (`referencedecoder.cpp`); about 95 stored values, account shapes, attention writes and refused writes | `tests/bridge/accounts` | `make check-unit` |
| A live libaccounts-qt manager sees the attention write through the signal | `tests/bridge/accounts` (`attentionSignal`) | `make check-unit` |
| Each part of the confinement in a fresh process, also from setgid copies | `rust/netvfs-accounts/tests/sandbox.rs` | `make check-rust` |
| netvfs-bridge's `ffi` module against the built `libnetvfs-bridge-ffi.so` and the fake backend: loading, establish (identity verdicts, prompts, phases, signond on the Qt thread), listing, walk, remove tree, handles, transfers through `nvb_io`, a cancel from another thread, copy across, URLs, error mapping, post/quit, panics in callbacks, discovery, no block left unfreed (heap growth over many calls) | `rust/netvfs-bridge/tests/ffi.rs` (its own harness: `init` needs the main thread; a test hung for 30 s fails) | `make check-rust-ffi` (part of `make check`); without the libraries every case says it is skipped |
| The FFI's C ABI from C++ (and its marshalling into one block per result) | `tests/bridge/ffi` | `make check-unit` |
| `libnetvfs-rs.so`'s table against the `mem` backend from Rust, as the shim calls it: every function, results and errors, callbacks, handles, transfers, cancel from another thread and the 1 s cut, one call at a time, a connection moving between threads, the two named workers, panics, no block or object left (counters of the `testing` build) | `rust/netvfs-backend/tests/ffi.rs` (nextest runs each test in a process of its own) | `make check-rust` |
| netvfs-sftp: the codecs, the client, the file operations and transfers against an SFTP server in memory; session, sign-in and the `Backend` against an SSH server in the test process; the key tools against key files of ssh-keygen and openssl (`testdata/keys`) | `rust/netvfs-sftp/src` | `make check-rust` |
| netvfs-sftp against OpenSSH 10.3p1, 9.6p1 and 8.9p1: negotiated algorithms, refusals of weaker servers, pins, sign-in, capabilities, cancel and timeouts | `rust/netvfs-sftp/tests/openssh.rs` | `make check-interop` (the end of `tests/interop/sftp/run.sh`) |
| The SFTP plugin: the key tools through it, connection failures without a server | `tests/unit/sftp` (`tst_sftp`) | `make check-unit` |
| The shim against the `mem` backend: loading (`NETVFS_RS_LIB`, a missing library), the plugin, conversions both ways, the callbacks and what they throw, cancel and the prompter, one call at a time, panics, calls from other threads; and the conformance suite on `mem` through the shim (`tests/backends/rs/conformance/mem.json`) | `tests/backends/rs` (`tst_rsshim`, the test plugin `libnetvfs-mem.so`, the library from the `rs-test` profile) | `make check-unit`, also under `SANITIZE=1` (the library uninstrumented) |
| The built `netvfs-bridge` as a black box from a libdbus client (`tests/bridge/common`): the introspection XML byte for byte, the `Peer` interface, an unknown path, fd passing both ways, error details, and every golden sequence of the contract, with the fake backend seeded through `NETVFS_FAKE_SEED` and a scripted accounts helper | `tests/bridge/contract` (`tst_contract`) | `make check-unit` |
| The built `netvfs-bridge` under socket activation (the test plays systemd), listing through the built `netvfs-accounts` against a libaccounts database; exit codes for an unknown consumer and a usage error | `tests/bridge/process` (`tst_bridgeprocess`) | `make check-unit` |
| The target build: tests under qemu, smoke run, linked libraries | see "Cross build" | CI job "Sailfish OS 5.2 aarch64 RPMs" |
| Mutations the tests must catch: curated lists, and cargo-mutants on every line a pull request changes (with the FFI's C++ libraries built by `tools/ci/ffi-libs.sh`, so `tests/ffi.rs` runs; exclusions with reasons in `rust/.cargo/mutants.toml`) | `tests/mutations/helper.json`, `bridge.json`, `ffi.json`, `rs.json` (the shim), `sftp.json` (netvfs-sftp, caught by `tst_sftp` and the interop driver), `smb.json` (netvfs-smb, through the interop suite and its own tests); `tools/ci/rust-mutants.sh diff <base> [<ffi-libs dir> [<k>/<n>]]` | CI matrix `helper`, `bridge`, `ffi`, `rs`, `sftp`, `smb` (with the SFTP or Samba servers started once); CI jobs "Tests bite (Rust, changed code, k/12)" |
| cargo-mutants on a whole crate, before the pull request of a new crate merges | `tools/ci/rust-mutants.sh crate <package> [<ffi-libs dir> [<k>/<n>]]` | workflow "Mutants (full crate)" (`mutants.yml`, by hand, 12 shards) |
| cargo-mutants with a test command of its own per mutant, for code whose real tests are suites through the C++ side or the interop containers: each mutant must build and make the command fail | `tools/ci/rust-mutants.sh interop <package> <base or all> <k>/<n> <command>` (`rust-mutants-command.py`) | by hand, e.g. `... interop netvfs-backend all 0/12 'make -s -C build/tests/backends/rs check'` |
| Fuzzing: stored values, bus replies, arguments, the FFI marshalling (`ffi_marshal`: parameters, entries, identities into their C form and back), UDisks2's answer to `GetManagedObjects` (`udisks_objects`: decoded and classified into drives), the SFTP client (`sftp_packet`: the decoders, and a fake server's replies to every file operation; `sftp_attrs`: attributes decoded, encoded and decoded again), key import (`ssh_key_import`); what an SMB server sends: responses (`smb_response`), TRANSFORM_HEADER and signing round trips with bit flips (`smb_transform`), the NTLM challenge (`ntlm_challenge`), SPNEGO (`spnego`), the srvsvc share list (`ndr_share_enum`); what a target found stays as a seed in `rust/fuzz/seeds/<target>` | `rust/fuzz` | `./tools/ci/rust-fuzz.sh <seconds>` (nightly) |
| netvfs-smb against Samba (the interop containers) and against Windows | `rust/netvfs-smb/tests/samba.rs`, `windows.rs` | `tests/interop/smb/run.sh` (`make check-interop`); CI job "SMB against Windows" |
| The crypto fence: RustCrypto in netvfs-smb's `crypto` module only | `tools/ci/check-crypto-fence.sh` | `make check-rust` |
| Advisories, yanked crates, licences, sources | `rust/deny.toml` | CI job "Rust supply chain"; advisories again weekly |
| Tests under ASan + LSan (the FFI test with the C++ side instrumented too, see below; netvfs-backend's `tests/ffi.rs` with the library's code instrumented), the current stable's clippy, the online workflow audit | `.github/workflows/scheduled.yml` (weekly, or by hand: `workflow_dispatch`) | `./tools/ci/rust-sanitize.sh <nightly> [<ffi-libs dir>]` |
| Workflow audit: no credentials left in checkouts, no `${{ }}` in `run:` | `.github/workflows` | CI job "Workflow audit" (`zizmor --offline`) |
| Coverage for Sonar | `build-coverage/rust-lcov.info` | `make coverage` |
| Clippy findings for Sonar | `build-coverage/clippy.json` | `make COVERAGE=1 clippy-report` |

`make check-rust` needs `cargo-nextest`
(`./tools/ci/cargo-tool.sh cargo-nextest 0.9.148`). `make check-rust-ffi`
runs every test of netvfs-bridge again, in the same build as
`make check-rust` (features `testing` and `test-bins`), with
`NETVFS_BRIDGE_FFI`, `NETVFS_BRIDGE_FFI_FAKE` and `NETVFS_BACKEND_PATH`
pointing into the build tree, so the tests that need the C ABI (`ffi`,
`backend`, `server`, and `process`, `contract`, `notifications`, `accounts`
through the cargo-built binary) run instead of saying they are skipped;
under `SANITIZE=1` it preloads gcc's ASan and UBSan runtimes, which the
instrumented libraries need first in the process (the bridge binary those
tests start inherits the preload).

The weekly ASan job checks the boundary from both sides. `rustc
-Zsanitizer=address` links LLVM's ASan runtime into the test binary; gcc's
libasan would be a second runtime, so `tools/ci/ffi-libs.sh <dir> --asan`
builds only the libraries the FFI test loads (libnetvfs, libnetvfstest, the
fake plugin, `libnetvfs-bridge-ffi.so`, its fake control table) with clang
and `-fsanitize=address` alone: clang leaves the `__asan_*` symbols of a
shared library undefined and the executable's runtime provides them; the
test binaries are linked with `--export-dynamic` so that the dynamic loader
sees that runtime. The clang must be of rustc's LLVM major (an older
clang's instrumentation against a newer runtime is not a combination LLVM
supports; rust-sanitize.sh refuses it), so the weekly job installs
`clang-<major>` from apt.llvm.org (`tools/ci/install-clang.sh`, the key
pinned by fingerprint) and builds with it (`CLANG_MAJOR=<major>
ffi-libs.sh`). `rust-sanitize.sh <nightly> <dir>` then points the test
at them; it builds the dev profile with `panic = "unwind"`, since std
rebuilt under `panic = "abort"` does not build for tests. Qt itself is not
instrumented; LSan uses `tools/sanitizer/lsan.supp`.
`make coverage` builds the helper, the bridge and the `rs-test` build of
`libnetvfs-rs.so` with `-C instrument-coverage`; the helper's confinement
lets it write its counters to `build-coverage/rust-coverage` only in that
build (`NETVFS_RUST_COVERAGE_DIR`). The bridge writes its counters when it exits,
so the C++ tests let it end with its idle exit instead of killing it.

## Choices

- Written for Rust 1.95 and cross-built with a host cargo against the
  SDK's compiler and sysroot. The bridge needs crates that the SDK's Rust
  (1.75) cannot build (zbus 5), and all Rust code uses one toolchain.
- The FFI bindings are written by hand from the frozen header rather than
  generated by bindgen (which needs libclang at build time); tests pin the
  sizes and offsets that gcc gives the header on LP64.
- Landlock and seccomp through raw syscalls rather than crates: the code is
  small, handles Landlock ABI 1 to 7 itself and adds no crate to review in
  the privileged process.
- A minimal D-Bus client (one signal, `Hello`, `RequestName`, `GetId`) rather
  than zbus, which would bring an async runtime and many crates into it.
- A curated mutation list in the format `tools/mutation-check.py` already
  runs for the C++ parts, plus cargo-mutants on the lines each pull request
  changes, and on the whole of a new crate before it merges.
- The Rust backends as one library behind thin C++ plugins rather than
  native in the bridge: libnetvfs, its C++ users and the bridge's C ABI keep
  one backend interface.
