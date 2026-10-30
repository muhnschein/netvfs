# Rust in netvfs

Rust parts:

- `netvfs-accounts` (package netvfs-bridge): setgid accounts helper. Requests `list`, `files <id>`, `attention <id> <state> [pin]`; `QDataStream` answer on stdout. Process with group `privileged` links libc, libgcc_s, libsqlite3 only: no Qt, GLib, libaccounts, GIO modules. All `unsafe` in `sandbox.rs` (descriptors, set-id, Landlock, seccomp).
- `netvfs-bridge` (package netvfs-bridge): only netvfs process a sandboxed consumer reaches. Everything a consumer sends decoded and checked in Rust: zbus p2p server with own inbound limits, peer check, argument validation, consent, locations, questions, jobs. Reaches backends through `libnetvfs-bridge-ffi.so` (`src/bridge/ffi`, C ABI `netvfs_bridge_ffi.h`, one export), `dlopen`ed from `/usr/lib64/netvfs`. Binary links libc, libgcc_s, libm only. Protocol = `tests/bridge/contract`.
- `libnetvfs-rs.so` (package netvfs): Rust backends `sftp`, `smb` (own SMB 3.1.1 client), `mem` (tests). C++ plugins (`src/backends/rs` shim) `dlopen` it from `/usr/lib64/netvfs`; C ABI `src/backends/rs/netvfs_rs.h`: `nvr_get()` returns one table.

Rest is C++.

## Layout

| Path | What |
|---|---|
| `rust/Cargo.toml` | workspace: version, `rust-version`, lints, profiles |
| `rust/netvfs-accounts/` | helper: `db.rs` libaccounts database, `gvariant.rs`, `qvariant.rs`/`wire.rs` answer, `policy.rs`/`store.rs`/`serve.rs` requests, `dbus.rs` `AccountChanged`, `sandbox.rs` confinement, `bin/probe.rs` tests only |
| `rust/netvfs-bridge-proto/` | `org.netvfs.Bridge1`: names, method table, signals, served XML, error names, limits, client (from lautta); `fake/` (feature `fake`) lautta's fake bridge and replayer |
| `rust/netvfs-vfs/` | shared by bridge and backends: backend types, async `Backend`/`ReadHandle`/`WriteHandle`, `CancelToken`, `Status`, `nvb_*` types of both C ABIs (`abi.rs`); no `unsafe` |
| `rust/netvfs-bridge/src/ffi/` | C ABI client: `raw.rs` table, `loader.rs` `dlopen` (`NETVFS_BRIDGE_FFI` for tests), `conn.rs` handles, `callback.rs` trampolines, `marshal.rs`, `discovery.rs` |
| `rust/netvfs-bridge/src/server/` | socket front: listener, peer check, sessions, inbound limits (2 MiB, 2 fds), dispatch, `args.rs`/`paths.rs` validation, `encode.rs`, `flow.rs` outgoing budget |
| `rust/netvfs-bridge/src/core/` | task owning state: sessions, consent, quotas, questions, discovery, connection states, drives, method handlers |
| `rust/netvfs-bridge/src/locations/`, `jobs/` | visible locations, pools and lanes, worker threads owning backend connections, known hosts; listings, walks, removals, transfers (`fdio.rs`: consumer's fds) |
| `rust/netvfs-bridge/src/accounts/`, `drives/` | helper as bridge runs it; memory cards and USB drives via UDisks2 (`classify.rs` pure, fuzzed) |
| `rust/netvfs-bridge/src/sys/` | libc calls: socket, peer creds, pidfd, fds, inotify, `flock` |
| `rust/netvfs-backend/` | `libnetvfs-rs.so`: `ffi/` table, `runtime.rs` tokio runtime and cancel cut, `erased.rs`, `providers.rs`, `mem/` (feature `testing`) |
| `rust/netvfs-sftp/` | `policy.rs` algorithms, `session.rs`, `auth.rs`, `keys.rs`, `wire.rs`/`proto.rs`/`client.rs` SFTP v3, `remote.rs`, `io.rs`, `backend.rs` |
| `rust/netvfs-smb/` | `transport`, `msg/` codecs, `negotiate`, `auth` (sspi), `crypto`, `conn`, `session`, `fs`, `files`, `rpc` (srvsvc), `names`, `status`, `profile`, `backend` |
| `src/bridge/rust/rust.pro`, `src/backends/rs/rs.pro` | qmake targets running cargo |
| `rust/fuzz/` | cargo-fuzz targets (nightly, outside workspace) |
| `rust/vendor/ssh-key/`, `rust/vendor/picky-asn1-der/` | patched copies, outside workspace |

## Dependencies

Why each is here; new one → line here.

- `libc`: syscalls. `rusqlite` (system libsqlite3, not bundled): helper's database.
- `zbus` 5 (`tokio`, `p2p`; bridge also `bus-impl`), `tokio`, `futures-lite` (in zbus's tree): bridge and protocol crate.
- `serde`: protocol crate. `serde_json`, `sha2`: test-only features (`fake`, `testing`).
- `zeroize`: secrets.
- `russh` exactly 0.64.1 (default features off, `ring`, `rsa`): SSH transport; netvfs links no OpenSSL. Pins RustCrypto pre-releases: bump as one unit. `data-encoding`, `pkcs8` (in russh's tree): key files, encrypted PKCS#8 parameters read before russh decrypts.
- `ssh-key` 0.7.0-rc.11 from `rust/vendor/ssh-key`: one line changed, ECDSA private scalar shorter than field size left-padded (OpenSSH stores ~1 in 256 P-256 keys with 31 bytes). `README.netvfs.md` there: checksum, diff.
- `sspi` 0.23 (default features off): NTLMv2 in SPNEGO, incl. RC4 of NTLM key exchange. No Kerberos.
- `picky-asn1-der` 0.5.7 from `rust/vendor/picky-asn1-der`: one line changed, `checked_add` on raw DER length so near-`usize::MAX` length is `TruncatedData`. `README.netvfs.md` there.
- `aes`, `aes-gcm`, `cmac`, `hmac`, `sha2`, `getrandom`: SMB 3.1.1 crypto, only in `netvfs-smb`'s `crypto.rs` (fence: `tools/ci/check-crypto-fence.sh`). `md-5`, `rc4`: one test.

Vendored copies: patched via `[patch.crates-io]` in `rust/Cargo.toml` and `rust/fuzz/Cargo.toml`; outside fmt, clippy, tests, mutants, Sonar, coverage. `rust/deny.toml`: second versions of `syn`, `getrandom`, `sha3`, `base64`, `generic-array`, each with reason.

## Toolchain

- Rust 1.95, edition 2024: rustc `sailfishos/rust` merges next. `rust-version` 1.95; `rust/rust-toolchain.toml` pins 1.95.0. Weekly `scheduled.yml` adds current stable's clippy.
- `tools/ci/check-lockfile.sh` (in `make check-rust`): lockfile cargo 1.95 reads, no crate needing newer Rust; plus `cargo +1.95.0 check --locked`. Update: `cd rust && cargo update -p <crate>` (resolver v3 prefers fitting `rust-version`).

## Cross build

No SDK target ships rustc 1.95: RPM job builds Rust with host cargo against SDK's compiler and sysroot; spec only installs binaries (so no OBS/Chum rebuild). Host needs `libc6-i386`, `qemu-user-static`.

| Step | Script |
|---|---|
| Lift `/opt/cross`, host libs and target sysroot from pinned 5.2.0.15 SDK image; binutils names, linker wrapper, unversioned `libsqlite3.so` | `tools/ci/lift-sdk.sh <image> <target> <dir>` |
| `cargo build --release` for `aarch64-unknown-linux-gnu`: PIE, full RELRO, `-z now`, NX stack; `libnetvfs-rs.so` with `--profile rs-release` (no PIE) | `tools/ci/cross-build.sh <dir> rust/prebuilt` |
| Workspace tests for target under `qemu-aarch64-static` (confinement tests native only) | `tools/ci/cross-build.sh <dir> <out> test` |
| Cross-built helper answers `list`/`files` byte for byte as host build; bridge starts, loads its C ABI | `tools/ci/cross-smoke.sh` |
| NEEDED libs, GLIBC floor, PIE, RELRO, BIND_NOW, NX of packaged binaries; `libnetvfs-bridge-ffi.so` exports only `nvb_ffi_get`; `libnetvfs-rs.so` exports only `nvr_get`, links only libc, libgcc_s, libm, libpthread, libdl, ld.so | `tools/ci/check-linked-libs.sh`, `check-ffi-lib.sh`, `check-rs-lib.sh` (from `check-rpm.sh`, `make check-packaging`) |

`tools/ci/build-rpm.sh` cross-builds itself when `rust/prebuilt` is empty. Once SDK ships 1.95: drop cross job, spec runs cargo (`rust.pro` builds unless `NETVFS_RUST_PREBUILT`).

## Build

- `src/bridge/rust/rust.pro`: one `cargo build --release --locked` for bridge and helper, copied to build tree's `libexec/netvfs` (C++ tests run them there), installed to `/usr/libexec/netvfs`. qmake vars: `NETVFS_CARGO`, `NETVFS_RUST_TARGET`, `NETVFS_CARGO_FLAGS`, `NETVFS_RUST_PREBUILT` (RPM: `rust/prebuilt`).
- `src/backends/rs/rs.pro`: `cargo build --profile rs-release -p netvfs-backend --lib` → build tree's `lib/netvfs`, installed to `/usr/lib64/netvfs`.
- Profiles: binaries abort on panic; library must unwind so table function reports panic as Internal, and cargo sets `panic` per profile. Hence `rs-release` (release + unwind + fat LTO) and `rs-test` (dev + unwind, `--features testing`, for C++ tests).

## libnetvfs-rs.so rules

- No version handshake: library and plugins ship in one package.
- Shim opens it `RTLD_NOW | RTLD_LOCAL` on first use (`NETVFS_RS_LIB` for tests); missing → Internal "netvfs Rust backends not installed".
- Every result one `malloc`ed block freed (key material wiped) by table's `free`; `catch_unwind` around every function; nothing unwinds into C.
- One tokio runtime per process, workers `nvr-io-0`, `nvr-io-1`. Table functions `block_on` on caller's thread; callbacks run there before return.
- One call per connection at a time, any thread; overlap or call from own callback → Internal "The connection is busy: one call at a time, none from a callback".
- `cancel` from any thread trips `CancelToken`; call missing it dropped 1 s later (`GRACE`) → Canceled, so 2 s cancel bound holds. Teardown runs with token tripped; `reset_cancel` clears.
- Shim: C++ callback exceptions stay in C++ (Internal "A callback of the Rust backend failed"); capabilities fixed after `authenticate`.

## Lints

Workspace `rust/Cargo.toml`: clippy `all`, `pedantic` deny plus picked nursery and restriction lints; no panics or silent overflow in shipped code (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `string_slice`, …; tests exempt via `rust/clippy.toml` and module `allow`); rustc `unsafe_code` (allowed only in helper's `sandbox`, bridge's `ffi` and `sys`, backend's `ffi`; netvfs-smb forbids), `missing_docs`, `unused_qualifications`, `trivial_casts`, `unsafe_op_in_unsafe_fn`; `undocumented_unsafe_blocks`: every `unsafe` block has `// SAFETY:`.

## Tests

`make check-rust` (in `make check`): fmt, clippy, `cargo nextest` (profile `ci`, no retries), doc tests, lockfile, 1.95, crypto fence. Needs `./tools/ci/cargo-tool.sh cargo-nextest 0.9.148`.

- `make check-rust-ffi`: netvfs-bridge tests again with `NETVFS_BRIDGE_FFI`, `NETVFS_BRIDGE_FFI_FAKE`, `NETVFS_BACKEND_PATH` into build tree, so `ffi`, `backend`, `server`, `process`, `contract`, `notifications`, `accounts` run instead of skipping. `SANITIZE=1`: preloads gcc ASan/UBSan.
- `rust/netvfs-bridge/tests/ffi.rs`: own harness (`init` needs main thread; 30 s hang fails).
- `rust/netvfs-backend/tests/ffi.rs`: table against `mem`, process per test.
- `tests/bridge/accounts`: helper answers byte for byte vs C++ reference helper (`referencehelper.cpp`), read back by `referencedecoder.cpp`; live libaccounts-qt sees attention write.
- `tests/bridge/contract` (`tst_contract`), `tests/bridge/process`, `tests/bridge/ffi`, `tests/backends/rs` (`tst_rsshim`, also `SANITIZE=1`), `tests/unit/sftp`: C++ side, `make check-unit`.
- Interop: `rust/netvfs-sftp/tests/openssh.rs` (OpenSSH 10.3p1, 9.6p1, 8.9p1; `NETVFS_SFTP_INTEROP_CONFIG` from `tests/interop/sftp/run.sh`), `rust/netvfs-smb/tests/samba.rs` (`NETVFS_INTEROP_SMB_*` from `tests/interop/smb/run.sh`), `windows.rs` (CI job "SMB against Windows"). Without settings: pass at once, say skipped.
- Mutants: `tools/ci/rust-mutants.sh diff <base> [<ffi-libs dir> [<k>/<n>]]` (PR CI, 12 shards; starts interop servers itself), `crate <package>` (new crate, `mutants.yml`), `interop <package> <base|all> <k>/<n> <command>` (mutant vs custom command). Exclusions with proof: `rust/.cargo/mutants.toml`. Curated lists: `tests/mutations/*.json`.
- Fuzz: `rust/fuzz`, `./tools/ci/rust-fuzz.sh <seconds>` (nightly); finds stay as seeds in `rust/fuzz/seeds/<target>`.
- Weekly ASan: `tools/ci/rust-sanitize.sh <nightly> [<ffi-libs dir>]`. rustc's LLVM ASan runtime in test binary; `ffi-libs.sh <dir> --asan` builds C++ libs with clang of rustc's LLVM major (`install-clang.sh`), `-fsanitize=address` only, binaries `--export-dynamic`. Qt uninstrumented; LSan `tools/sanitizer/lsan.supp`.
- `make coverage`: `-C instrument-coverage`; helper writes counters only to `NETVFS_RUST_COVERAGE_DIR`; bridge writes on exit, so C++ tests let it idle-exit.
- `cargo deny`: CI "Rust supply chain", advisories weekly. CodeQL: `.github/codeql/` (Rust query `hard-coded-cryptographic-value` with planted-case test).

## Choices

- Hand-written FFI bindings from frozen headers, no bindgen (no libclang at build); tests pin LP64 sizes and offsets.
- Landlock, seccomp via raw syscalls: small, handles Landlock ABI 1–7, no crate in privileged process.
- Helper's D-Bus: minimal client (`Hello`, `RequestName`, `GetId`, one signal), not zbus (no async runtime in privileged process).
- Rust backends as one library behind thin C++ plugins: libnetvfs, C++ users and bridge's C ABI keep one backend interface.
