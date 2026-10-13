# Rust in netvfs

Two programs of the package netvfs-bridge are written in Rust:

- `netvfs-accounts`, the setgid accounts helper (SPEC-v2 XB-2a), since 0.4.0.
  It is a drop-in replacement for the C++/Qt helper it replaced: the same
  requests (`list`, `files <id>`, `attention <id> <state> [pin]`), the same
  `QDataStream` answer on stdout, the same confinement. What it gains: the
  process that holds the group `privileged` links libc, libgcc_s and
  libsqlite3 only, no Qt, GLib, libaccounts or GIO modules, and every
  `unsafe` call is in one module (`sandbox.rs`).
- `netvfs-bridge` (SPEC-v2 §8a), since 0.5.0: the one netvfs process a
  sandboxed consumer can reach. Everything a consumer sends is decoded and
  checked in Rust: zbus as the peer-to-peer D-Bus server with the bridge's
  own inbound limits, the peer check, the argument validation (XSEC-7),
  consent, locations, questions and jobs. The C++ backends stay; the bridge
  reaches them through `libnetvfs-bridge-ffi.so` (`src/bridge/ffi`, the C
  ABI of `netvfs_bridge_ffi.h`), which it loads with `dlopen` from
  `/usr/lib64/netvfs` and which exports one symbol. The binary links libc,
  libgcc_s and libm only; Qt and libnetvfs come with that library. Its
  protocol (`tests/bridge/contract`), command line and files are those of
  the C++/Qt bridge of 0.4, which it replaces.

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
| `rust/netvfs-bridge/src/ffi/raw.rs` | the C ABI of `libnetvfs-bridge-ffi.so` by hand (`#[repr(C)]`, no bindgen), sizes and offsets pinned by tests |
| `rust/netvfs-bridge/src/ffi/loader.rs`, `mod.rs` | `dlopen` (`RTLD_NOW \| RTLD_LOCAL`, `/usr/lib64/netvfs/libnetvfs-bridge-ffi.so`, `NETVFS_BRIDGE_FFI` for tests), version and size check; `Ffi`: init/run/post/quit on the Qt thread, URLs, `conn_new` |
| `rust/netvfs-bridge/src/ffi/conn.rs` | `Conn` and `Handle` (`!Send`, owner thread, T4), `CancelHandle` (any thread; shares a lock with `conn_free`) |
| `rust/netvfs-bridge/src/ffi/callback.rs` | the trampolines (list sink, walk, progress, `nvb_io`, establish hooks, discovery, `post`): panics caught, never into C++ (T7); connection calls refused inside a callback (T6) |
| `rust/netvfs-bridge/src/ffi/marshal.rs` | plain Rust values both ways: `ParamsBuf` (owns the `nvb_kv`/`nvb_bytes` arrays of a call), readers of C++'s blocks and callback arguments |
| `rust/netvfs-bridge/src/ffi/discovery.rs` | `Discovery` (XD-5), Qt thread only (T3) |
| `rust/netvfs-bridge/src/ffi/fake.rs` | tests only (feature `testing`): the fake backend's control table (`NETVFS_BRIDGE_FFI_FAKE`) |
| `rust/netvfs-bridge/src/status.rs` | `Status`: XC-21 name, message, detail, retry time |
| `rust/netvfs-bridge/src/main.rs` | the binary: `[--listen ADDRESS] <consumer-id>` (default `systemd:`, fd 3), the Qt loop on the main thread and the bridge on the thread `nvb-rt`, exit codes 0 (idle exit), 1, 2 (usage) |
| `rust/netvfs-bridge/src/server/` | the socket front: listener, peer check, one session per connection (zbus p2p server, EXTERNAL, fd passing), inbound limits (`inbound.rs`: 2 MiB, 2 descriptors), dispatch (`Peer`, `Introspect` and unknown members answered by the bridge itself), argument validation (`args.rs`, `paths.rs`), replies and signals (`encode.rs`), the outgoing FIFO and its byte budget (`flow.rs`, C-10) |
| `rust/netvfs-bridge/src/core/` | the task that owns the state: sessions, consent, quotas (XB-17), questions, discovery, the handlers of every method |
| `rust/netvfs-bridge/src/locations/`, `jobs/` | the locations a consumer may see, connection pools and lanes (XB-12), the worker threads that own the backend connections, known hosts; the bodies of listings, walks, removals and transfers (`fdio.rs`: the consumer's descriptors, XB-11) |
| `rust/netvfs-bridge/src/accounts/` | `netvfs-accounts` as the bridge runs it, its answers (`qds.rs`), the `AccountChanged` watch |
| `rust/netvfs-bridge/src/config.rs`, `consent.rs`, `prompt.rs`, `handoff.rs`, `log.rs` | consumer files and the environment, `bridge.conf` (Qt's INI format, `ini.rs`, with a `QLockFile`-compatible lock, `lockfile.rs`, saved as `QSaveFile` does, `savefile.rs`), the consent notification, the settings handoff, logging (`QT_LOGGING_RULES`) |
| `rust/netvfs-bridge/src/sys/` | the libc calls of the bridge: the listening socket, peer credentials and pidfd, descriptors, inotify, `flock`, a zbus message from a frame |
| `rust/netvfs-bridge/src/testing.rs`, `testutil.rs`, `bin/accounts_fake.rs` | tests only (features `testing`, `test-bins`): fixtures, a private bus, `netvfs-accounts-fake` |
| `src/bridge/rust/rust.pro` | the qmake target that builds both binaries with cargo (see "Build") |
| `rust/fuzz/` | cargo-fuzz targets (nightly, not in the workspace) |

Dependencies: `libc` and `rusqlite` (without the bundled SQLite: the system
libsqlite3 through pkg-config). The protocol crate: `zbus` 5 (`tokio`, `p2p`),
`tokio`, `serde`, `zeroize` and `futures-lite` (already in zbus's tree);
`serde_json` and `sha2` only behind its test-only `fake` feature.
netvfs-bridge: the protocol crate, `libc`, `zeroize`, `zbus` 5 (`tokio`,
`p2p`, `bus-impl`), `tokio` and `futures-lite`.

`unsafe` is allowed in the helper's `sandbox` and in netvfs-bridge's `ffi`
and `sys` modules only; every block says why it holds. The `ffi` module keeps the threading and ownership rules of
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
| `cargo build --release` for `aarch64-unknown-linux-gnu` with that linker, PIE, full RELRO, `-z now`, no executable stack | `tools/ci/cross-build.sh <dir> rust/prebuilt` |
| The workspace's tests for the target under `qemu-aarch64-static`, against the target's glibc and SQLite (the confinement tests run natively only) | `tools/ci/cross-build.sh <dir> <out> test` |
| The cross-built helper's answers to `list` and `files` equal the host build's, byte for byte; the cross-built bridge starts and gets as far as loading its C ABI | `tools/ci/cross-smoke.sh <dir> rust/prebuilt/netvfs-accounts rust/prebuilt/netvfs-bridge` |
| NEEDED (the helper: libc, libgcc_s, libsqlite3; the bridge: libc, libgcc_s, libm), highest GLIBC symbol version (the target's glibc is the floor), PIE, RELRO, BIND_NOW, NX stack | `tools/ci/check-linked-libs.sh`, from `tools/ci/check-rpm.sh` on the packaged binaries |
| `libnetvfs-bridge-ffi.so`: exports only `nvb_ffi_get`, links libnetvfs, the GLIBC floor, RELRO, BIND_NOW, NX stack; the bridge loads it from where the package puts it, next to the backend folder libnetvfs searches | `tools/ci/check-ffi-lib.sh`, from `tools/ci/check-rpm.sh` (and from `make check-packaging` on the host build) |

The host needs the i386 C library and qemu (`libc6-i386`,
`qemu-user-static`; `tools/ci/install-host-deps.sh`).
`tools/ci/build-rpm.sh` cross-builds by itself when `rust/prebuilt` is
empty, so a local RPM build is still one command.

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
RPM sets it to `rust/prebuilt`).

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
| Golden tests: every answer byte for byte against the C++ helper, kept as a test-only reference (`referencehelper.cpp`), and read back with the C++ bridge's decoder of 0.4 (`referencedecoder.cpp`); about 95 stored values, account shapes, attention writes and refused writes | `tests/bridge/accounts` | `make check-unit` |
| A live libaccounts-qt manager sees the attention write through the signal | `tests/bridge/accounts` (`attentionSignal`) | `make check-unit` |
| Each part of the confinement in a fresh process, also from setgid copies | `rust/netvfs-accounts/tests/sandbox.rs` | `make check-rust` |
| netvfs-bridge's `ffi` module against the built `libnetvfs-bridge-ffi.so` and the fake backend: loading and version, establish (identity verdicts, prompts, phases, signond on the Qt thread), listing, walk, remove tree, handles, transfers through `nvb_io`, a cancel from another thread, copy across, URLs, error mapping, post/quit, panics in callbacks, discovery, no block left unfreed (heap growth over many calls) | `rust/netvfs-bridge/tests/ffi.rs` (its own harness: `init` needs the main thread; a test hung for 30 s fails) | `make check-rust-ffi` (part of `make check`); without the libraries every case says it is skipped |
| The FFI's C ABI from C++ (and its marshalling into one block per result) | `tests/bridge/ffi` | `make check-unit` |
| The built `netvfs-bridge` as a black box from a libdbus client (`tests/bridge/common`, the consumer side of the C++ bridge of 0.4): the introspection XML byte for byte, the `Peer` interface, an unknown path, fd passing both ways, error details, and every golden sequence of the contract, with the fake backend seeded through `NETVFS_FAKE_SEED` and a scripted accounts helper | `tests/bridge/contract` (`tst_contract`) | `make check-unit` |
| The built `netvfs-bridge` under socket activation (the test plays systemd), listing through the built `netvfs-accounts` against a libaccounts database; exit codes for an unknown consumer and a usage error | `tests/bridge/process` (`tst_bridgeprocess`) | `make check-unit` |
| The target build: tests under qemu, smoke run, linked libraries | see "Cross build" | CI job "Sailfish OS 5.2 aarch64 RPMs" |
| Mutations the tests must catch: curated lists, and cargo-mutants on every line a pull request changes (with the FFI's C++ libraries built by `tools/ci/ffi-libs.sh`, so `tests/ffi.rs` runs; exclusions with reasons in `rust/.cargo/mutants.toml`) | `tests/mutations/helper.json`, `bridge.json`, `ffi.json`; `tools/ci/rust-mutants.sh <base> [<ffi-libs dir>]` | CI matrix `helper`, `bridge`, `ffi`; CI job "Tests bite (Rust, changed code)" |
| Fuzzing: stored values, bus replies, arguments, the FFI marshalling (`ffi_marshal`: parameters, entries, identities into their C form and back) | `rust/fuzz` | `./tools/ci/rust-fuzz.sh <seconds>` (nightly) |
| Advisories, yanked crates, licences, sources | `rust/deny.toml` | CI job "Rust supply chain"; advisories again weekly |
| Tests under ASan + LSan (the FFI test with the C++ side instrumented too, see below), the current stable's clippy, the online workflow audit | `.github/workflows/scheduled.yml` | weekly; `./tools/ci/rust-sanitize.sh <nightly> [<ffi-libs dir>]` |
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
`make coverage` builds the helper and the bridge with
`-C instrument-coverage`; the helper's confinement lets it write its
counters to `build-coverage/rust-coverage` only in that build
(`NETVFS_RUST_COVERAGE_DIR`). The bridge writes its counters when it exits,
so the C++ tests let it end with its idle exit instead of killing it.

## Choices

- Since 0.4.1 written for Rust 1.95 and cross-built with a host cargo
  against the SDK's compiler and sysroot (0.4.0 built in `mb2` with the
  SDK's 1.75). The bridge (Phase 2) needs crates that 1.75 cannot build
  (zbus 5), and both binaries should use one toolchain.
- The FFI bindings are written by hand from the frozen header rather than
  generated by bindgen (which needs libclang at build time); tests pin the
  sizes and offsets that gcc gives the header on LP64.
- Landlock and seccomp through raw syscalls, as the C++ code did, rather than
  crates: the code is small, handles Landlock ABI 1 to 7 itself and adds
  nothing to vendor or review in the privileged process.
- A minimal D-Bus client (one signal, `Hello`, `RequestName`, `GetId`) rather
  than zbus, which would bring an async runtime and many crates into it.
- A curated mutation list in the format `tools/mutation-check.py` already
  runs for the C++ parts, plus cargo-mutants on the lines each pull request
  changes.
