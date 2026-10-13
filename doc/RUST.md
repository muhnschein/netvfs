# Rust in netvfs

Since 0.4.0 the setgid accounts helper `netvfs-accounts` (SPEC-v2 XB-2a) is
written in Rust. It is a drop-in replacement for the C++/Qt helper it
replaces: the same requests (`list`, `files <id>`, `attention <id> <state>
[pin]`), the same `QDataStream` answer on stdout, the same confinement. The
bridge and everything else stay C++.

What it gains: the process that holds the group `privileged` links libc,
libgcc_s and libsqlite3 only, no Qt, GLib, libaccounts or GIO modules, and
every `unsafe` call is in one module (`sandbox.rs`).

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
| `rust/fuzz/` | cargo-fuzz targets (nightly, not in the workspace) |

Dependencies: `libc` and `rusqlite` (without the bundled SQLite: the system
libsqlite3 through pkg-config).

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
| The cross-built helper's answers to `list` and `files` equal the host build's, byte for byte | `tools/ci/cross-smoke.sh <dir> rust/prebuilt/netvfs-accounts` |
| NEEDED, highest GLIBC symbol version (the target's glibc is the floor), PIE, RELRO, BIND_NOW, NX stack | `tools/ci/check-linked-libs.sh`, from `tools/ci/check-rpm.sh` on the packaged binaries |

The host needs the i386 C library and qemu (`libc6-i386`,
`qemu-user-static`; `tools/ci/install-host-deps.sh`).
`tools/ci/build-rpm.sh` cross-builds by itself when `rust/prebuilt` is
empty, so a local RPM build is still one command.

Since the spec only installs the binaries, OBS and Chum cannot rebuild
netvfs from the spec; netvfs ships no recipe for either. Once an SDK target
ships rustc 1.95, the cross job goes and the spec runs cargo again: the
qmake target (`src/bridge/accounts/accounts.pro`) builds with cargo
whenever `NETVFS_RUST_PREBUILT` is not set.

## Build

`src/bridge/accounts/accounts.pro` is a qmake aux target that runs
`cargo build --release --locked` and installs the binary, so `make` builds it
with the C++ parts. qmake variables: `NETVFS_CARGO` (the cargo to run),
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
| Golden tests: every answer byte for byte against the C++ helper, kept as a test-only reference (`referencehelper.cpp`); about 95 stored values, account shapes, attention writes and refused writes | `tests/bridge/accounts` | `make check-unit` |
| A live libaccounts-qt manager sees the attention write through the signal | `tests/bridge/accounts` (`attentionSignal`) | `make check-unit` |
| Each part of the confinement in a fresh process, also from setgid copies | `rust/netvfs-accounts/tests/sandbox.rs` | `make check-rust` |
| The target build: tests under qemu, smoke run, linked libraries | see "Cross build" | CI job "Sailfish OS 5.2 aarch64 RPMs" |
| Mutations the tests must catch: a curated list, and cargo-mutants on every line a pull request changes | `tests/mutations/helper.json`; `tools/ci/rust-mutants.sh <base>` | CI matrix `helper`; CI job "Tests bite (Rust, changed code)" |
| Fuzzing: stored values, bus replies, arguments | `rust/fuzz` | `./tools/ci/rust-fuzz.sh <seconds>` (nightly) |
| Advisories, yanked crates, licences, sources | `rust/deny.toml` | CI job "Rust supply chain"; advisories again weekly |
| Tests under ASan + LSan, the current stable's clippy, the online workflow audit | `.github/workflows/scheduled.yml` | weekly; `./tools/ci/rust-sanitize.sh <nightly>` |
| Workflow audit: no credentials left in checkouts, no `${{ }}` in `run:` | `.github/workflows` | CI job "Workflow audit" (`zizmor --offline`) |
| Coverage for Sonar | `build-coverage/rust-lcov.info` | `make coverage` |
| Clippy findings for Sonar | `build-coverage/clippy.json` | `make COVERAGE=1 clippy-report` |

`make check-rust` needs `cargo-nextest`
(`./tools/ci/cargo-tool.sh cargo-nextest 0.9.148`).
`make coverage` builds the helper with `-C instrument-coverage`; the
confinement lets it write its counters to `build-coverage/rust-coverage`
only in that build (`NETVFS_RUST_COVERAGE_DIR`).

## Choices

- Since 0.4.1 written for Rust 1.95 and cross-built with a host cargo
  against the SDK's compiler and sysroot (0.4.0 built in `mb2` with the
  SDK's 1.75). The bridge (Phase 2) needs crates that 1.75 cannot build
  (zbus 5), and both binaries should use one toolchain.
- Landlock and seccomp through raw syscalls, as the C++ code did, rather than
  crates: the code is small, handles Landlock ABI 1 to 7 itself and adds
  nothing to vendor or review in the privileged process.
- A minimal D-Bus client (one signal, `Hello`, `RequestName`, `GetId`) rather
  than zbus, which would bring an async runtime and many crates into it.
- A curated mutation list in the format `tools/mutation-check.py` already
  runs for the C++ parts, plus cargo-mutants on the lines each pull request
  changes.
