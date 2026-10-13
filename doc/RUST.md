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
| `rust/rust-toolchain.toml` | the pinned toolchain (1.75.0) |
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

The Sailfish OS 5.2 SDK target ships rustc 1.75, and the RPM builds the
helper with it inside `mb2`, as lautta does. So `rust-version` is 1.75 and
the toolchain file pins 1.75.0 for host builds, lints and tests too: what CI
checks is what the SDK compiles. Edition 2021.

cargo 1.75 reads lockfile version 3 only, and any newer cargo may write
version 4 or pull a crate that needs a newer compiler or edition 2024 (which
also breaks vendoring). `tools/ci/check-lockfile.sh` fails on each of these;
`make check-rust` runs it, plus `cargo +1.75.0 check --locked`. Update
dependencies with the pinned cargo (`cd rust && cargo update -p <crate>`).

## Build

`src/bridge/accounts/accounts.pro` is a qmake aux target that runs
`cargo build --release --locked` and installs the binary, so `make` builds it
with the C++ parts. qmake variables: `NETVFS_CARGO` (the cargo to run),
`NETVFS_RUST_TARGET` (a target triple), `NETVFS_CARGO_FLAGS` (extra flags).

The RPM (`rpm/netvfs.spec`) builds offline: `tools/ci/build-rpm.sh` vendors
the crates into `rust/vendor` with a `rust/.cargo-home/config.toml` that
points cargo there, and the spec passes `--frozen`. `tools/ci/sdk-build.sh`
restarts `mb2` when sb2 stalls, as lautta's build does.
`tools/ci/check-rpm.sh` checks the packaged helper: `NEEDED` is exactly
libc, libgcc_s and libsqlite3, and it is PIE with full RELRO (`BIND_NOW`).

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
| Format, clippy (`all` + `pedantic` at deny), unit and integration tests, lockfile, Rust 1.75 | `rust/` | `make check-rust` (part of `make check`) |
| Golden tests: every answer byte for byte against the C++ helper, kept as a test-only reference (`referencehelper.cpp`); about 95 stored values, account shapes, attention writes and refused writes | `tests/bridge/accounts` | `make check-unit` |
| A live libaccounts-qt manager sees the attention write through the signal | `tests/bridge/accounts` (`attentionSignal`) | `make check-unit` |
| Each part of the confinement in a fresh process, also from setgid copies | `rust/netvfs-accounts/tests/sandbox.rs` | `make check-rust` |
| Mutations the tests must catch | `tests/mutations/helper.json` | `./tools/mutation-check.py --build build tests/mutations/helper.json`, CI matrix `helper` |
| Fuzzing: stored values, bus replies, arguments | `rust/fuzz` | `./tools/ci/rust-fuzz.sh <seconds>` (nightly) |
| Advisories, yanked crates, licences, sources | `rust/deny.toml` | `cd rust && cargo +stable deny --locked check` |
| Coverage for Sonar | `build-coverage/rust-lcov.info` | `make coverage` |
| Clippy findings for Sonar | `build-coverage/clippy.json` | `make COVERAGE=1 clippy-report` |

`make coverage` builds the helper with `-C instrument-coverage`; the
confinement lets it write its counters to `build-coverage/rust-coverage`
only in that build (`NETVFS_RUST_COVERAGE_DIR`).

## Choices

- Built in `mb2` with the SDK's rustc 1.75, not with a host cargo against the
  SDK's cross compiler: the spec stays buildable as it is (OBS, Chum), and
  the helper needs nothing a newer compiler would give.
- Landlock and seccomp through raw syscalls, as the C++ code did, rather than
  crates: the code is small, handles Landlock ABI 1 to 7 itself and adds
  nothing to vendor or review in the privileged process.
- A minimal D-Bus client (one signal, `Hello`, `RequestName`, `GetId`) rather
  than zbus, which would bring an async runtime and many crates into it.
- A curated mutation list in the format `tools/mutation-check.py` already
  runs for the C++ parts, rather than cargo-mutants, and plain `cargo test`.
