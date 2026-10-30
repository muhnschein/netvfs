#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Cross-builds the Rust binaries and libnetvfs-rs.so for the Sailfish OS target with the host's cargo (pinned toolchain)
# and the SDK's gcc and sysroot, as lifted by lift-sdk.sh. They link the target's glibc and SQLite, so symbol versions
# are those of the oldest SDK the phone runs.
#
# Usage: cross-build.sh <sdk dir> <out dir> [test]
#   builds the release binaries and the library into <out dir>; with
#   "test", runs the workspace tests for the target under qemu-aarch64-static
#   instead, against the target's own glibc and SQLite.
set -eu
sdk=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
mode=${3:-build}
root=$(cd "$(dirname "$0")/../.." && pwd)
triple=aarch64-unknown-linux-gnu

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$sdk/bin/aarch64-meego-linux-gnu-gcc"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static -L $sdk/sysroot"
# libsqlite3-sys: link the target's library; no pkg-config, no build-time bindgen.
export SQLITE3_LIB_DIR="$sdk/linklib"
export SQLITE3_STATIC=0
# Hardening (checked by check-linked-libs.sh, check-rs-lib.sh): PIE and full RELRO are rustc's defaults here; immediate
# binding and non-executable stack are spelled out so a toolchain change cannot drop them. Binaries are explicit PIEs;
# libnetvfs-rs.so (so every build linking it, tests too) cannot be one.
hardening="-C relro-level=full -C link-arg=-Wl,-z,now -C link-arg=-Wl,-z,noexecstack -C link-arg=-Wl,--as-needed"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$hardening"
export CARGO_TARGET_DIR="$out/target"

cd "$root/rust"
rustup target add "$triple" > /dev/null
if [ "$mode" = test ]; then
    # Confinement tests start set-id copies and seccomp filters, which qemu-user cannot run faithfully; they run natively,
    # as do the bridge's tests of a helper that cannot be started (under qemu-user posix_spawn reports a failed exec as a
    # started child exiting 127). flow_control_bounded measures the whole process's resident set, so it runs alone (as under
    # nextest): other tests' memory would count.
    flow=server::session::tests::flow_control_bounded
    cargo test --locked --workspace --target "$triple" -- --skip sandbox \
        --skip accounts::helper::tests::failures_list_nothing \
        --skip accounts::helper::tests::files_are_fetched --skip "$flow"
    cargo test --locked -p netvfs-bridge --lib --target "$triple" -- --exact "$flow"
    exit 0
fi
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C relocation-model=pie $hardening" \
    cargo build --release --locked --workspace --target "$triple" --bins
for bin in netvfs-bridge netvfs-accounts; do
    cp -f "$CARGO_TARGET_DIR/$triple/release/$bin" "$out/$bin"
done
# libnetvfs-rs.so with its own profile (rs-release: panics unwind to the table, fat LTO; src/backends/rs/rs.pro).
cargo build --profile rs-release --locked -p netvfs-backend --lib --target "$triple"
cp -f "$CARGO_TARGET_DIR/$triple/rs-release/libnetvfs_rs.so" "$out/libnetvfs-rs.so"
ls -l "$out"
