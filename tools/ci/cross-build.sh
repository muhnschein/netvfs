#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Cross-builds the Rust binaries of netvfs and libnetvfs-rs.so for the
# Sailfish OS target with the host's cargo (the pinned toolchain,
# rust/rust-toolchain.toml) and the SDK's own gcc and sysroot, as lifted by
# lift-sdk.sh (doc/RUST.md "Cross build"). They link against the target's
# glibc and SQLite, so their symbol versions are those of the oldest SDK the
# phone runs.
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
# libsqlite3-sys: link the target's library, no pkg-config, no build-time
# bindgen (the crate's shipped bindings).
export SQLITE3_LIB_DIR="$sdk/linklib"
export SQLITE3_STATIC=0
# Hardening (checked by check-linked-libs.sh and check-rs-lib.sh): PIE and
# full RELRO are rustc's defaults for this target; immediate binding and a
# non-executable stack are spelled out so that a toolchain change cannot drop
# them. The binaries are built as PIEs explicitly; libnetvfs-rs.so (and so
# every workspace build that links it, the tests too) cannot be one.
hardening="-C relro-level=full -C link-arg=-Wl,-z,now -C link-arg=-Wl,-z,noexecstack -C link-arg=-Wl,--as-needed"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$hardening"
export CARGO_TARGET_DIR="$out/target"
# Reproducible binaries (SPEC P-8): build paths recorded in them (panic
# locations, `__FILE__` in C) mapped to fixed names, so checkout, SDK and
# cargo home may live anywhere. General to specific: rustc and gcc apply the
# last matching map. No spaces in these paths (RUSTFLAGS splits on them).
# Release builds only: tests stay as built.
rust_maps=""
c_maps=""
map() {
    rust_maps="$rust_maps --remap-path-prefix=$1=$2"
    c_maps="$c_maps -ffile-prefix-map=$1=$2"
}
map "$root" /netvfs
map "$out" /out
map "$sdk" /sdk
map "${CARGO_HOME:-$HOME/.cargo}" /cargo

cd "$root/rust"
rustup target add "$triple" > /dev/null
if [ "$mode" = test ]; then
    # The confinement tests start set-id copies and seccomp filters, which
    # qemu-user cannot run faithfully; they run natively on the host. So do
    # the bridge's tests of a helper that cannot be started: under qemu-user
    # posix_spawn reports a failed exec as a started child that exits 127.
    # flow_control_bounded measures the resident set of the whole process,
    # so it runs in a process of its own (as under cargo nextest, make
    # check-rust): next to the other tests their memory counts as well.
    flow=server::session::tests::flow_control_bounded
    cargo test --locked --workspace --target "$triple" -- --skip sandbox \
        --skip accounts::helper::tests::failures_list_nothing \
        --skip accounts::helper::tests::files_are_fetched --skip "$flow"
    cargo test --locked -p netvfs-bridge --lib --target "$triple" -- --exact "$flow"
    exit 0
fi
export TARGET_CFLAGS="$c_maps" TARGET_CXXFLAGS="$c_maps"
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C relocation-model=pie $hardening$rust_maps" \
    cargo build --release --locked --workspace --target "$triple" --bins
for bin in netvfs-bridge netvfs-accounts; do
    cp -f "$CARGO_TARGET_DIR/$triple/release/$bin" "$out/$bin"
done
# libnetvfs-rs.so with its own profile (rs-release: panics unwind to the
# table, fat LTO; src/backends/rs/rs.pro).
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$hardening$rust_maps" \
    cargo build --profile rs-release --locked -p netvfs-backend --lib --target "$triple"
cp -f "$CARGO_TARGET_DIR/$triple/rs-release/libnetvfs_rs.so" "$out/libnetvfs-rs.so"
ls -l "$out"
