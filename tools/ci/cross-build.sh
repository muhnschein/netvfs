#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Cross-builds the Rust binaries of netvfs for the Sailfish OS target with the
# host's cargo (the pinned toolchain, rust/rust-toolchain.toml) and the SDK's
# own gcc and sysroot, as lifted by lift-sdk.sh (doc/RUST.md "Cross build").
# The binaries link against the target's glibc and SQLite, so their symbol
# versions are those of the oldest SDK the phone runs.
#
# Usage: cross-build.sh <sdk dir> <out dir> [test]
#   builds the release binaries into <out dir>; with "test", runs the
#   workspace tests for the target under qemu-aarch64-static instead,
#   against the target's own glibc and SQLite.
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
# Hardening (checked by check-linked-libs.sh): PIE and full RELRO are
# rustc's defaults for this target; immediate binding and a non-executable
# stack are spelled out so that a toolchain change cannot drop them.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C relocation-model=pie -C relro-level=full \
-C link-arg=-Wl,-z,now -C link-arg=-Wl,-z,noexecstack -C link-arg=-Wl,--as-needed"
export CARGO_TARGET_DIR="$out/target"

cd "$root/rust"
rustup target add "$triple" > /dev/null
if [ "$mode" = test ]; then
    # The confinement tests start set-id copies and seccomp filters, which
    # qemu-user cannot run faithfully; they run natively on the host.
    cargo test --locked --workspace --target "$triple" -- --skip sandbox
    exit 0
fi
cargo build --release --locked --workspace --target "$triple" --bins
for bin in netvfs-accounts; do
    cp -f "$CARGO_TARGET_DIR/$triple/release/$bin" "$out/$bin"
done
ls -l "$out"
