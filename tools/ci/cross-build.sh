#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
sdk=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
mode=${3:-build}
root=$(cd "$(dirname "$0")/../.." && pwd)
triple=aarch64-unknown-linux-gnu

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$sdk/bin/aarch64-meego-linux-gnu-gcc"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64-static -L $sdk/sysroot"
export SQLITE3_LIB_DIR="$sdk/linklib"
export SQLITE3_STATIC=0
hardening="-C relro-level=full -C link-arg=-Wl,-z,now -C link-arg=-Wl,-z,noexecstack -C link-arg=-Wl,--as-needed"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$hardening"
export CARGO_TARGET_DIR="$out/target"
remap="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

cd "$root/rust"
rustup target add "$triple" > /dev/null
if [ "$mode" = test ]; then
    flow=server::session::tests::flow_control_bounded
    cargo test --locked --workspace --target "$triple" -- --skip sandbox \
        --skip accounts::helper::tests::failures_list_nothing \
        --skip accounts::helper::tests::files_are_fetched --skip "$flow"
    cargo test --locked -p netvfs-bridge --lib --target "$triple" -- --exact "$flow"
    exit 0
fi
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C relocation-model=pie $hardening $remap" \
    cargo build --release --locked --workspace --target "$triple" --bins
for bin in netvfs-bridge netvfs-accounts; do
    cp -f "$CARGO_TARGET_DIR/$triple/release/$bin" "$out/$bin"
done
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="$hardening $remap" \
    cargo build --profile rs-release --locked -p netvfs-backend --lib --target "$triple"
cp -f "$CARGO_TARGET_DIR/$triple/rs-release/libnetvfs_rs.so" "$out/libnetvfs-rs.so"
ls -l "$out"
