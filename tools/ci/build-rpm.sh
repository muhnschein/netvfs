#!/bin/sh
# Builds the aarch64 RPMs with the Sailfish OS Platform SDK container.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name).
# The Rust binaries and libnetvfs-rs.so come prebuilt from rust/prebuilt (the
# RPM job's step "Cross-build the Rust binaries" puts them there, doc/RUST.md
# "Cross build"); without them this script cross-builds them first, which
# needs the host packages of lift-sdk.sh.
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ ! -x "$root/rust/prebuilt/netvfs-bridge" ] || [ ! -x "$root/rust/prebuilt/netvfs-accounts" ] \
    || [ ! -f "$root/rust/prebuilt/libnetvfs-rs.so" ]; then
    sdk=$root/build-sdk-cross
    [ -x "$sdk/bin/aarch64-meego-linux-gnu-gcc" ] || "$root/tools/ci/lift-sdk.sh" "$SDK_IMAGE" "$TARGET" "$sdk"
    "$root/tools/ci/cross-build.sh" "$sdk" "$root/rust/prebuilt"
fi
# The SDK runs as mersdk (uid 100000) and builds in the source tree.
sudo chown -R 100000:100000 "$root"
trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
docker run --rm -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
    bash -euc "./tools/ci/sdk-build.sh '$TARGET'"
ls -l "$root"/RPMS
