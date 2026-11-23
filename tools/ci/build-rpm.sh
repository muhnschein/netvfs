#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)
fi
if [ -z "$SOURCE_DATE_EPOCH" ]; then
    echo "build-rpm: warning: no git commit and no SOURCE_DATE_EPOCH; package dates are today's" >&2
else
    dirty=$(git -C "$root" status --porcelain --ignore-submodules=dirty 2>/dev/null || true)
    if [ -n "$dirty" ]; then
        echo "build-rpm: warning: uncommitted changes go into the packages, so they are no commit's:" >&2
        echo "$dirty" | head -n 10 >&2
    fi
fi
if [ ! -x "$root/rust/prebuilt/netvfs-bridge" ] || [ ! -x "$root/rust/prebuilt/netvfs-accounts" ] \
    || [ ! -f "$root/rust/prebuilt/libnetvfs-rs.so" ]; then
    sdk=$root/build-sdk-cross
    [ -x "$sdk/bin/aarch64-meego-linux-gnu-gcc" ] || "$root/tools/ci/lift-sdk.sh" "$SDK_IMAGE" "$TARGET" "$sdk"
    "$root/tools/ci/cross-build.sh" "$sdk" "$root/rust/prebuilt"
fi
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"' EXIT
src=$work/src
mkdir -p "$src/rust/prebuilt"
(cd "$root" && git ls-files -z --cached --others --exclude-standard |
    xargs -0 sh -c 'for f do [ ! -f "$f" ] || cp --parents -P -t "$0" "$f"; done' "$src")
cp "$root"/rust/prebuilt/netvfs-bridge "$root"/rust/prebuilt/netvfs-accounts \
    "$root"/rust/prebuilt/libnetvfs-rs.so "$src/rust/prebuilt/"
chmod -R u=rwX,go=rX "$work"
sudo chown -R 100000:100000 "$work"
docker run --rm \
    ${SOURCE_DATE_EPOCH:+-e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"} \
    -v "$src:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
    bash -euc "./tools/ci/sdk-build.sh '$TARGET'"
mkdir -p "$root/RPMS"
cp "$src"/RPMS/*.rpm "$root/RPMS/"
ls -l "$root"/RPMS
