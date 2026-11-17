#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Builds the aarch64 RPMs with the Sailfish OS Platform SDK container.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name), SOURCE_DATE_EPOCH (default: commit time).
# Rust binaries and libnetvfs-rs.so come from rust/prebuilt (RPM job's cross-build step); without them this script cross-builds first, needing lift-sdk.sh's host packages.
# Reproducible (doc/VERIFYING.md): SOURCE_DATE_EPOCH is build time and clamps file dates; spec fixes host name.
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)
fi
# Untracked files are copied too and changes go in: the packages then are
# no commit's. Warn, don't refuse.
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
# SDK builds as mersdk (uid 100000) in a copy of tracked files plus binaries:
# checkout leftovers stay out of packages, qmake output out of checkout.
# No .git: mb2 then takes version from spec, not from latest tag.
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"' EXIT
src=$work/src
mkdir -p "$src/rust/prebuilt"
# Regular files and links only: the submodule is a folder (and host-only).
# shellcheck disable=SC2016 # expanded by the inner shell.
(cd "$root" && git ls-files -z --cached --others --exclude-standard |
    xargs -0 sh -c 'for f do [ ! -f "$f" ] || cp --parents -P -t "$0" "$f"; done' "$src")
cp "$root"/rust/prebuilt/netvfs-bridge "$root"/rust/prebuilt/netvfs-accounts \
    "$root"/rust/prebuilt/libnetvfs-rs.so "$src/rust/prebuilt/"
# File modes from the executable bit alone (644, 755), not this umask:
# %license packages LICENSE with its mode. The SDK user owns the copy: it
# builds there and overwrites files (qmake's Makefile); others may read it
# (the RPMs).
chmod -R u=rwX,go=rX "$work"
sudo chown -R 100000:100000 "$work"
docker run --rm \
    ${SOURCE_DATE_EPOCH:+-e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"} \
    -v "$src:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
    bash -euc "./tools/ci/sdk-build.sh '$TARGET'"
mkdir -p "$root/RPMS"
cp "$src"/RPMS/*.rpm "$root/RPMS/"
ls -l "$root"/RPMS
