#!/bin/sh
# Builds the aarch64 RPMs with the Sailfish OS Platform SDK container.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name).
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
# The SDK runs as mersdk (uid 100000) and builds in the source tree.
sudo chown -R 100000:100000 "$root"
trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
docker run --rm -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
    bash -euc "mb2 -t '$TARGET' build -j \$(nproc)"
ls -l "$root"/RPMS
