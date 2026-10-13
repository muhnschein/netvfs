#!/bin/sh
# Builds the aarch64 RPMs with the Sailfish OS Platform SDK container.
# Env: SDK_IMAGE (container image), TARGET (sb2 target name).
set -eu
: "${SDK_IMAGE:?}" "${TARGET:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
# SPEC-v2 XB-2a: the Rust helper's crates, vendored on the host so that the
# SDK build is offline (doc/RUST.md); the spec points CARGO_HOME here.
(cd "$root/rust" && cargo +stable vendor --locked --versioned-dirs -q vendor > /dev/null)
mkdir -p "$root/rust/.cargo-home"
cat > "$root/rust/.cargo-home/config.toml" <<CFG
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
CFG
# The SDK runs as mersdk (uid 100000) and builds in the source tree.
sudo chown -R 100000:100000 "$root"
trap 'sudo chown -R "$(id -u):$(id -g)" "$root"' EXIT
docker run --rm -v "$root:/home/mersdk/src" -w /home/mersdk/src "$SDK_IMAGE" \
    bash -euc "./tools/ci/sdk-build.sh '$TARGET'"
ls -l "$root"/RPMS
