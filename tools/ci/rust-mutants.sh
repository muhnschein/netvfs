#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Tests bite (Rust): cargo-mutants. Every mutant must be caught by a test or
# be unviable (it does not build); a missed one fails. A timeout counts as
# caught: the mutant made a test hang, which nextest's slow-timeout (or the
# command's time limit) ends. Exclusions, each with its reason:
# rust/.cargo/mutants.toml. Results in rust/mutants.out. Mutants are tested
# in place, one at a time, and each mutated file is restored after its run:
# tests read files outside rust/ (the shared contract), which a copy of the
# workspace would not have.
#
# rust-mutants.sh diff <base revision> [<ffi-libs.sh dir> [<k>/<n>]]
#     The Rust lines changed since <base> (ci.yml, "Tests bite (Rust,
#     changed code)"), each tested by the tests of its package.
# rust-mutants.sh crate <package> [<ffi-libs.sh dir> [<k>/<n>]]
#     All of <package> (mutants.yml, run by hand before the pull request of
#     a new crate merges), the same way.
# rust-mutants.sh interop <package> <base revision | all> <k>/<n> <command>
#     The mutants of <package> in the lines changed since <base> (all: the
#     whole package), each tested by <command> instead of the Rust tests:
#     run by sh -c from the repository root, it rebuilds what it needs and
#     runs suites that reach the Rust code through the C++ side, such as
#     the shim's tests or the interop suites (tests/interop). Servers that
#     take long to start (the interop containers) are started once for the
#     shard by the caller and handed to <command> in its environment.
#     tools/ci/rust-mutants-command.py runs them.
#
# With an ffi-libs.sh dir, netvfs-bridge's FFI test runs against the C++
# libraries `tools/ci/ffi-libs.sh <dir>` built there (else it is skipped
# and catches nothing). With <k>/<n>, only shard k (from 0) of n runs,
# every n-th mutant (CI runs the shards as parallel jobs).
set -eu
usage() {
    sed -n 's/^# rust-mutants\.sh /Usage: rust-mutants.sh /p' "$0" >&2
    exit 2
}
[ $# -ge 2 ] || usage
mode=$1
shift
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The diff since $1 of the workspace's Rust sources (not the fuzz targets),
# in $tmp/diff with paths relative to rust/ as --in-diff takes them; fails
# when nothing changed.
changed_since() {
    git -C "$root" diff "$1...HEAD" -- 'rust/*.rs' ':!rust/fuzz' > "$tmp/diff"
    if [ ! -s "$tmp/diff" ]; then
        echo "no Rust source changed since $1"
        return 1
    fi
    sed -i -e 's|^--- a/rust/|--- a/|' -e 's|^+++ b/rust/|+++ b/|' "$tmp/diff"
}

# FFI libraries for netvfs-bridge's tests, from the optional argument $1.
use_ffi_libs() {
    lib=$(cd "$1" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
}

case "$mode" in
diff | crate)
    target=$1
    shard=
    [ $# -lt 2 ] || use_ffi_libs "$2"
    [ $# -lt 3 ] || shard="--shard=$3 --sharding=round-robin"
    if [ "$mode" = diff ]; then
        changed_since "$target" || exit 0
        # All features: --in-diff selects the packages it touches, and
        # naming a feature of one it left out is an error.
        select="--in-diff $tmp/diff --workspace"
    else
        select="--package $target"
    fi
    cd "$root/rust"
    status=0
    # shellcheck disable=SC2086 # one word per argument
    cargo mutants --in-place $select --all-features \
        --test-tool nextest --no-shuffle --timeout-multiplier 3 $shard || status=$?
    # Its exit status says "timeouts" also when mutants were missed, so the
    # outcome is read from the lists: 0 ok, 2 missed, 3 timeouts, anything
    # else (the baseline failed, a usage error) stands.
    case "$status" in
        0 | 2 | 3) ;;
        *) exit "$status" ;;
    esac
    if [ -s mutants.out/missed.txt ]; then
        echo "missed mutants:"
        cat mutants.out/missed.txt
        exit 1
    fi
    ;;
interop)
    [ $# -ge 4 ] || usage
    package=$1
    scope=$2
    shard=$3
    shift 3
    select="--package $package"
    if [ "$scope" != all ]; then
        changed_since "$scope" || exit 0
        select="$select --in-diff $tmp/diff"
    fi
    cd "$root/rust"
    # shellcheck disable=SC2086 # one word per argument
    cargo mutants --list --json --diff $select --all-features \
        --shard="$shard" --sharding=round-robin > "$tmp/mutants.json"
    python3 "$root/tools/ci/rust-mutants-command.py" "$tmp/mutants.json" "$*"
    ;;
*)
    usage
    ;;
esac
