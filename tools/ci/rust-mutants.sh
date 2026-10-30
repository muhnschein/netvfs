#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Tests bite (Rust): cargo-mutants. Every mutant must be caught or unviable (does not build); a missed one fails.
# A timeout counts as caught (the mutant hung a test). Exclusions with reasons: rust/.cargo/mutants.toml. Results in
# rust/mutants.out. Mutants are tested in place, one at a time, each mutated file restored after: tests read files
# outside rust/ (the shared contract) that a workspace copy would lack.
#
# rust-mutants.sh diff <base revision> [<ffi-libs.sh dir> [<k>/<n>]]
# The Rust lines changed since <base>, each tested by the tests of its package.
# rust-mutants.sh crate <package> [<ffi-libs.sh dir> [<k>/<n>]]
# All of <package> (mutants.yml, by hand before a new crate's PR merges), the same way.
# rust-mutants.sh interop <package> <base revision | all> <k>/<n> <command>
# The mutants of <package> in lines changed since <base> (all: whole package), each tested by <command> instead of the
#     Rust tests: run by sh -c from the repository root, it rebuilds what it needs and runs suites that reach the Rust code
#     via the C++ side (shim's tests, tests/interop). Slow-starting servers (interop containers) are started once for the
#     shard by the caller and handed to <command> in its environment. tools/ci/rust-mutants-command.py runs them.
#
# With an ffi-libs.sh dir, netvfs-bridge's FFI test runs against the C++ libraries `tools/ci/ffi-libs.sh <dir>` built there
# (else skipped, catches nothing). With <k>/<n>, only shard k (from 0) of n runs, every n-th mutant (CI: parallel jobs).
#
# netvfs-sftp's tests/openssh.rs and netvfs-smb's tests/samba.rs run against the interop containers and pass at once
# (catching nothing) without NETVFS_SFTP_INTEROP_CONFIG, NETVFS_INTEROP_SMB_*. When the mutants include one of these
# crates and the settings are missing, its servers are started for the run (in the ffi-libs.sh dir when given) and
# removed at the end. CI starts them once per job and hands them in (ci.yml, mutants.yml).
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
# Container name prefixes of servers this run started.
started=""
finish() {
    for prefix in $started; do
        ids=$(docker ps -aq --filter "name=^$prefix-")
        # shellcheck disable=SC2086 # one word per container
        [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    done
    [ -z "${smb_work:-}" ] || rm -rf "$smb_work"
    rm -rf "$tmp"
}
trap finish EXIT
trap 'exit 1' INT TERM

# Diff since $1 of the workspace's Rust sources (not fuzz targets, not rust/vendor), in $tmp/diff with paths relative to
# rust/ as --in-diff takes them; fails when nothing changed.
changed_since() {
    git -C "$root" diff "$1...HEAD" -- 'rust/*.rs' ':!rust/fuzz' ':!rust/vendor' > "$tmp/diff"
    if [ ! -s "$tmp/diff" ]; then
        echo "no Rust source changed since $1"
        return 1
    fi
    sed -i -e 's|^--- a/rust/|--- a/|' -e 's|^+++ b/rust/|+++ b/|' "$tmp/diff"
}

# FFI libraries for netvfs-bridge's tests, from optional argument $1.
use_ffi_libs() {
    lib=$(cd "$1" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
}

# Interop servers of package $1 when its settings are missing; $2 holds their work files.
interop_servers() {
    case "$1" in
    netvfs-sftp)
        [ -z "${NETVFS_SFTP_INTEROP_CONFIG:-}" ] || return 0
        echo "starting the SFTP interop servers for $1"
        setting=$(NETVFS_SFTP_SERVERS_ONLY=1 "$root/tests/interop/sftp/run.sh" "$2" | tail -n 1)
        case "$setting" in
            NETVFS_SFTP_INTEROP_CONFIG=?*) export "${setting?}" ;;
            *) echo "the SFTP interop servers did not start"; exit 1 ;;
        esac
        started="$started $(python3 -c 'import json, sys
print(json.load(open(sys.argv[1]))["servers"]["o103"]["container"].rsplit("-", 1)[0])' "$NETVFS_SFTP_INTEROP_CONFIG")"
        ;;
    netvfs-smb)
        [ -z "${NETVFS_INTEROP_SMB_PREFIX:-}" ] || return 0
        echo "starting the SMB interop servers for $1"
        NETVFS_SMB_SERVERS_ONLY=1 "$root/tests/interop/smb/run.sh" "$2" > "$tmp/smb-servers"
        grep '^NETVFS_INTEROP_SMB_' "$tmp/smb-servers" > "$tmp/smb-settings" || true
        while IFS= read -r setting; do
            export "${setting?}"
        done < "$tmp/smb-settings"
        if [ -z "${NETVFS_INTEROP_SMB_PREFIX:-}" ]; then
            echo "the SMB interop servers did not start"
            exit 1
        fi
        started="$started $NETVFS_INTEROP_SMB_PREFIX"
        smb_work=$NETVFS_INTEROP_SMB_WORK
        ;;
    esac
}

case "$mode" in
diff | crate)
    target=$1
    shard=
    [ $# -lt 2 ] || use_ffi_libs "$2"
    [ $# -lt 3 ] || shard="--shard=$3 --sharding=round-robin"
    if [ "$mode" = diff ]; then
        changed_since "$target" || exit 0
        # All features: --in-diff selects the packages it touches, and naming a feature of one it left out is an error.
        select="--in-diff $tmp/diff --workspace"
        packages=$(sed -n 's|^+++ b/\(netvfs-[a-z-]*\)/.*|\1|p' "$tmp/diff" | sort -u)
    else
        select="--package $target"
        packages=$target
    fi
    work=$tmp
    [ $# -lt 2 ] || work=$(cd "$2" && pwd)
    for package in $packages; do
        interop_servers "$package" "$work"
    done
    cd "$root/rust"
    status=0
    # shellcheck disable=SC2086 # one word per argument
    cargo mutants --in-place $select --all-features \
        --test-tool nextest --no-shuffle --timeout-multiplier 3 $shard || status=$?
    # Exit status says "timeouts" also when mutants were missed, so read the outcome from the lists: 0 ok, 2 missed, 3 timeouts;
    # anything else (baseline failed, usage error) stands.
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
