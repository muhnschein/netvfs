#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
usage() {
    cat >&2 << 'EOF'
Usage: rust-mutants.sh diff <base revision> [<ffi-libs.sh dir> [<k>/<n>]]
Usage: rust-mutants.sh crate <package> [<ffi-libs.sh dir> [<k>/<n>]]
Usage: rust-mutants.sh interop <package> <base revision | all> <k>/<n> <command>
EOF
    exit 2
}
[ $# -ge 2 ] || usage
mode=$1
shift
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
started=""
finish() {
    for prefix in $started; do
        ids=$(docker ps -aq --filter "name=^$prefix-")
        [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    done
    [ -z "${smb_work:-}" ] || rm -rf "$smb_work"
    [ -z "${webdav_work:-}" ] || rm -rf "$webdav_work" 2>/dev/null || true
    rm -rf "$tmp"
}
trap finish EXIT
trap 'exit 1' INT TERM

changed_since() {
    git -C "$root" diff "$1...HEAD" -- 'rust/*.rs' ':!rust/fuzz' ':!rust/vendor' > "$tmp/diff"
    if [ ! -s "$tmp/diff" ]; then
        echo "no Rust source changed since $1"
        return 1
    fi
    sed -i -e 's|^--- a/rust/|--- a/|' -e 's|^+++ b/rust/|+++ b/|' "$tmp/diff"
}

use_ffi_libs() {
    lib=$(cd "$1" && pwd)/lib
    export NETVFS_BRIDGE_FFI="$lib/netvfs/libnetvfs-bridge-ffi.so"
    export NETVFS_BRIDGE_FFI_FAKE="$lib/libnetvfs-bridge-ffi-fake.so"
    export NETVFS_BACKEND_PATH="$lib/netvfs/test-backends"
    export QT_QPA_PLATFORM=offscreen
}

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
    netvfs-webdav)
        [ -z "${NETVFS_INTEROP_WEBDAV_PREFIX:-}" ] || return 0
        echo "starting the WebDAV interop server for $1"
        NETVFS_WEBDAV_SERVERS_ONLY=1 "$root/tests/interop/webdav/run.sh" "$2" > "$tmp/webdav-servers"
        grep '^NETVFS_INTEROP_WEBDAV_' "$tmp/webdav-servers" > "$tmp/webdav-settings" || true
        while IFS= read -r setting; do
            export "${setting?}"
        done < "$tmp/webdav-settings"
        if [ -z "${NETVFS_INTEROP_WEBDAV_PREFIX:-}" ]; then
            echo "the WebDAV interop server did not start"
            exit 1
        fi
        started="$started $NETVFS_INTEROP_WEBDAV_PREFIX"
        webdav_work=$NETVFS_INTEROP_WEBDAV_WORK
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
    cargo mutants --in-place $select --all-features \
        --test-tool nextest --no-shuffle --timeout-multiplier 3 $shard || status=$?
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
    cargo mutants --list --json --diff $select --all-features \
        --shard="$shard" --sharding=round-robin > "$tmp/mutants.json"
    python3 "$root/tools/ci/rust-mutants-command.py" "$tmp/mutants.json" "$*"
    ;;
*)
    usage
    ;;
esac
