#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Smoke run of the cross-built Rust binaries under qemu-aarch64-static with
# the target's own glibc and SQLite (doc/RUST.md "Cross build"):
#   - netvfs-accounts: its answers to `list` and `files` on a small
#     accounts.db must be byte for byte those of the host build (seccomp
#     does not install under qemu-user; the helper goes on without it, as it
#     is best-effort);
#   - netvfs-bridge: a usage error exits 2, and for a registered consumer it
#     gets as far as loading its C ABI (which needs the target's Qt, so a
#     missing one here: exit 1).
# Usage: cross-smoke.sh <sdk dir> <cross-built netvfs-accounts> [<cross-built netvfs-bridge>]
set -eu
sdk=$(cd "$1" && pwd)
target_helper=$2
target_bridge=${3:-}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd "$root/rust" && cargo build --locked --release -q -p netvfs-accounts --bin netvfs-accounts \
    --target-dir "$work/host-target")
host_helper=$work/host-target/release/netvfs-accounts

mkdir -p "$work/accounts"
python3 - "$work/accounts/accounts.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript("""
CREATE TABLE Accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, provider TEXT, enabled INTEGER);
CREATE TABLE Services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                       display TEXT NOT NULL, provider TEXT, type TEXT);
CREATE TABLE Settings (account INTEGER NOT NULL, service INTEGER, key TEXT NOT NULL,
                       type TEXT NOT NULL, value BLOB);
CREATE UNIQUE INDEX idx_setting ON Settings (account, service, key);
PRAGMA user_version = 1;
INSERT INTO Accounts VALUES (1, 'alice@nas', 'smb', 1), (2, 'bob', 'sftp', 1), (3, 'off', 'smb', 0);
INSERT INTO Services VALUES (1, 'smb-files', 'Files', 'smb', 'netvfs-files'),
                            (2, 'sftp-files', 'Files', 'sftp', 'netvfs-files');
INSERT INTO Settings VALUES (1, 0, 'netvfs/host', 's', '''nas.local''');
INSERT INTO Settings VALUES (1, 0, 'netvfs/port', 'i', '445');
INSERT INTO Settings VALUES (1, 1, 'files_root', 's', '''/share/Documents''');
INSERT INTO Settings VALUES (1, 0, 'CredentialsId', 'u', 'uint32 7');
INSERT INTO Settings VALUES (1, 1, 'enabled', 'b', 'true');
INSERT INTO Settings VALUES (2, 0, 'netvfs/host', 's', '''häme.example''');
INSERT INTO Settings VALUES (2, 0, 'netvfs/username', 's', '''bob''');
INSERT INTO Settings VALUES (2, 2, 'enabled', 'b', 'true');
INSERT INTO Settings VALUES (3, 1, 'enabled', 'b', 'true');
""")
c.commit()
PY

for request in "list" "files 1" "files 2" "files 3"; do
    # shellcheck disable=SC2086 # the request is two words
    ACCOUNTS=$work/accounts "$host_helper" $request > "$work/host.out" 2> /dev/null || true
    # shellcheck disable=SC2086
    ACCOUNTS=$work/accounts qemu-aarch64-static -L "$sdk/sysroot" "$target_helper" $request \
        > "$work/target.out" 2> /dev/null || true
    if ! cmp -s "$work/host.out" "$work/target.out"; then
        echo "cross-smoke: '$request' differs between the host and the target build"
        od -c "$work/host.out" | head -n 20
        od -c "$work/target.out" | head -n 20
        exit 1
    fi
    [ -s "$work/host.out" ] || { echo "cross-smoke: '$request' gave no answer"; exit 1; }
    echo "cross-smoke: '$request' ok ($(wc -c < "$work/target.out") bytes)"
done

[ -n "$target_bridge" ] || exit 0
code=0
qemu-aarch64-static -L "$sdk/sysroot" "$target_bridge" > /dev/null 2>&1 || code=$?
if [ "$code" -ne 2 ]; then
    echo "cross-smoke: netvfs-bridge without arguments exited $code, not 2"
    exit 1
fi
mkdir -p "$work/consumers"
printf '[Consumer]\nId=smoke\nDisplayName=Smoke\nExecutable=/usr/bin/smoke\nDataDir=.local/share/smoke\n' \
    > "$work/consumers/smoke.conf"
code=0
NETVFS_CONSUMERS_DIR=$work/consumers NETVFS_BRIDGE_FFI=$work/missing.so \
    qemu-aarch64-static -L "$sdk/sysroot" "$target_bridge" --listen "unix:path=$work/bridge.sock" smoke \
    > /dev/null 2> "$work/bridge.err" || code=$?
if [ "$code" -ne 1 ] || ! grep -q 'Cannot load the backends' "$work/bridge.err"; then
    echo "cross-smoke: netvfs-bridge did not get as far as loading its C ABI (exit $code)"
    cat "$work/bridge.err"
    exit 1
fi
echo "cross-smoke: netvfs-bridge ok"
