#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Smoke run of the cross-built netvfs-accounts under qemu-aarch64-static with
# the target's own glibc and SQLite (doc/RUST.md "Cross build"): its answers
# to `list` and `files` on a small accounts.db must be byte for byte those
# of the host build. (seccomp does not install under qemu-user; the helper
# goes on without it, as it is best-effort.)
# Usage: cross-smoke.sh <sdk dir> <cross-built netvfs-accounts>
set -eu
sdk=$(cd "$1" && pwd)
target_helper=$2
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
