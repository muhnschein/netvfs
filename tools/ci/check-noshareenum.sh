#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPEC-v2 XP-3, SPEC 10.2 gate G-SMB item 4: asserts that the SMB backend
# plugin contains no share enumeration code. src/backends/smb/noshareenum.c
# keeps libsmb2's NetrShareEnum client and its DCE/RPC parser out at link
# time; this checks the linked result. Share enumeration belongs to the
# netvfs-smb-shares helper only (SPEC-v2 XM-7).
#
# Usage: tools/ci/check-noshareenum.sh FILE...
#   FILE is libnetvfs-smb.so (stripped or not) or its separate debug file.
#   Checked: the strings of the read-only data (libsmb2's DCE/RPC and srvsvc
#   code brings "DCERPC ..." messages and the "srvsvc" pipe name) and the
#   symbol tables (dcerpc_*, *srvsvc*). The synchronous wrapper
#   smb2_share_enum_sync() stays: it only reaches the stub in noshareenum.c.
# Needs readelf (any architecture).
set -eu

# Strings and symbols that only libsmb2's DCE/RPC and share enumeration code has.
strings_pattern='DCERPC|srvsvc|NetrShareEnum'
symbols_pattern='dcerpc|srvsvc|NetrShareEnum'

check() {
    file=$1
    if ! readelf -h "$file" >/dev/null 2>&1; then
        echo "$file: not an ELF file"
        return 1
    fi
    result=0
    found=$(readelf -W -p .rodata "$file" 2>/dev/null | grep -E "$strings_pattern" || true)
    if [ -n "$found" ]; then
        echo "$file: share enumeration strings in .rodata:"
        echo "$found" | head -n 5
        result=1
    fi
    found=$(readelf -W -s "$file" 2>/dev/null | awk '{ print $8 }' | grep -i -E "$symbols_pattern" || true)
    if [ -n "$found" ]; then
        echo "$file: share enumeration symbols:"
        echo "$found" | head -n 5
        result=1
    fi
    return $result
}

if [ $# -eq 0 ]; then
    echo "usage: $0 FILE..." >&2
    exit 2
fi
status=0
for file in "$@"; do
    if check "$file"; then
        echo "$file: no share enumeration code"
    else
        status=1
    fi
done
exit $status
