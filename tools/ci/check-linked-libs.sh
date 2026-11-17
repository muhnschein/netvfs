#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Checks a Rust binary of netvfs from ELF headers:
#   - NEEDED is exactly the given list (sorted, space separated);
#   - no GLIBC symbol version above the given one (target glibc is the floor);
#   - position independent, full RELRO, immediate binding, no executable stack.
# Usage: check-linked-libs.sh <binary> "<lib> <lib> ..." <max glibc version>
set -eu
binary=$1
expected=$2
max_glibc=$3
name=$(basename "$binary")
status=0
fail() {
    echo "FAIL: $name: $1"
    status=1
}

needed=$(readelf -d "$binary" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ' | sed 's/ $//')
expected=$(echo "$expected" | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
[ "$needed" = "$expected" ] || fail "links \"$needed\", expected \"$expected\""

highest=$(readelf -W --dyn-syms "$binary" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)
if [ -n "$highest" ] && [ "$(printf '%s\n%s\n' "$highest" "$max_glibc" | sort -V | tail -n 1)" != "$max_glibc" ]; then
    fail "needs GLIBC_$highest, the target has $max_glibc"
fi

readelf -h "$binary" | grep -q 'Type: *DYN' || fail "not position independent"
readelf -lW "$binary" | grep -q GNU_RELRO || fail "no RELRO"
readelf -d "$binary" | grep -Eq 'FLAGS.*(BIND_NOW| NOW)' || fail "does not bind now"
stack=$(readelf -lW "$binary" | grep GNU_STACK || true)
case "$stack" in
    *RWE*) fail "executable stack" ;;
    "") fail "no GNU_STACK header" ;;
esac
[ "$status" -ne 0 ] || echo "$name: links $needed, GLIBC_${highest:-none} <= $max_glibc, PIE, RELRO, BIND_NOW, NX stack"
exit $status
