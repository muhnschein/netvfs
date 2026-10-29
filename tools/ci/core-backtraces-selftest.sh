#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Prove tools/ci/core-backtraces.sh turns a test's core into a readable backtrace.
#
# Real core of a real binary (gdb writes it, stopped at its first
# instruction), named as ci.yml's `kernel.core_pattern` names it. Needs gdb:
# missing = SKIP locally, FAIL in CI.
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/ci/core-backtraces.sh"

if ! command -v gdb >/dev/null 2>&1; then
    if [[ -n "${CI:-}" ]]; then
        echo "selftest: FAIL gdb not installed" >&2
        exit 1
    fi
    echo "selftest: SKIP gdb not installed"
    exit 0
fi

status=0
cases=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# check <why> <command...>: passes when command does.
check() {
    local why=$1
    shift
    cases=$((cases + 1))
    if "$@"; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why" >&2
        status=1
    fi
    return 0
}

# Binary of our own, so "gone" can be made true.
exe="$work/bin/crasher"
mkdir -p "$work/bin"
cp "$(command -v sleep)" "$exe"
core_of() {
    local dir=$1 binary=$2
    mkdir -p "$dir"
    local core="$dir/core.4242.${binary//\//!}"
    gdb -batch -nx -ex starti -ex "generate-core-file $core" --args "$binary" 5 >/dev/null 2>&1
    echo "$core"
    return 0
}

empty="$work/empty"
mkdir -p "$empty"
out=$("$script" "$empty" 2>&1)
check "no core: says so, succeeds, no gdb run" \
    test "$?" -eq 0 -a "$out" = "core-backtraces: no core in $empty"

one="$work/one"
core=$(core_of "$one" "$exe")
out=$("$script" "$one" 2>&1)
check "a core: succeeds" test "$?" -eq 0
check "a core: its stack is printed" grep -q '^#0 ' <<<"$out"
check "a core: its stack is kept beside it" grep -q '^#0 ' "$core.txt"
check "a core: its binary is copied beside it, path read from the name" \
    cmp -s "$exe" "$one/crasher"

# Rerun over kept results: `.txt` and copied binary are not cores.
out=$("$script" "$one" 2>&1)
check "rerun: only the core is read" \
    test "$(grep -c '^core-backtraces: core\.' <<<"$out")" -eq 1

gone="$work/gone"
core=$(core_of "$gone" "$exe")
rm "$exe"
out=$("$script" "$gone" 2>&1)
check "binary gone: still succeeds" test "$?" -eq 0
check "binary gone: says so beside the core" grep -q "is gone" "$core.txt"

if [[ $status -eq 0 ]]; then
    echo "selftest: all $cases cases passed"
fi
exit $status
