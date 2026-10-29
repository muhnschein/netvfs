#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Prove tools/ci/mutation-lists.py runs the lists a change can affect.
#
# Costly mistake: a list left out although its code or tests changed, so a
# PR that stops its tests biting goes green. Most cases guard that side.
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/ci/mutation-lists.py"
all=$("$script" --all)

status=0

# says <want: JSON array or "all"> <why> <file names, one per line>
says() {
    local want=$1 why=$2 files=$3 got
    [[ "$want" = all ]] && want=${all#lists=}
    got=$("$script" --classify <<<"$files")
    if [[ "$got" = "lists=$want" ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- got $got, wanted lists=$want" >&2
        status=1
    fi
    return 0
}

says '["bridge"]' "a bridge source runs the bridge list" "rust/netvfs-bridge/src/peer.rs"
says '["bridge"]' "a bridge test runs it" "rust/netvfs-bridge/tests/server.rs"
says '["bridge"]' "a test folder named by a test command runs its list" \
    "tests/bridge/contract/tst_contract.cpp"
says '["bridge"]' "a mutated crate's other files run its list" \
    "rust/netvfs-bridge-proto/Cargo.toml"
says '["smb"]' "an SMB interop test runs the SMB list" "tests/interop/smb/run.sh"
says '["ops"]' "a pipe test runs the ops list" "tests/unit/pipe/tst_boundedpipe.cpp"
says '["accounts","bridge","core","discovery","ops","url"]' \
    "the C++ core runs every list that mutates it" "src/core/url.cpp"
says '["cli"]' "a list's own JSON runs it" "tests/mutations/cli.json"
says '["bridge","helper","sftp","smb"]' "the lockfile runs the Rust lists" "rust/Cargo.lock"
says '["bridge","helper","sftp","smb"]' "a vendored crate runs them" \
    "rust/vendor/ssh-key/src/lib.rs"
says '["bridge","helper","sftp","smb"]' "the shared VFS crate runs them" \
    "rust/netvfs-vfs/src/backend.rs"
says '["bridge","ffi","helper"]' "bridge test helpers run the bridge-test lists" \
    "tests/bridge/common/bridgetest.cpp"
says all "the mutation checker runs all" "tools/mutation-check.py"
says all "this rule runs all" "tools/ci/mutation-lists.py"
says all "the CI workflow runs all" ".github/workflows/ci.yml"
says all "a qmake project runs all" "src/bridge/bridge.pro"
says all "a qmake include runs all" "tests/test.pri"
says all "the Makefile runs all" "Makefile"
says all "the toolchain runs all" "rust/rust-toolchain.toml"
says all "shared test code runs all" "tests/common/accountsfixture.h"
says all "an empty list runs all" ""
says '[]' "docs outside any area run none" $'doc/SPEC.md\nREADME.md'
says '[]' "the CodeQL workflow runs none" ".github/workflows/codeql.yml"

# event <want> <why> <EVENT>
event() {
    local want=$1 why=$2 got
    got=$(EVENT=$3 "$script" 2>/dev/null)
    if [[ "$got" = "lists=$want" ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- got $got, wanted lists=$want" >&2
        status=1
    fi
    return 0
}
event '[]' "a push to main runs none (its PR ran them)" push
event "${all#lists=}" "the weekly run runs all" schedule
event "${all#lists=}" "a run by hand runs all" workflow_dispatch
count=$(ls "$root"/tests/mutations/*.json | wc -l)
if [[ $(python3 -c 'import json,sys;print(len(json.loads(sys.argv[1][6:])))' "$all") -eq "$count" ]]; then
    echo "selftest: ok   --all names every list"
else
    echo "selftest: FAIL --all names $all, not the $count lists" >&2
    status=1
fi
exit "$status"
