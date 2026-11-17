#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Prove changes.sh skips build and test jobs for docs alone, never for anything else. Costly mistake: code read as docs-only, CI green without tests; most cases guard that side.
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/ci/changes.sh"

if [[ ! -x "$script" ]]; then
    echo "selftest: FAIL $script is missing or not executable" >&2
    exit 1
fi

status=0
cases=0

# says <want> <why> <file names, one per line>
says() {
    local want=$1 why=$2 files=$3
    cases=$((cases + 1))
    local got
    got=$("$script" --classify <<<"$files")
    if [[ "$got" = "code=$want" ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- got $got, wanted code=$want" >&2
        status=1
    fi
    return 0
}

says false "docs alone skip the jobs" $'doc/SPEC.md\nREADME.md\nAGENTS.md'
says false "changelog alone skips them" "CHANGELOG.md"
says false "a test's README alone skips them" "tests/fuzz/README.md"
says true "a source file runs them" "rust/netvfs-smb/src/client.rs"
says true "a page runs them" $'doc/SPEC.md\naccounts/ui/qml/AccountSettings.qml'
says true "code after docs still runs them" $'README.md\nMakefile'
says true "a vendored crate's README runs them (ssh-key builds it in)" \
    "rust/vendor/ssh-key/README.md"
says true "a vendored crate's patch notes run them" \
    "rust/vendor/picky-asn1-der/README.netvfs.md"
says true "a submodule's docs run them" "vendor/host/buteo-syncfw/README.md"
says true "a file only named like docs runs them" "CHANGELOG.md.orig"
says true "an empty list runs them" ""

# Whole script on own repo: last commit touches docs alone, so only the event can make it run everything.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git_() {
    git -C "$work" -c user.name=t -c user.email=t@t "$@" >/dev/null 2>&1
    return $?
}
git_ init -q
echo a >"$work/main.rs"
git_ add . && git_ commit -qm code

# event <want> <why> <EVENT>: script run in $work.
event() {
    local want=$1 why=$2 got
    cases=$((cases + 1))
    got=$(cd "$work" && EVENT=$3 "$script" 2>/dev/null)
    if [[ "$got" = "code=$want" ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- got $got, wanted code=$want" >&2
        status=1
    fi
    return 0
}

event true "a first commit (no base to diff) runs everything" pull_request
echo a >"$work/README.md"
git_ add . && git_ commit -qm docs
event false "a PR touching docs alone skips them" pull_request
event true "a push to main runs everything" push
event true "a manual run runs everything" workflow_dispatch
echo b >"$work/main.rs"
git_ add . && git_ commit -qm code
event true "a PR touching code runs them" pull_request

echo "selftest: $cases case(s)"
if [[ "$status" -ne 0 ]]; then
    echo "selftest: FAILED" >&2
fi
exit "$status"
