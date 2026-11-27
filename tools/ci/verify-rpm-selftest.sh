#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/verify-rpm.sh"

status=0

prints_usage() {
    local why=$1
    shift
    local got code
    got=$(sh "$script" "$@" 2>&1 > /dev/null)
    code=$?
    if [[ $code -eq 3 && "$got" == "usage: tools/verify-rpm.sh --ref <ref> <rpm>..."* && "$got" == *"--ref <ref>  commit"* && "$got" == *"<rpm>        packages"* && "$got" != *'$'* ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- exit $code, printed:" >&2
        echo "$got" >&2
        status=1
    fi
}

prints_usage "--help prints usage" --help
prints_usage "no arguments print usage"
prints_usage "--ref without RPMs prints usage" --ref main
prints_usage "--ref without value prints usage" --ref

if [[ $status -eq 0 ]]; then
    echo "selftest: verify-rpm usage passed"
fi
exit "$status"
