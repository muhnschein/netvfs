#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
script="$root/tools/ci/rust-mutants.sh"

status=0

prints_usage() {
    local why=$1
    shift
    local got code
    got=$(sh "$script" "$@" 2>&1 > /dev/null)
    code=$?
    if [[ $code -eq 2 \
        && "$got" == *"Usage: rust-mutants.sh diff <base revision> [<ffi-libs.sh dir> [<k>/<n>]]"* \
        && "$got" == *"Usage: rust-mutants.sh crate <package> [<ffi-libs.sh dir> [<k>/<n>]]"* \
        && "$got" == *"Usage: rust-mutants.sh interop <package> <base revision | all> <k>/<n> <command>"* \
        && "$got" != *'$'* ]]; then
        echo "selftest: ok   $why"
    else
        echo "selftest: FAIL $why -- exit $code, printed:" >&2
        echo "$got" >&2
        status=1
    fi
}

prints_usage "no arguments print usage"
prints_usage "--help prints usage" --help
prints_usage "unknown mode prints usage" bogus origin/main
prints_usage "interop without command prints usage" interop netvfs-sftp all 0/1

if [[ $status -eq 0 ]]; then
    echo "selftest: rust-mutants usage passed"
fi
exit "$status"
