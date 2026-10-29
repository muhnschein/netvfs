#!/bin/sh
# Interop suite (SPEC 12.2): containerised servers + per-backend test drivers.
# Usage: run.sh <build dir>. Each backend contributes tests/interop/<p>/run.sh.
# Suites run side by side (own servers each; mostly wait on them), each
# log printed whole once all ended.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
build=$1
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT
for suite in "$here"/*/run.sh; do
    [ -f "$suite" ] || continue
    name=$(basename "$(dirname "$suite")")
    (sh "$suite" "$build" >"$logs/$name.log" 2>&1 || echo failed >"$logs/$name.failed") &
done
wait
status=0
for log in "$logs"/*.log; do
    name=$(basename "$log" .log)
    echo "== interop: $name"
    cat "$log"
    if [ -e "$logs/$name.failed" ]; then
        echo "== interop: $name FAILED"
        status=1
    fi
done
exit $status
