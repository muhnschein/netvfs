#!/bin/sh
# Interop suite (SPEC 12.2): containerised servers + per-backend test drivers.
# Usage: run.sh <build dir>. Each backend contributes tests/interop/<p>/run.sh.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
build=$1
status=0
for suite in "$here"/*/run.sh; do
    [ -f "$suite" ] || continue
    echo "== interop: $(basename "$(dirname "$suite")")"
    sh "$suite" "$build" || status=1
done
exit $status
