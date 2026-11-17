#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Backtrace each test process that died by signal. ci.yml points `kernel.core_pattern` at `<dir>/core.%p.%E` (%E: binary path, `/` as `!`).
# Each core gets its binary copied beside it and `<core>.txt` (all threads' stacks, also printed to the log).
# gdb is fetched only here: green runs never pay for it.
#
#   tools/ci/core-backtraces.sh <dir>
set -euo pipefail

dir=${1:?usage: tools/ci/core-backtraces.sh <dir>}
cores=()
for core in "$dir"/core.*; do
    [[ -f "$core" && "$core" != *.txt ]] && cores+=("$core")
done

if [[ ${#cores[@]} -eq 0 ]]; then
    echo "core-backtraces: no core in $dir"
    exit 0
fi

if ! command -v gdb >/dev/null 2>&1; then
    "$(dirname -- "$0")/apt-install.sh" gdb
fi

for core in "${cores[@]}"; do
    name=${core##*/}
    # core.<pid>.<path, ! for />
    exe=${name#core.*.}
    exe=${exe//!//}
    echo "core-backtraces: $name, from $exe"
    if [[ ! -f "$exe" ]]; then
        echo "core-backtraces: $exe is gone; core kept without it" | tee "$core.txt"
        continue
    fi
    cp -- "$exe" "$dir/"
    gdb -batch -nx -ex 'thread apply all bt' "$exe" "$core" 2>&1 | tee "$core.txt"
done
