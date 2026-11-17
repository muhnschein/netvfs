#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs inside the SDK container: mb2 build of the RPMs. Rust binaries come prebuilt today; once the spec runs cargo
# again: cargo under scratchbox2 occasionally deadlocks in a forked child before exec (lock held at fork time in the sb2
# preload), so the build restarts when its log has not grown for 10 minutes. Built steps are kept between attempts.
set -uo pipefail
target=$1
stall_limit=600
for attempt in 1 2 3 4 5; do
    : > build.log
    mb2 -t "$target" build -j "$(nproc)" > build.log 2>&1 &
    pid=$!
    last_size=-1
    idle=0
    stalled=no
    while kill -0 "$pid" 2>/dev/null; do
        sleep 15
        size=$(stat -c %s build.log)
        if [[ "$size" -ne "$last_size" ]]; then
            last_size=$size
            idle=0
        else
            idle=$((idle + 15))
        fi
        if [[ "$idle" -ge "$stall_limit" ]]; then
            stalled=yes
            echo "attempt $attempt: no build output for $stall_limit s, restarting"
            pkill -f 'cargo build' || true
            break
        fi
    done
    wait "$pid"
    status=$?
    tail -n 60 build.log
    if [[ "$status" -eq 0 ]]; then
        exit 0
    fi
    # With -j the failing step has usually scrolled out of the tail.
    echo "== errors in build.log"
    grep -n -E -B 2 -A 4 '(error|Error):|Error [0-9]+$|undefined reference|\*\*\* ' build.log | head -n 150
    [[ "$stalled" = yes ]] || exit "$status"
done
echo "cargo kept stalling under scratchbox2"
exit 1
