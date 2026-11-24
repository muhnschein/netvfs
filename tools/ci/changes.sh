#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

classify() {
    local file seen=0
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        seen=1
        case "$file" in
        vendor/* | rust/vendor/*)
            echo code=true
            return 0
            ;;
        *.md) ;;
        *)
            echo code=true
            return 0
            ;;
        esac
    done
    if [[ "$seen" -eq 0 ]]; then
        echo code=true
    else
        echo code=false
    fi
    return 0
}

if [[ "${1:-}" = --classify ]]; then
    classify
    exit 0
fi

event=$(printenv EVENT || true)
if [[ "$event" != pull_request ]]; then
    echo code=true
    exit 0
fi

if ! files=$(git diff --name-only HEAD^1 HEAD); then
    echo "changes: diff unreadable; running everything" >&2
    echo code=true
    exit 0
fi
classify <<<"$files"
