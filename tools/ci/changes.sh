#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Does this change need build and test jobs? Prints `code=true|false` for $GITHUB_OUTPUT (`changes` job in ci.yml, build.yml).
#
# false only for a PR touching nothing but `*.md` outside vendor/ and rust/vendor/ (rust/vendor/ssh-key includes its README.md in docs; vendor/ holds submodules). Push to main, dispatch, unreadable diff: true. Running too much costs minutes; skipping wrongly costs a red main.
#
# Usage:  tools/ci/changes.sh                 (PR: diff of merge commit vs base)
#         tools/ci/changes.sh --classify      (file names on stdin; for selftest)
#
# EVENT = github.event_name.
set -euo pipefail

# File names on stdin; docs only = every one `*.md`, none under vendor/ or rust/vendor/. Nothing named = true.
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

# PR checkout = merge commit: first parent = base, so this is the PR's change.
if ! files=$(git diff --name-only HEAD^1 HEAD); then
    echo "changes: diff unreadable; running everything" >&2
    echo code=true
    exit 0
fi
classify <<<"$files"
