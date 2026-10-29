#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Which mutation lists (tests/mutations/*.json) a CI run checks. Prints
`lists=<JSON array>` for $GITHUB_OUTPUT (ci.yml `changes`).

A list's verdict changes only with its code or its tests, so a pull request
runs the lists whose area it touches: each mutant's file (its crate under
rust/), the folders of the paths its test command names, the list itself.
Shared build and test setup runs more or all. Push to main: none, its pull
request ran them. Weekly and by hand: all, which catches indirect changes
(a helper outside the area).

Usage:  tools/ci/mutation-lists.py            (EVENT = github.event_name; PR: merge commit vs base)
        tools/ci/mutation-lists.py --all
        tools/ci/mutation-lists.py --classify (file names on stdin; for selftest)
"""
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Any of these changes what every list builds or how it is checked.
RUN_ALL = [
    re.compile(p) for p in (
        r"^tools/mutation-check\.py$",
        r"^tools/ci/mutation-lists\.py$",
        r"^tools/ci/install-host-deps\.sh$",
        r"^\.github/workflows/ci\.yml$",
        r"^Makefile$",
        r"\.pr[io]$",
        r"^rust/rust-toolchain\.toml$",
        r"^vendor/",
        r"^tests/(common|fakeplugin)/",
    )
]
# Shared by many: runs every list with an area under the second prefix.
SHARED = [
    (re.compile(r"^rust/(Cargo\.(toml|lock)$|vendor/|netvfs-vfs/|netvfs-backend/)"), "rust/"),
    (re.compile(r"^tests/bridge/common/"), "tests/bridge/"),
    (re.compile(r"^tests/unit/fake/"), "tests/unit/"),
]
REPO_PATH = re.compile(r"(?:^|[\s=/])((?:src|tests|tools|rust|accounts)/[\w./-]+)")


def lists():
    return sorted(os.path.basename(p)[:-len(".json")]
                  for p in glob.glob(os.path.join(ROOT, "tests/mutations/*.json")))


def folder(path):
    parts = path.split("/")
    if parts[0] == "rust" and len(parts) > 2:
        return "/".join(parts[:2]) + "/"
    return os.path.dirname(path) + "/"


def area(name):
    """Path prefixes whose change can change this list's verdict."""
    with open(os.path.join(ROOT, "tests/mutations", name + ".json")) as f:
        mutations = json.load(f)
    prefixes = {"tests/mutations/" + name + ".json"}
    for m in mutations:
        prefixes.add(folder(m["file"]))
        for path in REPO_PATH.findall(m["test"]):
            # build/tests/unit/ops/tst_ops: its sources are in tests/unit/ops/.
            prefixes.add(folder(path))
    return prefixes


def classify(files):
    files = [f for f in files if f]
    names = lists()
    # Nothing named: empty diff is no proof.
    if not files or any(p.search(f) for p in RUN_ALL for f in files):
        return names
    parents = {parent for pattern, parent in SHARED for f in files if pattern.search(f)}
    chosen = []
    for name in names:
        prefixes = area(name)
        if (any(f.startswith(p) for p in prefixes for f in files)
                or any(p.startswith(parent) for p in prefixes for parent in parents)):
            chosen.append(name)
    return chosen


def main():
    if sys.argv[1:] == ["--all"]:
        chosen = lists()
    elif sys.argv[1:] == ["--classify"]:
        chosen = classify(sys.stdin.read().splitlines())
    elif os.environ.get("EVENT") == "push":
        chosen = []
    elif os.environ.get("EVENT") != "pull_request":
        chosen = lists()
    else:
        # PR checkout = merge commit: first parent = base.
        diff = subprocess.run(["git", "diff", "--name-only", "HEAD^1", "HEAD"],
                              cwd=ROOT, capture_output=True, text=True)
        if diff.returncode != 0:
            print("mutation-lists: diff unreadable; running all", file=sys.stderr)
            chosen = lists()
        else:
            chosen = classify(diff.stdout.splitlines())
    print("lists=" + json.dumps(chosen, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
