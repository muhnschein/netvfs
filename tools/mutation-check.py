#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Checks that the tests bite: applies each mutation from tests/mutations/*.json,
rebuilds, runs the named test command and expects it to FAIL. Every mutation
that survives (tests still pass) is reported and makes the run fail.

Mutation file format: a JSON list of objects
  {"name": ..., "file": <repo path>, "search": <exact text>, "replace": <text>,
   "test": <shell command run from the repo root, e.g. "build/tests/unit/core/tst_core">}
`search` must occur exactly once in `file`.

Usage: tools/mutation-check.py [--build DIR] [mutation files...]
"""
import argparse
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, env=None):
    return subprocess.run(cmd, shell=True, cwd=ROOT, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", default="build")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args()
    files = args.files or sorted(glob.glob(os.path.join(ROOT, "tests/mutations/*.json")))

    env = dict(os.environ)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    survivors = []
    total = 0
    for path in files:
        with open(path) as f:
            mutations = json.load(f)
        for m in mutations:
            total += 1
            target = os.path.join(ROOT, m["file"])
            with open(target) as f:
                original = f.read()
            count = original.count(m["search"])
            if count != 1:
                print(f"BROKEN   {m['name']}: search text found {count} times in {m['file']}")
                survivors.append(m["name"])
                continue
            try:
                with open(target, "w") as f:
                    f.write(original.replace(m["search"], m["replace"]))
                build = run(f"make -C {args.build} -j{os.cpu_count()}", env)
                if build.returncode != 0:
                    print(f"KILLED   {m['name']} (does not compile)")
                    continue
                test = run(m["test"], env)
                if test.returncode == 0:
                    print(f"SURVIVED {m['name']}")
                    survivors.append(m["name"])
                else:
                    print(f"KILLED   {m['name']}")
            finally:
                with open(target, "w") as f:
                    f.write(original)
    run(f"make -C {args.build} -j{os.cpu_count()}", env)
    print(f"{total - len(survivors)}/{total} mutations killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
