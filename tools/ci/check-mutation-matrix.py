#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fails when the CI mutation matrix (.github/workflows/ci.yml, job "mutation")
does not name exactly the lists in tests/mutations/*.json, so that a new list
cannot be left out of the "Tests bite" jobs."""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    with open(os.path.join(ROOT, ".github/workflows/ci.yml")) as f:
        workflow = f.read()
    match = re.search(r"^  mutation:\n(?:.*\n)*?\s+list: \[([^\]]*)\]", workflow, re.M)
    if not match:
        print("ci.yml: no mutation matrix found")
        return 1
    listed = {name.strip() for name in match.group(1).split(",") if name.strip()}
    present = {os.path.basename(p)[:-len(".json")]
               for p in glob.glob(os.path.join(ROOT, "tests/mutations/*.json"))}
    for name in sorted(present - listed):
        print("mutation list not in the CI matrix:", name)
    for name in sorted(listed - present):
        print("CI matrix names a missing mutation list:", name)
    return 1 if present != listed else 0


if __name__ == "__main__":
    sys.exit(main())
