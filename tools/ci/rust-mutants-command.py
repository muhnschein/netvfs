#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""The interop mode of tools/ci/rust-mutants.sh: tests each mutant that
`cargo mutants --list --json --diff` listed with a command of its own
instead of the Rust tests.

For each mutant, in place and one at a time: apply its diff, check that its
package still builds (else it is unviable), run the command (sh -c, from the
repository root), restore the file. The command failing catches the mutant;
passing misses it; running out of time counts as caught (the mutant made it
hang). The command first runs once unmutated and must pass; its time limit
per mutant is 300 s plus three times that run's duration
(NETVFS_MUTANTS_TIMEOUT: seconds, instead).

Results in rust/mutants.out as cargo-mutants writes them (caught.txt,
missed.txt, timeout.txt, unviable.txt) with each run's output in log/.
Exit status 0 when nothing was missed, 1 when something was, 4 when the
unmutated run failed or a diff did not apply. Afterwards the build the
command made holds the last mutant: rebuild before using it.

Usage: rust-mutants-command.py <mutants.json> <command>
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST = os.path.join(ROOT, "rust")
OUT = os.path.join(RUST, "mutants.out")


def run(command, log, timeout=None):
    """Runs `command` (sh -c, from the repository root) into `log`: its exit
    status, or None when it ran out of time (its whole process group is
    then killed)."""
    with open(log, "a") as out:
        out.write(f"$ {command}\n")
        out.flush()
        process = subprocess.Popen(command, shell=True, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            out.write(f"\n*** timed out after {timeout:.0f} s\n")
            return None


def patched(mutant):
    """The mutant's diff with its file as the new name too (cargo-mutants
    puts the mutation's description there)."""
    lines = mutant["diff"].splitlines(keepends=True)
    return "".join(f"+++ {mutant['file']}\n" if line.startswith("+++ ") else line for line in lines)


def test(mutant, command, timeout, log):
    """The outcome of one mutant: caught, missed, timeout or unviable."""
    path = os.path.join(RUST, mutant["file"])
    with open(path, "rb") as f:
        original = f.read()
    try:
        applied = subprocess.run(["patch", "-p0", "--forward", "--silent", "--no-backup-if-mismatch"],
                                 cwd=RUST, input=patched(mutant), text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if applied.returncode != 0:
            print(f"the diff of {mutant['name']} does not apply:\n{applied.stdout}", file=sys.stderr)
            return None
        check = f"cd rust && cargo check --locked --package {mutant['package']} --all-features --all-targets"
        if run(check, log) != 0:
            return "unviable"
        status = run(command, log, timeout)
        if status is None:
            return "timeout"
        return "missed" if status == 0 else "caught"
    finally:
        with open(path, "wb") as f:
            f.write(original)


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(sys.argv[1]) as f:
        mutants = json.load(f)
    command = sys.argv[2]
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "log"))

    started = time.monotonic()
    if run(command, os.path.join(OUT, "log", "baseline.log")) != 0:
        print("the command fails without a mutant (mutants.out/log/baseline.log)", file=sys.stderr)
        return 4
    baseline = time.monotonic() - started
    timeout = float(os.environ.get("NETVFS_MUTANTS_TIMEOUT") or 300 + 3 * baseline)
    print(f"{len(mutants)} mutants; the command took {baseline:.0f} s unmutated, "
          f"{timeout:.0f} s allowed per mutant")

    outcomes = {"caught": [], "missed": [], "timeout": [], "unviable": []}
    for number, mutant in enumerate(mutants, 1):
        started = time.monotonic()
        outcome = test(mutant, command, timeout, os.path.join(OUT, "log", f"{number}.log"))
        if outcome is None:
            return 4
        outcomes[outcome].append(mutant["name"])
        print(f"{outcome:9} {mutant['name']} in {time.monotonic() - started:.0f} s", flush=True)

    for outcome, names in outcomes.items():
        with open(os.path.join(OUT, f"{outcome}.txt"), "w") as f:
            f.writelines(name + "\n" for name in names)
    print(f"{len(mutants)} mutants tested: " + ", ".join(f"{len(n)} {o}" for o, n in outcomes.items()))
    if outcomes["missed"]:
        print("missed mutants:\n" + "\n".join(outcomes["missed"]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
