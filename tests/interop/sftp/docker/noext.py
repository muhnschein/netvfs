#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""SFTP subsystem wrapper for S-T17: runs the real sftp-server and rewrites
its SSH_FXP_VERSION reply to plain version 3 without any extension pairs, so
the client sees a server without posix-rename, fsync, statvfs and limits.
Everything else is passed through unchanged."""
import os
import select
import subprocess
import sys

CHUNK = 256 * 1024


def read_exact(fd, size):
    data = b""
    while len(data) < size:
        part = os.read(fd, size - len(data))
        if not part:
            return None
        data += part
    return data


def write_all(fd, data):
    while data:
        data = data[os.write(fd, data):]


def main():
    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    to_child = child.stdin.fileno()
    from_child = child.stdout.fileno()
    sources = [0, from_child]
    first = True
    while from_child in sources:
        readable, _, _ = select.select(sources, [], [])
        if 0 in readable:
            data = os.read(0, CHUNK)
            if data:
                write_all(to_child, data)
            else:
                child.stdin.close()
                sources.remove(0)
        if from_child not in readable:
            continue
        if first:
            header = read_exact(from_child, 4)
            body = header and read_exact(from_child, int.from_bytes(header, "big"))
            if not body:
                break
            # type (SSH_FXP_VERSION) and version only; drop the extensions.
            write_all(1, (5).to_bytes(4, "big") + body[:5])
            first = False
            continue
        data = os.read(from_child, CHUNK)
        if not data:
            break
        write_all(1, data)
    child.wait()


if __name__ == "__main__":
    main()
