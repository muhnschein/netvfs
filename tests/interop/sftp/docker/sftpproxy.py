#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""SFTP subsystem wrapper for the interop suite. Runs the real sftp-server
and passes the client's data through unchanged. The server's replies are
forwarded as whole SFTP packets, with two optional changes:

  --no-extensions    rewrite SSH_FXP_VERSION to plain version 3 without
                     extension pairs (S-T17: no posix-rename, fsync,
                     statvfs or limits)
  --hold-file PATH   while PATH exists, hold back further replies; the
                     client then waits for an answer without ever seeing
                     half a packet (C-9 cancel while waiting)
"""
import os
import select
import subprocess
import sys
import time

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


def parse(arguments):
    strip = False
    hold = None
    while arguments and arguments[0].startswith("--"):
        option = arguments.pop(0)
        if option == "--no-extensions":
            strip = True
        elif option == "--hold-file":
            hold = arguments.pop(0)
    return strip, hold, arguments


def next_reply(fd, strip):
    header = read_exact(fd, 4)
    body = header and read_exact(fd, int.from_bytes(header, "big"))
    if not body:
        return None
    if strip:
        # type (SSH_FXP_VERSION) and version only; drop the extensions.
        return (5).to_bytes(4, "big") + body[:5]
    return header + body


def main():
    strip, hold, command = parse(sys.argv[1:])
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    to_child = child.stdin.fileno()
    from_child = child.stdout.fileno()
    sources = [0, from_child]
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
        reply = next_reply(from_child, strip)
        strip = False
        if reply is None:
            break
        while hold and os.path.exists(hold):
            time.sleep(0.05)
        write_all(1, reply)
    child.wait()


if __name__ == "__main__":
    main()
