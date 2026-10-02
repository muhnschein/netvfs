#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Stalling proxies for the SFTP interop suite.

Subsystem mode (the default): an SFTP subsystem wrapper. Runs the real
sftp-server and passes the client's data through unchanged. The server's
replies are forwarded as whole SFTP packets, with two optional changes:

  --no-extensions    rewrite SSH_FXP_VERSION to plain version 3 without
                     extension pairs (S-T17: no posix-rename, fsync,
                     statvfs or limits)
  --hold-file PATH   while PATH exists, hold back further replies; the
                     client then waits for an answer without ever seeing
                     half a packet (C-9 cancel while waiting)

Relay mode (--relay LISTEN_PORT TARGET_PORT --hold-file PATH): a TCP relay
to 127.0.0.1:TARGET_PORT for whole SSH connections. While PATH exists it
forwards nothing in either direction, so every request of a connection,
SSH global requests (keepalive@openssh.com) included, stays unanswered.
The conformance suite engages it only while a connection is idle, so no
reply is ever cut in half (tests/conformance, cancelStalledProxy).
"""
import os
import select
import socket
import subprocess
import sys
import threading
import time

CHUNK = 256 * 1024
HOLD_POLL = 0.05


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
    relay = None
    while arguments and arguments[0].startswith("--"):
        option = arguments.pop(0)
        if option == "--no-extensions":
            strip = True
        elif option == "--hold-file":
            hold = arguments.pop(0)
        elif option == "--relay":
            relay = (int(arguments.pop(0)), int(arguments.pop(0)))
    return strip, hold, relay, arguments


def next_reply(fd, strip):
    header = read_exact(fd, 4)
    body = header and read_exact(fd, int.from_bytes(header, "big"))
    if not body:
        return None
    if strip:
        # type (SSH_FXP_VERSION) and version only; drop the extensions.
        return (5).to_bytes(4, "big") + body[:5]
    return header + body


def wait_while(hold):
    while hold and os.path.exists(hold):
        time.sleep(HOLD_POLL)


def subsystem(strip, hold, command):
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
        wait_while(hold)
        write_all(1, reply)
    child.wait()


def pump(client, server, hold):
    peers = {client: server, server: client}
    try:
        while True:
            wait_while(hold)
            readable, _, _ = select.select(list(peers), [], [], HOLD_POLL)
            for sock in readable:
                if hold and os.path.exists(hold):
                    break
                data = sock.recv(CHUNK)
                if not data:
                    return
                peers[sock].sendall(data)
    except OSError:
        return
    finally:
        client.close()
        server.close()


def relay(listen_port, target_port, hold):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", listen_port))
    listener.listen(16)
    while True:
        client, _ = listener.accept()
        try:
            server = socket.create_connection(("127.0.0.1", target_port))
        except OSError:
            client.close()
            continue
        threading.Thread(target=pump, args=(client, server, hold), daemon=True).start()


def main():
    strip, hold, relay_ports, command = parse(sys.argv[1:])
    if relay_ports:
        relay(relay_ports[0], relay_ports[1], hold)
    else:
        subsystem(strip, hold, command)


if __name__ == "__main__":
    main()
