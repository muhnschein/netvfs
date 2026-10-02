#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Test helpers for the FTP interop suite (SPEC-v2 XT-1, XT-5).

Listens on 127.0.0.1 (an ephemeral port, printed as the first line on
stdout) and serves one of three modes:

  forward --target HOST:PORT [--hold REGEX]
      Plain TCP proxy for the control connection. Once a client command
      matches REGEX, nothing the server sends reaches the client any more
      (a server that stops answering, for the C-9 cancel tests). SIGUSR1
      closes every open session (a server restart, for keepAlive).
  silent
      Accepts connections and never sends anything (no greeting).
  fake --tls explicit|implicit|none --cert FILE --key FILE --log FILE
      A minimal FTP server that records everything the client sends: the
      clear text before TLS and the decrypted text after it, one line per
      command, plus TLS-START / TLS-OK / TLS-FAIL markers. USER gets 331,
      PASS 530. The identity tests (XT-5) read the log to prove that no USER
      command was sent before the identity was accepted. With --busy N the
      2nd to (N+1)th connection is greeted with "421 Too many connections"
      and closed (logged as BUSY), like a server with a connection limit
      that still counts the client's previous connection.
"""
import argparse
import re
import signal
import socket
import ssl
import sys
import threading

sessions = []
sessions_lock = threading.Lock()


def listen():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    print(server.getsockname()[1], flush=True)
    return server


def track(sock):
    with sessions_lock:
        sessions.append(sock)


def close_all(*_):
    with sessions_lock:
        for sock in sessions:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        sessions.clear()


# ------------------------------------------------------------------ forward

def pump(source, sink, hold_state, inspect, pattern):
    pending = b""
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            if inspect:
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if pattern and pattern.search(line.decode("latin-1")):
                        hold_state["held"] = True
                sink.sendall(data)
            elif not hold_state["held"]:
                sink.sendall(data)
    except OSError:
        pass
    for sock in (source, sink):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def forward(args):
    host, port = args.target.rsplit(":", 1)
    pattern = re.compile(args.hold) if args.hold else None
    server = listen()
    signal.signal(signal.SIGUSR1, close_all)
    while True:
        try:
            client, _ = server.accept()
        except InterruptedError:
            continue
        upstream = socket.create_connection((host, int(port)))
        track(client)
        track(upstream)
        state = {"held": False}
        threading.Thread(target=pump, args=(client, upstream, state, True, pattern), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, state, False, None), daemon=True).start()


# ------------------------------------------------------------------- silent

def silent(_args):
    server = listen()
    held = []
    while True:
        client, _ = server.accept()
        held.append(client)


# --------------------------------------------------------------------- fake

class Recorder:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, text):
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as log:
                log.write(text + "\n")


def read_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            return None
        data += chunk
    return data.rstrip(b"\r\n").decode("latin-1")


def start_tls(conn, context, recorder):
    recorder.write("TLS-START")
    try:
        tls = context.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as error:
        recorder.write("TLS-FAIL " + type(error).__name__)
        return None
    recorder.write("TLS-OK")
    return tls


REPLIES = {
    "USER": b"331 Password required\r\n",
    "PASS": b"530 Login incorrect\r\n",
    "PBSZ": b"200 PBSZ=0\r\n",
    "PROT": b"200 Protection set\r\n",
    "QUIT": b"221 Bye\r\n",
}


def serve_fake(conn, args, context, recorder):
    if args.tls == "implicit":
        conn = start_tls(conn, context, recorder)
        if conn is None:
            return
    conn.sendall(b"220 netvfs fake FTP server\r\n")
    while True:
        line = read_line(conn)
        if line is None:
            recorder.write("CLOSED")
            return
        recorder.write("C: " + line)
        verb = line.split(" ", 1)[0].upper()
        if verb == "AUTH" and args.tls == "explicit" and not isinstance(conn, ssl.SSLSocket):
            conn.sendall(b"234 Proceed with negotiation\r\n")
            conn = start_tls(conn, context, recorder)
            if conn is None:
                return
            continue
        conn.sendall(REPLIES.get(verb, b"502 Not implemented\r\n"))
        if verb == "QUIT":
            return


def fake(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if args.cert:
        context.load_cert_chain(args.cert, args.key)
    recorder = Recorder(args.log)
    server = listen()
    accepted = 0
    while True:
        client, _ = server.accept()
        accepted += 1
        if 1 < accepted <= 1 + args.busy:
            recorder.write("BUSY")
            client.sendall(b"421 Too many connections from your IP\r\n")
            client.close()
            continue
        track(client)
        threading.Thread(target=serve_fake, args=(client, args, context, recorder), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("forward")
    p.add_argument("--target", required=True)
    p.add_argument("--hold")
    sub.add_parser("silent")
    p = sub.add_parser("fake")
    p.add_argument("--tls", choices=["explicit", "implicit", "none"], default="explicit")
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--log", required=True)
    p.add_argument("--busy", type=int, default=0)
    args = parser.parse_args()
    {"forward": forward, "silent": silent, "fake": fake}[args.mode](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
