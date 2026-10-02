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
       [--alt-cert FILE --alt-key FILE] [--behavior [N:]KEY[=VALUE]]... [--trace]
      A minimal FTP server that records everything the client sends: the
      clear text before TLS and the decrypted text after it, one line per
      command, plus TLS-START / TLS-OK / TLS-FAIL markers. USER gets 331,
      PASS 530 (unless login=ok). The identity tests (XT-5) read the log to
      prove that no USER command was sent before the identity was accepted.
      --behavior makes the server misbehave per connection (a refused or
      botched AUTH TLS, an unsolicited 230, refused PBSZ/PROT, a dropped
      control connection; see class Behavior) and --trace adds the clear text
      bytes it received, so that the XSEC-1/XSEC-2 tests can prove that no USER,
      PASS or file data ever arrived unprotected (see class Session).
"""
import argparse
import codecs
import hashlib
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

REPLIES = {
    "USER": b"331 Password required\r\n",
    "PASS": b"530 Login incorrect\r\n",
    "PBSZ": b"200 PBSZ=0\r\n",
    "PROT": b"200 Protection set\r\n",
    "QUIT": b"221 Bye\r\n",
}

GARBAGE = b"HTTP/1.1 400 Bad Request\r\nThis is not a TLS server\r\n\r\n"
FEAT_REPLY = b"211-Features:\r\n UTF8\r\n REST STREAM\r\n SIZE\r\n MDTM\r\n211 End\r\n"
EXISTING_FILE = "/hello.txt"
EXISTING_DATA = b"hello from the fake FTP server\n"
SOCKET_TIMEOUT = 5.0
DRAIN_TIMEOUT = 1.0


class Behavior:
    """Per-connection server behaviour from --behavior [N:]key[=value].

    Without N a setting applies to every connection; with N (1 is the first
    connection the server accepted) to that connection only, overriding the
    general one. Keys:
      greeting=CODE   the first reply instead of 220
      extra=CODE      an unsolicited reply sent right behind the greeting
      auth=CODE       the reply to AUTH TLS instead of 234
      auth-after=close|garbage|stall
                      after a 234: close the socket, send non-TLS bytes or
                      send nothing, instead of a TLS handshake
      pbsz=CODE, prot=CODE
                      the replies to PBSZ and PROT
      login=ok        PASS is answered 230 and the common post-login commands
                      (FEAT, PWD, TYPE, EPSV, SIZE, STOR, RETR, LIST ...) work
      auth-raw=TEXT   the reply to AUTH TLS as raw bytes (Python escapes such as
                      \\r\\n), nothing else follows; the client may carry on in clear
      data=clear      after an accepted PROT P the data connection answers with
                      non-TLS bytes (a server that claims protection it does
                      not give)
      cert=alt        present --alt-cert instead of --cert
      drop-after=VERB close the control connection after answering VERB
    """

    def __init__(self, specs):
        self.general = {}
        self.specific = {}
        for spec in specs or []:
            head, _, value = spec.partition("=")
            index, _, key = head.rpartition(":")
            target = self.specific.setdefault(int(index), {}) if index else self.general
            target[key] = value

    def get(self, index, key, default=None):
        return self.specific.get(index, {}).get(key, self.general.get(key, default))


class Recorder:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, text):
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as log:
                log.write(text + "\n")


def read_line(conn):
    """Returns (the line without CRLF, the raw bytes read); line is None at EOF."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            return None, data
        data += chunk
    return data.rstrip(b"\r\n").decode("latin-1"), data


def start_tls(conn, context, recorder):
    recorder.write("TLS-START")
    try:
        tls = context.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as error:
        recorder.write("TLS-FAIL " + type(error).__name__)
        return None
    recorder.write("TLS-OK")
    return tls


def reply(code, text):
    return ("%s %s\r\n" % (code, text)).encode()


def fixed(data):
    def handler(session, _argument):
        session.send(data)
        return True
    return handler


class Session:
    """One accepted control connection of the recording fake server.

    With --trace the log also gets "CONN n" (one per accepted control
    connection) and "CLEAR <c|d><n> <hex>" lines: every byte the server
    received on the control (c) or a data (d) connection of connection n
    while that socket was NOT wrapped in TLS. Tests use them to prove that
    no USER, PASS or file data ever reached the server in clear text.
    "UPLOAD <len> <sha256>" records a file received over a protected data
    connection and "END n" the end of connection n.
    """

    def __init__(self, conn, index, server):
        self.conn = conn
        self.index = index
        self.server = server
        self.recorder = server.recorder
        self.args = server.args
        self.protected = False       # PROT P accepted
        self.passive = None          # listening socket for the next transfer
        self.logged_in = False

    def get(self, key, default=None):
        return self.server.behavior.get(self.index, key, default)

    def clear(self, kind, data):
        if self.args.trace and data:
            self.recorder.write("CLEAR %s%d %s" % (kind, self.index, data.hex()))

    def send(self, data):
        self.conn.sendall(data)

    def is_tls(self):
        return isinstance(self.conn, ssl.SSLSocket)

    def context(self):
        return self.server.alt_context if self.get("cert") == "alt" else self.server.context

    def read_command(self):
        line, raw = read_line(self.conn)
        if not self.is_tls():
            self.clear("c", raw)
        return line

    def drain(self):
        """Records whatever the client still sends (a handshake that never comes)."""
        self.conn.settimeout(DRAIN_TIMEOUT)
        try:
            while True:
                data = self.conn.recv(4096)
                if not data:
                    break
                self.clear("c", data)
        except OSError:
            pass
        self.conn.settimeout(None)

    def serve(self):
        if self.args.trace:
            self.recorder.write("CONN %d" % self.index)
        try:
            self.converse()
        finally:
            if self.args.trace:
                self.recorder.write("END %d" % self.index)

    def converse(self):
        if self.args.tls == "implicit":
            self.conn = start_tls(self.conn, self.context(), self.recorder)
            if self.conn is None:
                return
        greeting = reply(self.get("greeting", "220"), "netvfs fake FTP server")
        extra = self.get("extra")
        if extra:
            greeting += reply(extra, "unsolicited")
        self.send(greeting)
        while self.step():
            pass

    def step(self):
        line = self.read_command()
        if line is None:
            self.recorder.write("CLOSED")
            return False
        self.recorder.write("C: " + line)
        verb, _, argument = line.partition(" ")
        verb = verb.upper()
        keep = self.dispatch(verb, argument)
        if keep and self.get("drop-after", "").upper() == verb:
            self.recorder.write("DROPPED")
            self.conn.close()
            return False
        return keep

    def dispatch(self, verb, argument):
        if verb == "AUTH" and self.args.tls == "explicit" and not self.is_tls():
            return self.auth()
        if verb == "PASS" and self.get("login") == "ok":
            self.logged_in = True
            self.send(reply(230, "Logged in"))
            return True
        if verb in ("PBSZ", "PROT"):
            return self.protection(verb, argument)
        handler = COMMANDS.get(verb) if self.logged_in else None
        if handler:
            return handler(self, argument)
        self.send(REPLIES.get(verb, b"502 Not implemented\r\n"))
        return verb != "QUIT"

    def auth(self):
        raw = self.get("auth-raw")
        if raw:
            self.send(codecs.decode(raw, "unicode_escape").encode("latin-1"))
            return True
        code = self.get("auth", "234")
        if code != "234":
            self.send(reply(code, "AUTH TLS refused"))
            return True
        self.send(reply(234, "Proceed with negotiation"))
        after = self.get("auth-after")
        if after is None:
            self.conn = start_tls(self.conn, self.context(), self.recorder)
            return self.conn is not None
        if after == "garbage":
            self.send(GARBAGE)
        if after in ("garbage", "stall"):
            self.drain()
        self.conn.close()
        self.recorder.write("ENDED-AFTER-234")
        return False

    def protection(self, verb, argument):
        code = self.get(verb.lower(), "200")
        self.send(reply(code, verb))
        if verb == "PROT" and code.startswith("2"):
            self.protected = argument.strip().upper() == "P"
        return True

    # Commands that only work after a login (login=ok).

    def size(self, argument):
        if argument == EXISTING_FILE:
            self.send(reply(213, len(EXISTING_DATA)))
        else:
            self.send(reply(550, "No such file"))
        return True

    def cwd(self, argument):
        if argument in ("/", ""):
            self.send(reply(250, "OK"))
        else:
            self.send(reply(550, "No such file or directory"))
        return True

    def listen_passive(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(SOCKET_TIMEOUT)
        self.passive = listener
        return listener.getsockname()[1]

    def epsv(self, _argument):
        self.send(reply(229, "Entering Extended Passive Mode (|||%d|)" % self.listen_passive()))
        return True

    def pasv(self, _argument):
        port = self.listen_passive()
        self.send(reply(227, "Entering Passive Mode (127,0,0,1,%d,%d)" % (port >> 8, port & 255)))
        return True

    def data_connection(self):
        listener, self.passive = self.passive, None
        if listener is None:
            self.send(reply(425, "Use PASV first"))
            return None
        self.send(reply(150, "Opening data connection"))
        try:
            data, _ = listener.accept()
        except OSError:
            self.send(reply(425, "No data connection"))
            return None
        finally:
            listener.close()
        data.settimeout(SOCKET_TIMEOUT)
        if self.protected and self.get("data") == "clear":
            data.sendall(GARBAGE)   # claims protection, then does not speak TLS
        elif self.protected:
            data = self.context().wrap_socket(data, server_side=True)
        return data

    def receive_data(self):
        data = self.data_connection()
        if data is None:
            return None
        received = b""
        while True:
            chunk = data.recv(65536)
            if not chunk:
                break
            received += chunk
        if isinstance(data, ssl.SSLSocket):
            self.recorder.write("UPLOAD %d %s" % (len(received), hashlib.sha256(received).hexdigest()))
        else:
            self.clear("d", received)
        data.close()
        return received

    def send_data(self, payload):
        data = self.data_connection()
        if data is None:
            return
        data.sendall(payload)
        data.close()

    def transfer(self, action):
        try:
            action()
        except (ssl.SSLError, OSError) as error:
            self.recorder.write("DATA-FAIL " + type(error).__name__)
            self.send(reply(426, "Data connection failed"))
            return True
        self.send(reply(226, "Transfer complete"))
        return True

    def stor(self, _argument):
        return self.transfer(self.receive_data)

    def retr(self, argument):
        if argument != EXISTING_FILE:
            self.send(reply(550, "No such file"))
            return True
        return self.transfer(lambda: self.send_data(EXISTING_DATA))

    def listing(self, _argument):
        line = b"-rw-r--r-- 1 ftp ftp %d Jan  1 12:00 hello.txt\r\n" % len(EXISTING_DATA)
        return self.transfer(lambda: self.send_data(line))


COMMANDS = {
    "FEAT": fixed(FEAT_REPLY),
    "PWD": fixed(b'257 "/" is the current directory\r\n'),
    "TYPE": fixed(b"200 Type set\r\n"),
    "OPTS": fixed(b"200 OK\r\n"),
    "NOOP": fixed(b"200 NOOP ok\r\n"),
    "SYST": fixed(b"215 UNIX Type: L8\r\n"),
    "MDTM": fixed(b"550 No such file\r\n"),
    "SIZE": Session.size,
    "CWD": Session.cwd,
    "EPSV": Session.epsv,
    "PASV": Session.pasv,
    "STOR": Session.stor,
    "RETR": Session.retr,
    "LIST": Session.listing,
    "QUIT": lambda session, _argument: session.send(reply(221, "Bye")) or False,
}


class FakeServer:
    def __init__(self, args):
        self.args = args
        self.behavior = Behavior(args.behavior)
        self.recorder = Recorder(args.log)
        self.context = self.make_context(args.cert, args.key)
        self.alt_context = self.make_context(args.alt_cert, args.alt_key)
        self.count = 0

    @staticmethod
    def make_context(cert, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if cert:
            context.load_cert_chain(cert, key)
        return context

    def run(self):
        server = listen()
        while True:
            client, _ = server.accept()
            track(client)
            self.count += 1
            session = Session(client, self.count, self)
            threading.Thread(target=session.serve, daemon=True).start()


def fake(args):
    FakeServer(args).run()


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
    p.add_argument("--alt-cert")
    p.add_argument("--alt-key")
    p.add_argument("--behavior", action="append", metavar="[N:]KEY[=VALUE]")
    p.add_argument("--trace", action="store_true")
    p.add_argument("--log", required=True)
    args = parser.parse_args()
    {"forward": forward, "silent": silent, "fake": fake}[args.mode](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
