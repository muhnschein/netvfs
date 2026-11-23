#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import socket
import sys
import threading



def container_address():
    return socket.gethostbyname(socket.gethostname())

def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def client_to_server(client, server):
    try:
        while True:
            data = client.recv(65536)
            if not data:
                break
            server.sendall(data)
    except OSError:
        pass
    for s in (client, server):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def server_to_client(server, client, mode, frame):
    count = 0
    try:
        while True:
            header = recv_exact(server, 4)
            if header is None:
                break
            payload = recv_exact(server, int.from_bytes(header[1:4], "big"))
            if payload is None:
                break
            count += 1
            if mode == "stall" and count >= frame:
                continue
            if mode == "drop" and count == frame:
                break
            if mode == "dialect" and count == frame and len(payload) >= 70:
                payload = payload[:68] + b"\x10\x02" + payload[70:]
            if mode == "flip" and count == frame and payload:
                payload = payload[:-1] + bytes([payload[-1] ^ 0x01])
                print("flipped a byte in frame %d" % count, flush=True)
            client.sendall(header + payload)
    except OSError:
        pass
    for s in (client, server):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def serve(port, target, mode, frame):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((container_address(), port))
    listener.listen(16)
    while True:
        client, _ = listener.accept()
        server = socket.create_connection((target, 445))
        threading.Thread(target=client_to_server, args=(client, server), daemon=True).start()
        threading.Thread(target=server_to_client, args=(server, client, mode, frame), daemon=True).start()


def main():
    threads = []
    for spec in sys.argv[1:]:
        port, mode, frame, target = spec.split(":")
        t = threading.Thread(target=serve, args=(int(port), target, mode, int(frame)), daemon=True)
        t.start()
        threads.append(t)
    print("proxies ready", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
