#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""TCP proxy that can stall, for the C-9 cancel tests (SPEC-v2 XT-1).

Usage: httpstall.py <target host> <target port>

Listens on two ephemeral ports on 127.0.0.1 and prints
"PORTS <proxy port> <control port>" on stdout. Connections to the proxy port
are relayed to the target. The control port takes one command per line and
answers "ok":
  stall   stop relaying in both directions (bytes are held, nothing is lost)
  flow    relay again
  drop    close every relayed connection
"""
import asyncio
import sys

CHUNK = 65536
TICK = 0.05


class Proxy:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.stalled = False
        self.writers = set()

    async def pump(self, reader, writer):
        try:
            while True:
                while self.stalled:
                    await asyncio.sleep(TICK)
                data = await reader.read(CHUNK)
                if not data:
                    break
                while self.stalled:
                    await asyncio.sleep(TICK)
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def relay(self, client_reader, client_writer):
        try:
            server_reader, server_writer = await asyncio.open_connection(self.host, self.port)
        except OSError:
            client_writer.close()
            return
        self.writers.update((client_writer, server_writer))
        await asyncio.gather(self.pump(client_reader, server_writer), self.pump(server_reader, client_writer))
        self.writers.difference_update((client_writer, server_writer))

    async def control(self, reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            command = line.decode().strip()
            if command == "stall":
                self.stalled = True
            elif command == "flow":
                self.stalled = False
            elif command == "drop":
                for relayed in list(self.writers):
                    relayed.close()
                self.writers.clear()
            writer.write(b"ok\n")
            await writer.drain()
        writer.close()


async def main():
    proxy = Proxy(sys.argv[1], int(sys.argv[2]))
    relay = await asyncio.start_server(proxy.relay, "127.0.0.1", 0)
    control = await asyncio.start_server(proxy.control, "127.0.0.1", 0)
    print("PORTS %d %d" % (relay.sockets[0].getsockname()[1], control.sockets[0].getsockname()[1]), flush=True)
    async with relay, control:
        await asyncio.gather(relay.serve_forever(), control.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
