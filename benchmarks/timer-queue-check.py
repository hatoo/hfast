#!/usr/bin/env python3
"""Recover a lost handshake among active, idle, and closing independent peers."""

import asyncio
from contextlib import AsyncExitStack
import importlib.util
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from interoperability import Client

spec = importlib.util.spec_from_file_location(
    "crypto_recovery", Path(__file__).with_name("crypto-recovery-check.py")
)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


async def traffic(client):
    for post in (False, True):
        for _ in range(4):
            await asyncio.gather(*(client.request(post) for _ in range(16)))
            await asyncio.sleep(0.005)


async def close_all(clients):
    # Close in parallel: the peers' QUIC draining intervals would otherwise
    # accumulate while AsyncExitStack exits the connection contexts in series.
    for client in clients:
        client.close()
    await asyncio.gather(*(client.wait_closed() for client in clients))


async def check(port, relay_port, relay):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with AsyncExitStack() as stack:
        clients = []
        for _ in range(32):
            clients.append(
                await stack.enter_async_context(
                    connect("127.0.0.1", port, configuration=conf, create_protocol=Client)
                )
            )
        stack.push_async_callback(close_all, clients)
        # Different connections can have no timer, an ACK deadline postponed by
        # traffic, or a PTO that must fire without another datagram from its peer.
        await asyncio.gather(
            recovery.check(relay_port, relay), *(traffic(c) for c in clients[:16])
        )
        await asyncio.sleep(0.05)
        for c in clients[:8]:
            c.close()
        await asyncio.gather(*(c.wait_closed() for c in clients[:8]))
        await asyncio.gather(*(traffic(c) for c in clients[8:]))
    print(
        "PASS: 32 background peers, 5120 exact background responses, "
        "128 recovered responses, and 8 peers closed before survivor traffic",
        flush=True,
    )


async def main(binary):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        loop = asyncio.get_running_loop()
        transport, relay = await loop.create_datagram_endpoint(
            lambda: recovery.Relay(("127.0.0.1", port)),
            local_addr=("127.0.0.1", 0),
        )
    server = None
    try:
        server = subprocess.Popen(
            [binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(0.2)
        assert server.poll() is None, "server exited during startup"
        relay_port = transport.get_extra_info("sockname")[1]
        await asyncio.wait_for(check(port, relay_port, relay), 20)
    finally:
        transport.close()
        if server is not None:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
