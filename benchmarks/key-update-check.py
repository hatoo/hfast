#!/usr/bin/env python3
"""Independent QUIC key updates with loss, old-packet reordering and forgery.

The crypto hook only records authenticated headers. aioquic 1.3.0 is pinned in
interop-requirements.txt; its key schedule and packet protection are unchanged.
"""

import asyncio
import socket
import ssl
import subprocess
import sys

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from interoperability import Client


class Relay(asyncio.DatagramProtocol):
    def __init__(self, target):
        self.target = target
        self.peer = None
        self.drop_client = False
        self.drop_server = False
        self.hold_next = False
        self.held = None
        self.held_ready = asyncio.Event()
        self.forge_next = False
        self.dropped = [0, 0]
        self.reordered = 0
        self.duplicated = 0
        self.forged = 0
        self.largest_server_datagram = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        server = source == self.target
        if server:
            destination = self.peer
            self.largest_server_datagram = max(self.largest_server_datagram, len(data))
            if self.drop_server and data[0] & 0x80 == 0:
                self.drop_server = False
                self.dropped[1] += 1
                return
        else:
            self.peer = source
            destination = self.target
            if self.hold_next:
                self.hold_next = False
                self.held = data
                self.held_ready.set()
                return
            if self.drop_client:
                self.drop_client = False
                self.dropped[0] += 1
                return
            if self.forge_next:
                self.forge_next = False
                # Header protection is unchanged by either corruption. One
                # changes the authenticated phase, the other the AEAD tag.
                self.transport.sendto(bytes([data[0] ^ 4]) + data[1:], destination)
                self.transport.sendto(data[:-1] + bytes([data[-1] ^ 1]), destination)
                self.forged += 2
        self.transport.sendto(data, destination)
        if not server and self.held is not None:
            # A genuine old-generation request arrives after the new packet,
            # twice. Its response must still finish exactly once.
            self.transport.sendto(self.held, destination)
            self.transport.sendto(self.held, destination)
            self.held = None
            self.reordered += 1
            self.duplicated += 1


async def check(port, relay, cid_length, cipher, mode):
    config = QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], initial_rtt=0.02,
        connection_id_length=cid_length, cipher_suites=[cipher],
    )
    config.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=Client
    ) as client:
        await client.ping()
        assert client._quic._handshake_confirmed
        crypto = client._quic._cryptos[tls.Epoch.ONE_RTT]
        decrypt = crypto.decrypt_packet
        received = []

        def observed(*args, **kwargs):
            header, body, pn = decrypt(*args, **kwargs)
            received.append(((header[0] & 4) >> 2, pn))
            return header, body, pn

        crypto.decrypt_packet = observed
        replies = 0
        for generation in range(1, 7):
            old_request = None
            if mode == "reorder-forge":
                relay.held_ready.clear()
                relay.hold_next = True
                old_request = asyncio.create_task(client.request(generation % 2 == 0))
                await relay.held_ready.wait()
                relay.forge_next = True
            if mode == "loss":
                relay.drop_client = True
                relay.drop_server = True
            start = len(received)
            client.request_key_update()
            # Ping completion confirms the new phase ACK before the next update.
            await client.ping()
            assert any(phase == generation % 2 for phase, _ in received[start:]), received[start:]
            if old_request is not None:
                await old_request
                replies += 1
            await asyncio.gather(*(client.request(i % 2 == 1) for i in range(32)))
            replies += 32
        assert not client.pending
        assert relay.largest_server_datagram <= 1200
        if mode == "loss":
            assert relay.dropped == [6, 6], relay.dropped
        if mode == "reorder-forge":
            assert (relay.reordered, relay.duplicated, relay.forged) == (6, 6, 12)
        print(
            f"PASS: {cipher.name} CID{cid_length} {mode}: 6 confirmed key updates, "
            f"{replies} exact HTTP/3 replies; dropped={relay.dropped}, "
            f"reordered={relay.reordered}, duplicates={relay.duplicated}, "
            f"forgeries={relay.forged}, max_datagram={relay.largest_server_datagram}",
            flush=True,
        )


async def main(binary, cid_length, cipher, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        server_port = reservation.getsockname()[1]
        loop = asyncio.get_running_loop()
        transport, relay = await loop.create_datagram_endpoint(
            lambda: Relay(("127.0.0.1", server_port)), local_addr=("127.0.0.1", 0)
        )
    server = None
    try:
        server = subprocess.Popen(
            [binary, "--threads", "1", "--tcp", "0", "--quic", str(server_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(0.2)
        assert server.poll() is None
        await asyncio.wait_for(
            check(transport.get_extra_info("sockname")[1], relay, cid_length, cipher, mode), 15
        )
    finally:
        transport.close()
        if server is not None:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    for cipher in (
        tls.CipherSuite.AES_128_GCM_SHA256,
        tls.CipherSuite.AES_256_GCM_SHA384,
        tls.CipherSuite.CHACHA20_POLY1305_SHA256,
    ):
        for cid_length in (0, 8, 20):
            for mode in ("clean", "loss", "reorder-forge"):
                asyncio.run(main(sys.argv[1], cid_length, cipher, mode))
