#!/usr/bin/env python3
"""Independent full TLS/HTTP checks: hfast does not deliver session tickets."""
import asyncio
import json
import socket
import ssl
import subprocess
import sys

from aioquic.asyncio import connect
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import pull_quic_header

from interoperability import Client


class ObservedClient(Client):
    handshakes = 0

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            assert event.alpn_protocol == "h3"
            assert not event.session_resumed
            assert not event.early_data_accepted
            self.handshakes += 1
        super().quic_event_received(event)


class Relay(asyncio.DatagramProtocol):
    def __init__(self, target, mode):
        self.target, self.mode = target, mode
        self.peer = None
        self.injected = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        if source != self.target:
            self.peer = source
            self.transport.sendto(data, self.target)
            return
        if self.injected == 0 and self.mode == "loss":
            self.injected += 1
            return
        if self.injected == 0 and self.mode == "reorder":
            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            if header.packet_length < len(data):
                self.injected += 1
                # Deliver the coalesced Handshake before Initial, then replay
                # both. The genuine TLS/QUIC peer handles epoch readiness.
                self.transport.sendto(data[header.packet_length:], self.peer)
                self.transport.sendto(data[:header.packet_length], self.peer)
                self.transport.sendto(data, self.peer)
                return
        self.transport.sendto(data, self.peer)


async def check(binary, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen(
        [binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    transport = None
    tickets = []
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None
        config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], initial_rtt=0.02)
        config.verify_mode = ssl.CERT_NONE
        completed = 0
        for _ in range(2):
            transport, relay = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Relay(("127.0.0.1", port), mode), local_addr=("127.0.0.1", 0),
            )
            async with connect(
                "127.0.0.1", transport.get_extra_info("sockname")[1],
                configuration=config, create_protocol=ObservedClient,
                session_ticket_handler=tickets.append,
            ) as client:
                await client.ping()
                assert client._quic._handshake_confirmed
                for post in (False, True):
                    await asyncio.gather(*(client.request(post) for _ in range(32)))
                    completed += 32
                await asyncio.sleep(0.1)
                await client.ping()
                assert client.handshakes == 1
                assert not client.pending
                assert not tickets, "unexpected usable resumption ticket"
                assert relay.injected == (mode != "normal")
            transport.close()
            transport = None
        assert completed == 128
        print(json.dumps(dict(mode=mode, handshakes=2, responses=completed, tickets=len(tickets))), flush=True)
    finally:
        if transport:
            transport.close()
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    for mode in ("normal", "loss", "reorder"):
        asyncio.run(asyncio.wait_for(check(sys.argv[1], mode), 15))
