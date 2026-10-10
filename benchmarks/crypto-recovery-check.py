#!/usr/bin/env python3
"""Independent regression: ACK a later Initial while the first flight is lost."""

import asyncio
import socket
import ssl
import subprocess
import sys

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from interoperability import Client


class RecoveryClient(Client):
    forced_ack = None

    def datagram_received(self, data, addr):
        super().datagram_received(data, addr)
        space = self._quic._spaces[tls.Epoch.INITIAL]
        # The relay loses the first flight. The client's PTO elicits a later
        # ACK-only Initial. Explicitly acknowledge it while pn0 is still lost.
        # aioquic otherwise waits for an ack-eliciting packet before ACKing it.
        # These internals are pinned by interop-requirements.txt (aioquic 1.3).
        if (
            self.forced_ack is None
            and not space.discarded
            and len(space.ack_queue) > 0
            and space.ack_queue[0].start > 0
        ):
            self.forced_ack = [(r.start, r.stop - 1) for r in space.ack_queue]
            print("Injected Initial ACK ranges:", self.forced_ack, flush=True)
            space.ack_at = self._loop.time()
            self.transmit()


class Relay(asyncio.DatagramProtocol):
    def __init__(self, target):
        self.target = target
        self.peer = None
        self.dropped = 0
        self.largest_datagram = 0
        self.oversized = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        if source == self.target:
            self.largest_datagram = max(self.largest_datagram, len(data))
            if len(data) > 1200:
                self.oversized.append(len(data))
            if self.dropped == 0:
                # Initial headers are visible before header protection.
                assert data[0] & 0xF0 == 0xC0, "expected server Initial flight"
                self.dropped += 1
                return
            destination = self.peer
        else:
            self.peer = source
            destination = self.target
        if destination is not None:
            self.transport.sendto(data, destination)


async def check(port, relay, cid_length):
    conf = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        initial_rtt=0.02,
        connection_id_length=cid_length,
    )
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf, create_protocol=RecoveryClient
    ) as client:
        assert relay.dropped == 1
        assert client.forced_ack is not None, "sparse ACK was not exercised"
        for post in (False, True):
            await asyncio.gather(*(client.request(post) for _ in range(64)))
        assert not relay.oversized, relay.oversized
        print(
            f"PASS: peer CID length {cid_length}; lost first server flight; ACK ranges",
            client.forced_ack,
            "exclude pn0; handshake and 64 GET + 64 POST recovered;",
            f"largest server datagram {relay.largest_datagram} <= 1200",
            flush=True,
        )


async def main(binary, cid_length):
    # Ephemeral loopback ports avoid collisions with other benchmark servers.
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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(0.2)
        assert server.poll() is None, "server exited during startup"
        port = transport.get_extra_info("sockname")[1]
        await asyncio.wait_for(check(port, relay, cid_length), 8)
    finally:
        transport.close()
        if server is not None:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    for cid_length in (0, 8, 20):
        asyncio.run(main(sys.argv[1], cid_length))
