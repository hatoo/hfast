#!/usr/bin/env python3
"""ACK only the original full response after PTO copies, using aioquic 1.3.0.

Authenticate every response but withhold it from the independent client's
packet/ACK accounting. After one or three retries, deliver the original wire
packet and keep rejecting retries. A one-stream server must grant stream credit
from that original ACK, allowing subsequent exact HTTP responses to complete.
This is a correctness fixture, never a throughput measurement.
"""

import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoError
from aioquic.quic.logger import QuicLogger

from interoperability import Client

# Share the independent parser for authenticated STREAM frames with the credit
# fixture. No hfast implementation is used to interpret the response.
spec = importlib.util.spec_from_file_location(
    "response_credit", Path(__file__).with_name("response-credit-check.py")
)
credit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credit)


class LateAckClient(Client):
    def __init__(self, *args, copies, **kwargs):
        super().__init__(*args, **kwargs)
        self.copies = copies
        self.packets = []
        self.original = None
        self.held = None
        self.released = asyncio.Event()
        self.replaying = False
        self.injected = False
        self.failure = None

    def datagram_received(self, data, addr):
        self.current = (data, addr)
        if not self.injected:
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def filtered(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                parts, _ = credit.stream_frames(plain)
                target = [p for p in parts if p[0] == 0]
                if not target:
                    return result
                if target != [(0, 0, credit.RESPONSE, True)]:
                    self.failure = f"incorrect response: {target!r}"
                if self.replaying:
                    assert pn == self.original
                    return result
                self.packets.append(pn)
                if self.original is None:
                    self.original = pn
                    self.held = self.current
                if len(self.packets) == self.copies + 1:
                    self._loop.call_soon(self.release_original)
                raise CryptoError("withhold response from packet and ACK accounting")

            crypto.decrypt_packet = filtered
            self.injected = True
        super().datagram_received(data, addr)

    def release_original(self):
        self.replaying = True
        try:
            super().datagram_received(*self.held)
        finally:
            self.replaying = False
        # Send the ACK promptly. Retransmitted packet numbers never entered
        # ack_queue, so this cannot accidentally acknowledge a newer copy.
        space = self._quic._spaces[tls.Epoch.ONE_RTT]
        assert self.original in space.ack_queue
        assert all(pn not in space.ack_queue for pn in self.packets[1:])
        space.ack_at = self._loop.time()
        self.transmit()
        self.released.set()


async def check(port, copies, observe, logger):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf,
        create_protocol=lambda *a, **kw: LateAckClient(*a, copies=copies, **kw),
    ) as client:
        # Let control ACKs settle before holding the first response.
        await client.ping()
        await asyncio.sleep(0.05)
        assert client._quic._remote_max_streams_bidi == 1
        task = asyncio.create_task(client.request())
        await asyncio.wait_for(client.released.wait(), 10)
        await task
        # Later authenticated packets exercise packet-threshold recovery
        # without depending on a long, exponentially backed-off PTO. ACK only
        # packets the independent peer actually received, including PING ACKs.
        for _ in range(6):
            await client.ping()
            space = client._quic._spaces[tls.Epoch.ONE_RTT]
            space.ack_at = client._loop.time()
            client.transmit()
            await asyncio.sleep(0.01)
        for _ in range(150):
            if client._quic._remote_max_streams_bidi >= 2:
                break
            await asyncio.sleep(0.01)
        granted = client._quic._remote_max_streams_bidi >= 2
        # Observe beyond several local PTOs to expose redundant STREAM work.
        await asyncio.sleep(0.3)
        assert client.failure is None, client.failure
        space = client._quic._spaces[tls.Epoch.ONE_RTT]
        assert all(pn not in space.ack_queue for pn in client.packets[1:])
        row = dict(copies=copies, original=client.original, response_packets=client.packets,
                   extra_after_original_ack=len(client.packets) - copies - 1,
                   stream_credit=client._quic._remote_max_streams_bidi, granted=granted)
        print(json.dumps(row), flush=True)
        if not observe:
            assert granted, "original ACK did not release the response's stream credit"
            assert row["extra_after_original_ack"] == 0, row
            for post in (False, True):
                for _ in range(8):
                    await client.request(post)
            assert not client.pending
        return row


async def main(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen(
        [args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port), "--max-streams", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    logger = QuicLogger()
    rows = []
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None
        for copies in (1, 3):
            rows.append(await asyncio.wait_for(check(port, copies, args.observe, logger), 20))
        assert server.poll() is None
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.qlog:
            with open(args.qlog, "x") as out:
                json.dump(logger.to_dict(), out)
    if args.json:
        with open(args.json, "x") as out:
            json.dump(rows, out, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--observe", action="store_true", help="record a known-broken baseline")
    parser.add_argument("--json")
    parser.add_argument("--qlog")
    asyncio.run(main(parser.parse_args()))
