#!/usr/bin/env python3
"""Validate and time delayed sparse ACKs with the independent aioquic peer.

Fill a complete-response window, inserting PINGs to create authenticated
ACK-only packet gaps. Acknowledge every outstanding response in one sparse ACK,
then require a new exact HTTP response as a processing fence. No response is
lost or excluded. Report whole-cycle throughput separately from ACK-to-response
latency: the Python peer can limit throughput, and the fence is not a GET rate.
"""

import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.rangeset import RangeSet

spec = importlib.util.spec_from_file_location(
    "ack_ledger", Path(__file__).with_name("ack-ledger-bench.py")
)
ledger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)


class Client(ledger.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sparse = None
        self.sparse_sent = 0
        self.received = set()
        self.tracked = False
        original_ack = self._quic._write_ack_frame

        def sparse_ack(builder, space, now):
            if self.sparse is None or space is not self._quic._spaces[tls.Epoch.ONE_RTT]:
                return original_ack(builder, space, now)
            saved = (space.ack_queue, space.largest_received_packet, space.largest_received_time)
            space.ack_queue = self.sparse
            space.largest_received_packet = self.sparse[-1].stop - 1
            space.largest_received_time = now
            try:
                QuicConnection._write_ack_frame(self._quic, builder, space, now)
            finally:
                space.ack_queue, space.largest_received_packet, space.largest_received_time = saved
            self.sparse = None
            self.sparse_sent += 1

        self._quic._write_ack_frame = sparse_ack

    def datagram_received(self, data, addr):
        super().datagram_received(data, addr)
        if not self.tracked:
            # The base peer has installed its exact response/duplicate checks.
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            original = crypto.decrypt_packet

            def observed(*args, **kwargs):
                result = original(*args, **kwargs)
                self.received.add(result[2])
                return result

            crypto.decrypt_packet = observed
            self.tracked = True

    async def cycle(self, window, ranges, pid):
        assert not self.outstanding
        self.controlled = True
        before = ledger.cpu(pid)
        completed_before = self.completed
        start = time.perf_counter()
        since_gap = 0
        while len(self.outstanding) < window:
            await self.request(bool(self.outstanding) and self.completed % 64 == 0)
            since_gap += 1
            if since_gap == window // ranges:
                await self.ping()  # An ACK-only server packet makes a real PN gap.
                since_gap = 0
        sparse = RangeSet()
        space = self._quic._spaces[tls.Epoch.ONE_RTT]
        for pn, _ in self.outstanding:
            assert pn in self.received and pn in space.ack_queue
            sparse.add(pn, pn + 1)
        assert ranges <= len(sparse) <= ranges + 2, len(sparse)
        assert sum(r.stop - r.start for r in sparse) == window
        range_count = len(sparse)
        # Sparse gaps contain no outstanding response. Thus the server must
        # complete the entire window without scheduling a single retry.
        self.sparse = sparse
        self.controlled = False
        space.ack_at = self._loop.time()
        fence_start = time.perf_counter()
        await self.request(False)
        fence_seconds = time.perf_counter() - fence_start
        elapsed = time.perf_counter() - start
        after = ledger.cpu(pid)
        assert self.sparse is None
        assert self._quic._remote_max_streams_bidi > window * 2
        self.outstanding.clear()
        space.ack_at = self._loop.time()
        await self.ping()
        assert self.lost == self.duplicates == 0
        assert not self.pending and not self.packet_for_stream
        completed = self.completed - completed_before
        return dict(completed=completed, seconds=elapsed, ack_response_seconds=fence_seconds,
                    requests_per_second=completed / elapsed, ack_ranges=range_count,
                    server_cpu_ns_per_request=sum(after[i] - before[i] for i in range(2))
                    * 1e9 / completed)


async def measure(port, pid, args):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                             max_data=1 << 30, max_stream_data=1 << 20)
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf, create_protocol=Client) as client:
        await client.ping()
        await asyncio.sleep(0.02)
        assert client._quic._remote_max_streams_bidi == args.window * 2
        warmup = await client.cycle(args.window, args.ranges, pid)
        rows = [await client.cycle(args.window, args.ranges, pid) for _ in range(args.cycles)]
        # A credit update can lag by less than half a window, but must never
        # exceed one increment per completed response.
        limit = client._quic._remote_max_streams_bidi
        assert args.window * 2 + client.completed - args.window <= limit
        assert limit <= args.window * 2 + client.completed
        # The bulk ACK advertises all completions before the fence response;
        # the final fence ACK alone is below the half-window refresh threshold.
        assert limit == args.window * 2 + client.completed - 1, limit
        assert client.sparse_sent == args.cycles + 1
        return dict(window=args.window, ranges=args.ranges, cycles=rows, warmup=warmup,
                    completed=client.completed, errors=0, lost_packets=client.lost,
                    duplicate_responses=client.duplicates, advertised_stream_limit=limit)


async def main(args):
    assert args.window >= 64 and 1 <= args.ranges <= 256 and args.cycles >= 1
    assert args.window % args.ranges == 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen([args.binary, "--threads", "1", "--tcp", "0",
                               "--quic", str(port), "--max-streams", str(args.window * 2)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        await asyncio.sleep(0.25)
        assert server.poll() is None
        result = await measure(port, server.pid, args)
        assert server.poll() is None
        print(json.dumps(result), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--window", type=int, default=65536)
    parser.add_argument("--ranges", type=int, default=256)
    parser.add_argument("--cycles", type=int, default=3)
    asyncio.run(main(parser.parse_args()))
