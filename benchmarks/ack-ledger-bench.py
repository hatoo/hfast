#!/usr/bin/env python3
"""Controlled complete-response ACK window with pinned aioquic.

Receive and validate a full window, then acknowledge its oldest packet with
each new request. Small progress ACKs during filling keep recovery active.
Only packets authenticated by aioquic are acknowledged. Fail on retransmitted
responses or peer loss: either would confound the complete-response ledger.
Report client-observed throughput and server CPU separately; Python may limit
throughput. This deliberately delayed-ACK workload is not an ordinary GET rate.
"""

import argparse
import asyncio
from collections import deque
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

from aioquic import tls
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.rangeset import RangeSet

spec = importlib.util.spec_from_file_location(
    "response_credit", Path(__file__).with_name("response-credit-check.py")
)
credit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credit)
HEADERS = [(b":method", b"GET"), (b":scheme", b"https"),
           (b":authority", b"localhost"), (b":path", b"/")]


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}
        self.packet_for_stream = {}
        self.outstanding = deque()
        self.completed = 0
        self.ack_frames = 0
        self.lost = 0
        self.duplicates = 0
        self.seen = set()
        self.controlled = False
        self.injected = False
        self.ack_limit = -1
        self.ack_sent = -1
        self.ack_time = 0
        self.failure = None
        original_ack = self._quic._write_ack_frame
        original_lost = self._quic._loss._on_packets_lost

        def capped_ack(builder, space, now):
            if not self.controlled or space is not self._quic._spaces[tls.Epoch.ONE_RTT]:
                return original_ack(builder, space, now)
            saved = (space.ack_queue, space.largest_received_packet, space.largest_received_time)
            capped = RangeSet(range(r.start, min(r.stop, self.ack_limit + 1))
                              for r in space.ack_queue if r.start <= self.ack_limit)
            assert len(capped) and self.ack_limit in capped
            space.ack_queue = capped
            space.largest_received_packet = self.ack_limit
            space.largest_received_time = self.ack_time
            try:
                original_ack(builder, space, now)
            finally:
                space.ack_queue, space.largest_received_packet, space.largest_received_time = saved
            self.ack_sent = self.ack_limit
            self.ack_frames += 1

        def counted_lost(*, now, packets, space):
            packets = list(packets)
            self.lost += len(packets)
            original_lost(now=now, packets=packets, space=space)

        self._quic._write_ack_frame = capped_ack
        self._quic._loss._on_packets_lost = counted_lost

    def datagram_received(self, data, addr):
        if not self.injected:
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def observed(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                parts, resets = credit.stream_frames(plain)
                assert not resets
                for stream, offset, body, fin in parts:
                    if stream & 3:
                        continue
                    if (offset, body, fin) != (0, credit.RESPONSE, True):
                        self.failure = "incomplete or incorrect response on wire"
                    if stream in self.seen:
                        self.duplicates += 1
                    self.seen.add(stream)
                    self.packet_for_stream[stream] = (pn, self._loop.time())
                return result

            crypto.decrypt_packet = observed
            self.injected = True
        super().datagram_received(data, addr)

    def transmit(self):
        if self.controlled:
            space = self._quic._spaces[tls.Epoch.ONE_RTT]
            space.ack_at = self._loop.time() if self.ack_limit > self.ack_sent else None
        super().transmit()

    def quic_event_received(self, event):
        for ev in self.http.handle_event(event):
            if isinstance(ev, (HeadersReceived, DataReceived)):
                future, headers, body = self.pending[ev.stream_id]
                if isinstance(ev, HeadersReceived):
                    headers.extend(ev.headers)
                else:
                    body.extend(ev.data)
                if ev.stream_ended:
                    assert (b":status", b"200") in headers, headers
                    assert body == b"Hello, World!", body
                    self.completed += 1
                    future.set_result(self.packet_for_stream.pop(ev.stream_id))

    async def request(self, acknowledge_oldest):
        if acknowledge_oldest:
            self.ack_limit, self.ack_time = self.outstanding.popleft()
        stream = self._quic.get_next_available_stream_id()
        future = self._loop.create_future()
        self.pending[stream] = (future, [], bytearray())
        self.http.send_headers(stream, HEADERS, end_stream=True)
        self.transmit()
        response = await asyncio.wait_for(future, 5)
        del self.pending[stream]
        if self.outstanding:
            assert response[0] > self.outstanding[-1][0], "response packet order changed"
        self.outstanding.append(response)
        assert self.failure is None, self.failure
        assert self.lost == self.duplicates == 0, (self.lost, self.duplicates)


def cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split(") ")[1].split()
    tick = os.sysconf("SC_CLK_TCK")
    return [int(fields[11]) / tick, int(fields[12]) / tick]


async def measure(port, pid, args):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                             max_data=1 << 30, max_stream_data=1 << 20)
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf, create_protocol=Client) as client:
        await client.ping()
        await asyncio.sleep(0.02)
        assert client._quic._remote_max_streams_bidi == args.window * 2
        client.controlled = True
        while len(client.outstanding) < args.window:
            await client.request(client.completed > 0 and client.completed % 64 == 0)
        for _ in range(args.warmup):
            await client.request(True)
        assert len(client.outstanding) == args.window
        before = cpu(pid)
        ack_before = client.ack_frames
        completed_before = client.completed
        start = time.perf_counter()
        for _ in range(args.requests):
            await client.request(True)
        elapsed = time.perf_counter() - start
        after = cpu(pid)
        assert client.completed - completed_before == args.requests
        assert len(client.outstanding) == args.window
        assert client.ack_frames - ack_before == args.requests
        # Deliver every remaining ACK and verify stream credit from the whole
        # window, outside the timing interval. No response or FIN is discarded.
        client.controlled = False
        client._quic._spaces[tls.Epoch.ONE_RTT].ack_at = client._loop.time()
        await client.ping()
        for _ in range(100):
            if client._quic._remote_max_streams_bidi > args.window * 2:
                break
            await asyncio.sleep(0.01)
        limit = client._quic._remote_max_streams_bidi
        assert limit > args.window * 2, limit
        assert not client.pending and not client.packet_for_stream
        assert client.lost == client.duplicates == 0
        used = [after[i] - before[i] for i in range(2)]
        return dict(window=args.window, requests=args.requests, warmup=args.warmup,
                    completed=client.completed, errors=0, seconds=elapsed,
                    requests_per_second=args.requests / elapsed,
                    server_user_seconds=used[0], server_system_seconds=used[1],
                    server_cpu_ns_per_request=sum(used) * 1e9 / args.requests,
                    application_ack_frames=client.ack_frames - ack_before,
                    lost_packets=client.lost, duplicate_responses=client.duplicates,
                    advertised_stream_limit=limit)


async def main(args):
    assert args.window >= 64 and args.requests > 0 and args.warmup >= 0
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
    parser.add_argument("--requests", type=int, default=16384)
    parser.add_argument("--warmup", type=int, default=1024)
    asyncio.run(main(parser.parse_args()))
