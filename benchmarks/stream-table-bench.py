#!/usr/bin/env python3
"""Controlled stream-prefix retirement benchmark using pinned aioquic.

Hold the highest permitted request open, then complete lower requests in order,
with a prompt ACK before the next request. This exercises a large stream table
without conflating retirement with scanning many unacknowledged responses.
Every measured request requires an exact HTTP response. Report client-observed
throughput and Linux server CPU separately: Python can limit throughput.
"""

import argparse
import asyncio
import json
import os
import socket
import ssl
import subprocess
import time

from aioquic import tls
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

HEADERS = [(b":method", b"GET"), (b":scheme", b"https"),
           (b":authority", b"localhost"), (b":path", b"/")]


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}
        self.completed = 0
        self.ack_frames = 0
        self.lost = 0
        write_ack = self._quic._write_ack_frame
        on_lost = self._quic._loss._on_packets_lost

        def counted_ack(builder, space, now):
            write_ack(builder, space, now)
            if space is self._quic._spaces[tls.Epoch.ONE_RTT]:
                self.ack_frames += 1

        def counted_lost(*, now, packets, space):
            packets = list(packets)
            self.lost += len(packets)
            on_lost(now=now, packets=packets, space=space)

        self._quic._write_ack_frame = counted_ack
        self._quic._loss._on_packets_lost = counted_lost

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
                    future.set_result(None)

    def start(self, stream_id, end_stream):
        future = self._loop.create_future()
        self.pending[stream_id] = (future, [], bytearray())
        self.http.send_headers(stream_id, HEADERS, end_stream=end_stream)
        self.transmit()
        return future

    def prompt_ack(self):
        self._quic._spaces[tls.Epoch.ONE_RTT].ack_at = self._loop.time()

    async def request(self, stream_id):
        await asyncio.wait_for(self.start(stream_id, True), 5)
        del self.pending[stream_id]
        # The next request's transmit sends this ACK with its request frame.
        self.prompt_ack()


def cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split(") ")[1].split()
    tick = os.sysconf("SC_CLK_TCK")
    return [int(fields[11]) / tick, int(fields[12]) / tick]


async def measure(port, pid, args):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf, create_protocol=Client) as client:
        assert client._quic._remote_max_streams_bidi == args.slots
        held_id = (args.slots - 1) * 4
        held = client.start(held_id, False)
        await client.ping()
        for n in range(args.warmup):
            await client.request(n * 4)
        await client.ping()
        before = cpu(pid)
        ack_before, lost_before = client.ack_frames, client.lost
        start = time.perf_counter()
        for n in range(args.warmup, args.warmup + args.requests):
            await client.request(n * 4)
        await client.ping()  # Deliver the last response's ACK before measuring CPU.
        elapsed = time.perf_counter() - start
        after = cpu(pid)
        assert client.completed == args.warmup + args.requests
        assert not held.done(), "unfinished high stream got a premature response"
        assert client.lost == lost_before, "loss confounds the controlled workload"
        acks = client.ack_frames - ack_before
        assert acks >= args.requests - 1, acks
        limit = client._quic._remote_max_streams_bidi
        if args.warmup + args.requests >= args.slots // 2:
            assert limit >= args.slots + args.slots // 2, limit
        # Check that a live upper slot survived all prefix retirements.
        client.http.send_data(held_id, b"", end_stream=True)
        client.transmit()
        await asyncio.wait_for(held, 5)
        del client.pending[held_id]
        assert not client.pending
        used = [after[i] - before[i] for i in range(2)]
        return dict(slots=args.slots, requests=args.requests, warmup=args.warmup,
                    completed=client.completed, errors=0, seconds=elapsed,
                    requests_per_second=args.requests / elapsed,
                    server_user_seconds=used[0], server_system_seconds=used[1],
                    server_cpu_ns_per_request=sum(used) * 1e9 / args.requests,
                    application_ack_frames=acks, lost_packets=client.lost - lost_before,
                    advertised_stream_limit=limit)


async def main(args):
    assert args.warmup + args.requests < args.slots
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen([args.binary, "--threads", "1", "--tcp", "0",
                               "--quic", str(port), "--max-streams", str(args.slots)],
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
    parser.add_argument("--slots", type=int, default=65536)
    parser.add_argument("--requests", type=int, default=32768)
    parser.add_argument("--warmup", type=int, default=2048)
    asyncio.run(main(parser.parse_args()))
