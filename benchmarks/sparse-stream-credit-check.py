#!/usr/bin/env python3
"""Keep acknowledged extended streams open while one stream needs credit recovery.

All request bytes must be ACKed before FIN. Prime with real DATA, then finish
streams around the survivor to exercise ACK compaction and FIN removal.
"""
import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from interoperability import BODY

spec = importlib.util.spec_from_file_location(
    "stream_credit_check", Path(__file__).with_name("stream-credit-check.py"))
credit_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credit_check)


class SparseClient(credit_check.StreamCreditClient):
    async def ack_body(self, stream):
        sender = self._quic._streams[stream].sender
        end = sender._buffer_stop
        self.transmit()
        while sender._buffer_start != end:
            assert not self.pending[stream][0].done(), "response before FIN"
            state = self._quic._streams[stream]
            self.blocked_seen |= (
                stream == 0 and len(self.dropped) >= 2
                and sender.highest_offset == state.max_stream_data_remote
                and sender.highest_offset < end)
            await asyncio.sleep(.001)
        assert not sender._buffer and not self.pending[stream][0].done()
        return end

    async def start(self, size):
        stream = self._quic.get_next_available_stream_id()
        self.pending[stream] = (self._loop.create_future(), [], bytearray())
        self.http.send_headers(stream, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/"),
        ], end_stream=False)
        self.http.send_data(stream, b"x" * size, end_stream=False)
        await self.ack_body(stream)
        # The priming update itself must have reached the independent peer.
        while self._quic._streams[stream].max_stream_data_remote <= 1 << 24:
            await asyncio.sleep(.001)
        return stream

    async def finish(self, stream, body_bytes):
        sender = self._quic._streams[stream].sender
        end = sender._buffer_stop
        assert sender._buffer_start == end and not sender._buffer
        future = self.pending[stream][0]
        self.http.send_data(stream, b"", end_stream=True)
        self.transmit()
        headers, body = await future
        assert (b":status", b"200") in headers and body == BODY
        while not sender.is_finished:
            await asyncio.sleep(.001)
        self.pending.pop(stream)
        return dict(stream=stream, body_bytes=body_bytes, acked_before_fin=end, fin_acked=True)


async def workload(port, count, loss):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf,
                       create_protocol=lambda *a, **k: SparseClient(*a, mode="ordinary", **k)) as client:
        size = (1 << 23) + 17
        streams = [await client.start(size) for _ in range(count)]
        await asyncio.sleep(.05)  # allow the independent peer's delayed credit ACK
        assert len(client.pending) == count
        survivor = streams[0]
        client.mode = "reorder" if loss else "ordinary"
        extra = (1 << 24) + 65543
        client.http.send_data(survivor, b"y" * extra, end_stream=False)
        await client.ack_body(survivor)
        if loss:
            assert client.blocked_seen and len(client.held) >= 2
            limit = client._quic._streams[survivor].max_stream_data_remote
            for packet, addr in reversed(client.held):
                client.datagram_received(packet, addr)
                client.datagram_received(packet, addr)
            assert client._quic._streams[survivor].max_stream_data_remote == limit
        results = []
        # Remove the last, middle and first non-survivors before the final live one.
        order = streams[1::2][::-1] + streams[2::2] + [survivor]
        assert len(set(order)) == count
        for stream in order:
            results.append(await client.finish(stream, size + (extra if stream == survivor else 0)))
        assert not client.pending
        await asyncio.gather(*(client.request(post) for post in [False, True] * 4))
        return dict(retained_streams=count, loss=loss, completed=results,
                    lost_credit_packets=client.dropped, blocked_seen=client.blocked_seen,
                    followup_responses=8, errors=0)


async def main(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen([args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        await asyncio.sleep(.2)
        assert server.poll() is None
        for loss in [False, True]:
            result = await asyncio.wait_for(workload(port, args.streams, loss), args.timeout)
            results.append(result)
            print(json.dumps(result), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.output:
            with open(args.output, "x") as out:
                json.dump(results, out, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--streams", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--output")
    asyncio.run(main(parser.parse_args()))
