#!/usr/bin/env python3
"""Independent aioquic regression for request bodies beyond stream receive credit.

Every body byte must be acknowledged before FIN is sent. This checks transport
delivery and the exact response; hfast deliberately does not parse request bodies.
"""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoError

from interoperability import BODY, Client


def stream_credits(plain):
    """Inspect authenticated frames before received-PN accounting or ACKs."""
    buf = Buffer(data=plain)
    limits = []
    while not buf.eof():
        ty = buf.pull_uint_var()
        if ty in (0, 1, 0x1E):
            continue
        if ty in (2, 3):
            buf.pull_uint_var()
            buf.pull_uint_var()
            count = buf.pull_uint_var()
            buf.pull_uint_var()
            for _ in range(2 * count + (3 if ty == 3 else 0)):
                buf.pull_uint_var()
        elif ty == 6:
            buf.pull_uint_var()
            buf.pull_bytes(buf.pull_uint_var())
        elif 8 <= ty <= 15:
            buf.pull_uint_var()
            if ty & 4:
                buf.pull_uint_var()
            size = buf.pull_uint_var() if ty & 2 else buf.capacity - buf.tell()
            buf.pull_bytes(size)
        elif ty in (0x10, 0x12, 0x13):
            buf.pull_uint_var()
        elif ty == 0x11:
            limits.append((buf.pull_uint_var(), buf.pull_uint_var()))
        elif ty == 4:
            for _ in range(3):
                buf.pull_uint_var()
        elif ty in (0x1A, 0x1B):
            buf.pull_bytes(8)
        else:
            raise AssertionError(f"unexpected server frame {ty:#x}")
    return limits


class StreamCreditClient(Client):
    def __init__(self, *args, mode, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = mode
        self.injected = False
        self.dropped = []
        self.held = []
        self.credits = []
        self.released = False
        self.completed = []
        self.blocked_seen = False

    def datagram_received(self, data, addr):
        if not self.injected:
            # Pinned aioquic 1.3: reject protected packets before the QUIC
            # receiver sees them, so no ACK can hide a missing credit update.
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def filtered(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                credits = stream_credits(plain)
                if credits:
                    self.credits.append((pn, credits))
                if (self.mode != "ordinary" and any(s == 0 for s, _ in credits)
                        and (len(self.dropped) < 2 or not self.blocked_seen)):
                    self.dropped.append(pn)
                    raise CryptoError("injected MAX_STREAM_DATA loss")
                return result

            crypto.decrypt_packet = filtered
            self.injected = True
        before = len(self.dropped)
        super().datagram_received(data, addr)
        if len(self.dropped) > before:
            self.held.append((bytes(data), addr))

    async def post(self, size):
        stream = self._quic.get_next_available_stream_id()
        future = self._loop.create_future()
        self.pending[stream] = (future, [], bytearray())
        self.http.send_headers(stream, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/"),
            (b"content-length", str(size).encode()),
        ], end_stream=False)
        # A single DATA frame with real bytes. Offsets alone cannot satisfy
        # this test: aioquic retains each byte until its range is acknowledged.
        self.http.send_data(stream, b"x" * size, end_stream=False)
        sender = self._quic._streams[stream].sender
        end = sender._buffer_stop
        self.transmit()
        try:
            while sender._buffer_start != end:
                assert not future.done(), "response arrived before request FIN"
                state = self._quic._streams[stream]
                self.blocked_seen |= (
                    stream == 0 and len(self.dropped) >= 2
                    and sender.highest_offset == state.max_stream_data_remote
                    and sender.highest_offset < end
                )
                await asyncio.sleep(0.001)
            assert not sender._buffer and not future.done()
            if self.mode == "reorder" and stream == 0:
                # Deliver obsolete updates after newer credit has already
                # enabled progress, including duplicate protected datagrams.
                assert len(self.held) >= 2 and self.blocked_seen
                current = self._quic._streams[stream].max_stream_data_remote
                for packet, addr in reversed(self.held):
                    self.datagram_received(packet, addr)
                    self.datagram_received(packet, addr)
                assert self._quic._streams[stream].max_stream_data_remote == current
                self.released = True
            self.http.send_data(stream, b"", end_stream=True)
            self.transmit()
            headers, body = await future
            assert (b":status", b"200") in headers and body == BODY, (headers, body)
            while not sender.is_finished:
                await asyncio.sleep(0.001)
            self.completed.append({"stream": stream, "body_bytes": size,
                                   "acked_before_fin": end, "fin_acked": True})
        finally:
            self.pending.pop(stream, None)


async def check(port, mode, size, count, timeout):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf,
                       create_protocol=lambda *a, **k: StreamCreditClient(*a, mode=mode, **k)) as client:
        initial = client._quic._remote_max_stream_data_bidi_remote
        # These are client-initiated streams, so the server's bidi_remote
        # transport parameter is the relevant initial receive limit.
        assert initial == 1 << 24 and size > initial
        try:
            await asyncio.wait_for(asyncio.gather(*(client.post(size) for _ in range(count))), timeout)
            assert len(client.completed) == count and not client.pending
            assert client.credits, "large bodies require stream receive updates"
            if mode != "ordinary":
                assert len(client.dropped) >= 2 and client.blocked_seen
                if mode == "loss":
                    space = client._quic._spaces[tls.Epoch.ONE_RTT]
                    assert all(pn not in space.ack_queue for pn in client.dropped)
                else:
                    assert client.released
            # Reuse the connection after completion; duplicates must not
            # reopen old streams or corrupt subsequent replies.
            await asyncio.gather(*(client.request(post) for post in [False, True] * 4))
            result = {"mode": mode, "completed": client.completed,
                      "lost_credit_packets": client.dropped,
                      "credit_frames": sum(len(v) for _, v in client.credits),
                      "blocked_seen": client.blocked_seen,
                      "followup_responses": 8, "errors": 0}
            print(json.dumps(result), flush=True)
            return result
        finally:
            print("Final receive credit:",
                  {s: {"limit": q.max_stream_data_remote,
                       "highest_sent": q.sender.highest_offset,
                       "acked_prefix": q.sender._buffer_start,
                       "body_end": q.sender._buffer_stop}
                   for s, q in client._quic._streams.items() if s % 4 == 0},
                  "completed:", len(client.completed), "dropped:", client.dropped, flush=True)


async def main(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen([args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None, "server exited during startup"
        for mode in ([args.mode] if args.mode else ["ordinary", "loss", "reorder"]):
            results.append(await check(port, mode, args.bytes, args.streams, args.timeout))
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.output:
            with open(args.output, "x") as out:
                json.dump(results, out, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--mode", choices=["ordinary", "loss", "reorder"])
    parser.add_argument("--bytes", type=int, default=(1 << 24) + 65543)
    parser.add_argument("--streams", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--output")
    asyncio.run(main(parser.parse_args()))
