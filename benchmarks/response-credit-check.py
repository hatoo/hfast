#!/usr/bin/env python3
"""Independent QUIC response-credit regression (pinned aioquic 1.3.0).

The TLS transport parameters really advertise these limits. Disable aioquic's
automatic window growth and send deliberate, reliable grants instead. Inspect
authenticated STREAM/RESET frames before packet accounting, including packets
discarded for the loss/reordering cases. No rate measurements.
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
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
from aioquic.quic.packet import QuicFrameType, pull_quic_transport_parameters
from aioquic.quic.stream import QuicStream

from interoperability import BODY, Client

RESPONSE = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!"
CONTROL = b"\x00\x04\x00"


def stream_frames(plain):
    buf = Buffer(data=plain)
    streams, resets = [], []
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
            stream = buf.pull_uint_var()
            offset = buf.pull_uint_var() if ty & 4 else 0
            length = buf.pull_uint_var() if ty & 2 else buf.capacity - buf.tell()
            streams.append((stream, offset, buf.pull_bytes(length), bool(ty & 1)))
        elif ty == 4:
            resets.append(tuple(buf.pull_uint_var() for _ in range(3)))
        elif ty in (0x10, 0x12, 0x13):
            buf.pull_uint_var()
        elif ty == 0x11:
            buf.pull_uint_var()
            buf.pull_uint_var()
        elif ty in (0x1A, 0x1B):
            buf.pull_bytes(8)
        else:
            raise AssertionError(f"unexpected server frame {ty:#x}")
    return streams, resets


class CreditClient(Client):
    def __init__(self, *args, case, **kwargs):
        super().__init__(*args, **kwargs)
        self.case = case
        self.raw = {}
        self.fins = {}
        self.resets = {}
        self.wire_resets = []
        self.wire_highest = {}
        self.frames = []
        self.dropped = []
        self.held = []
        self.injected = False
        self.failure = None
        self.stale = []
        self.drop_grant = False
        self.lost_grants = 0
        q = self._quic
        q._local_max_data.value = case.get("data", 1 << 20)
        q._local_max_stream_data_bidi_local = case.get("stream", 1024)
        q._local_max_stream_data_uni = case.get("uni", 1024)
        q._local_max_streams_uni.value = case.get("uni_count", 8)
        q._write_connection_limits = self.write_limits
        q._write_stream_limits = self.write_stream_limit
        serialize = q._serialize_transport_parameters

        def capture():
            raw = serialize()
            tp = pull_quic_transport_parameters(Buffer(data=raw))
            self.advertised = {key: getattr(tp, key) for key in (
                "initial_max_data", "initial_max_stream_data_bidi_local",
                "initial_max_stream_data_uni", "initial_max_streams_uni")}
            return raw

        q._serialize_transport_parameters = capture
        send = q.datagrams_to_send

        def filtered_send(now):
            packets = send(now)
            if self.drop_grant and packets:
                self.drop_grant = False
                self.lost_grants += len(packets)
                return []
            return packets

        q.datagrams_to_send = filtered_send

    def write_limits(self, builder, space):
        q = self._quic
        for limit in (q._local_max_data, q._local_max_streams_bidi, q._local_max_streams_uni):
            if limit.value != limit.sent:
                buf = builder.start_frame(limit.frame_type, capacity=16,
                                          handler=q._on_connection_limit_delivery,
                                          handler_args=(limit,))
                buf.push_uint_var(limit.value)
                limit.sent = limit.value
        for stream, value in self.stale:
            buf = builder.start_frame(QuicFrameType.MAX_DATA if stream is None else
                                      QuicFrameType.MAX_STREAM_DATA, capacity=24)
            if stream is not None:
                buf.push_uint_var(stream)
            buf.push_uint_var(value)
        self.stale.clear()

    def write_stream_limit(self, builder, space, stream):
        if stream.max_stream_data_local != stream.max_stream_data_local_sent:
            buf = builder.start_frame(QuicFrameType.MAX_STREAM_DATA, capacity=24,
                                      handler=self._quic._on_max_stream_data_delivery,
                                      handler_args=(stream,))
            buf.push_uint_var(stream.stream_id)
            buf.push_uint_var(stream.max_stream_data_local)
            stream.max_stream_data_local_sent = stream.max_stream_data_local

    def grant(self, stream=None, value=1024):
        if stream is None:
            limit = self._quic._local_max_data
            assert value >= limit.value
            limit.value = value
        else:
            # A zero-credit control stream has no bytes with which to create
            # aioquic's receive object yet. It is within the advertised count.
            if stream == 3 and stream not in self._quic._streams:
                obj = QuicStream(stream_id=3, max_stream_data_local=0, writable=False)
                self._quic._streams[3] = obj
                self._quic._streams_queue.append(obj)
            obj = self._quic._streams[stream]
            assert value >= obj.max_stream_data_local
            obj.max_stream_data_local = value
        self.transmit()

    def start_request(self):
        stream = self._quic.get_next_available_stream_id()
        future = self._loop.create_future()
        self.pending[stream] = (future, [], bytearray())
        self.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
                                       (b":authority", b"localhost"), (b":path", b"/")],
                               end_stream=True)
        self.transmit()
        return stream, future

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.failure = repr(event)
        if isinstance(event, StreamDataReceived):
            self.raw.setdefault(event.stream_id, bytearray()).extend(event.data)
            self.fins[event.stream_id] = self.fins.get(event.stream_id, 0) + event.end_stream
        if isinstance(event, StreamReset):
            self.resets[event.stream_id] = event.error_code
        super().quic_event_received(event)

    def datagram_received(self, data, addr):
        if not self.injected:
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def filtered(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                parts, resets = stream_frames(plain)
                try:
                    for stream, offset, body, fin in parts:
                        expected = CONTROL if stream == 3 else RESPONSE
                        assert body == expected[offset:offset + len(body)]
                        assert not fin if stream == 3 else (not fin or offset + len(body) == len(RESPONSE))
                        assert stream != 3 or self._quic._local_max_streams_uni.value >= 1
                        state = self._quic._streams.get(stream)
                        limit = state.max_stream_data_local if state else self._quic._local_max_stream_data_uni
                        end = offset + len(body)
                        assert end <= limit, ("stream credit", stream, end, limit)
                        self.wire_highest[stream] = max(self.wire_highest.get(stream, 0), end)
                        assert sum(self.wire_highest.values()) <= self._quic._local_max_data.value
                        self.frames.append((pn, stream, offset, len(body), fin))
                    self.wire_resets.extend(resets)
                    for stream, _, final_size in resets:
                        assert final_size == self.wire_highest.get(stream, 0)
                except AssertionError as error:
                    self.failure = repr(error)
                if self.case.get("fault") and len(self.dropped) < 2 and any(s == 0 for s, *_ in parts):
                    self.dropped.append(pn)
                    raise CryptoError("injected response-fragment loss")
                return result

            crypto.decrypt_packet = filtered
            self.injected = True
        before = len(self.dropped)
        super().datagram_received(data, addr)
        if len(self.dropped) > before:
            self.held.append((bytes(data), addr))

    async def until(self, predicate):
        async def wait():
            while not predicate():
                assert self.failure is None, self.failure
                await asyncio.sleep(.001)
            assert self.failure is None, self.failure
        await asyncio.wait_for(wait(), 8)

    async def stable(self):
        before = {s: bytes(b) for s, b in self.raw.items()}
        await asyncio.sleep(.04)
        assert self.failure is None, self.failure
        assert before == self.raw, "new bytes arrived while credit was exhausted"


async def check(port, case):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf,
                       create_protocol=lambda *a, **k: CreditClient(*a, case=case, **k)) as client:
        requests = [client.start_request() for _ in range(case.get("count", 8))]
        name = case["name"]
        if name == "sparse-acks":
            await client.until(lambda: client.raw.get(3) == CONTROL and
                               all(len(client.raw.get(s, b"")) == 1 for s, _ in requests))
            assert len(client.dropped) == 2
            for packet, addr in reversed(client.held):
                client.datagram_received(packet, addr)
                client.datagram_received(packet, addr)
            # Repeated ACK traffic with hundreds of credit-blocked replies;
            # only one sparse response receives fresh credit at a time.
            selected = [requests[i] for i in [511, 257, 2, 1]]
            for stream, future in selected:
                for end in [9, 19, len(RESPONSE)]:
                    if stream == selected[0][0] and end == 9:
                        client.drop_grant = True
                    client.grant(stream, end)
                    await client.until(lambda: len(client.raw.get(stream, b"")) == end)
                    await asyncio.wait_for(client.ping(), 8)
                    client.stale.extend([(stream, 0), (stream, end)])
                    client.transmit()
                    assert all(len(client.raw.get(s, b"")) == 1
                               for s, _ in requests if s not in {x for x, _ in selected})
                await client.until(future.done)
            await client.stable()
            # A dense refill and FIN retirement follow the sparse phase.
            for stream, future in requests:
                if not future.done():
                    client.grant(stream, len(RESPONSE))
        elif name.startswith("stream"):
            initial = case["stream"]
            await client.until(lambda: client.raw.get(3) == CONTROL)
            if initial:
                await client.until(lambda: all(len(client.raw.get(s, b"")) == initial for s, _ in requests))
            await client.stable()
            assert not any(f.done() for _, f in requests)
            if case.get("fault"):
                assert len(client.dropped) == 2
                if case["fault"] == "reorder":
                    for packet, addr in reversed(client.held):
                        client.datagram_received(packet, addr)
                        client.datagram_received(packet, addr)
                else:
                    assert all(pn not in client._quic._spaces[tls.Epoch.ONE_RTT].ack_queue for pn in client.dropped)
            for stream, future in requests[::-1]:
                for end in [9, 19, len(RESPONSE)]:
                    if end == 9 and stream == requests[-1][0] and case.get("fault"):
                        client.drop_grant = True
                    client.grant(stream, end)
                    await client.until(lambda: len(client.raw.get(stream, b"")) == end)
                    client.stale.extend([(stream, 0), (stream, end), (None, 0)])
                    client.transmit()
                await client.until(future.done)
                if stream != requests[0][0]:
                    assert len(client.raw.get(requests[0][0], b"")) == initial
        elif name == "connection":
            for limit in [0, 1, 2, 3, 4, 17, 50, 3 + len(requests) * len(RESPONSE)]:
                client.grant(value=limit)
                await client.until(lambda: sum(len(b) for b in client.raw.values()) == limit)
                await client.stable()
                client.stale.append((None, max(0, limit - 1)))
                client.transmit()
        elif name in ("control", "uni-count"):
            if name == "uni-count":
                await asyncio.sleep(.04)
                assert not client.raw.get(3)
                client._quic._local_max_streams_uni.value = 1
                client.transmit()
            else:
                for end in range(1, 4):
                    client.grant(3, end)
                    await client.until(lambda: len(client.raw.get(3, b"")) == end)
            await client.until(lambda: client.http.received_settings is not None)
        elif name == "stop":
            stream, future = requests.pop(0)
            await client.until(lambda: len(client.raw.get(stream, b"")) == 4)
            client.pending.pop(stream)
            future.cancel()
            client._quic.stop_stream(stream, 0x10C)
            client.transmit()
            await client.until(lambda: stream in client.resets)
            assert (stream, 0x10C, 4) in client.wire_resets
            for other, _ in requests:
                client.grant(other, len(RESPONSE))
        else:
            raise AssertionError(name)

        await client.until(lambda: all(f.done() for _, f in requests))
        for stream, future in requests:
            headers, body = future.result()
            assert (b":status", b"200") in headers and body == BODY
            assert client.raw[stream] == RESPONSE and client.fins[stream] == 1
            client.pending.pop(stream)
        assert client.raw[3] == CONTROL and client.fins[3] == 0
        assert not client.pending and client.failure is None
        if case.get("fault"):
            assert client.lost_grants >= 1
        # Ordinary GET/POST after increasing the connection and default
        # stream window checks slot retirement and followup accounting.
        client._quic._local_max_stream_data_bidi_local = 1024
        client.grant(value=1 << 21)
        followups = [asyncio.create_task(client.request(post)) for post in [False, True] * 4]
        await asyncio.sleep(0)
        for stream in client.pending:
            client._quic._streams[stream].max_stream_data_local_sent = 0
        client.transmit()
        await asyncio.gather(*followups)
        assert client.failure is None
        return {"case": case, "advertised": client.advertised, "responses": len(requests),
                "followups": 8, "lost_responses": client.dropped, "lost_grants": client.lost_grants,
                "wire_highest": client.wire_highest, "frames": client.frames,
                "resets": client.wire_resets, "errors": 0}


async def main(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen([args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    cases = [dict(name="stream-zero", stream=0, count=32), dict(name="stream-one", stream=1),
             dict(name="stream-loss", stream=4, fault="loss"),
             dict(name="stream-reorder", stream=4, fault="reorder"),
             dict(name="connection", data=0), dict(name="control", uni=0),
             dict(name="uni-count", uni_count=0), dict(name="stop", stream=4),
             dict(name="sparse-acks", stream=1, count=512, fault="reorder")]
    try:
        await asyncio.sleep(.2)
        assert server.poll() is None
        for case in cases:
            if args.case and args.case != case["name"]:
                continue
            result = await asyncio.wait_for(check(port, case), 40)
            results.append(result)
            print(json.dumps({k: v for k, v in result.items() if k not in ("frames", "wire_highest")}), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.output:
            with open(args.output, "x") as out:
                json.dump(results, out, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--case")
    parser.add_argument("--output")
    asyncio.run(main(parser.parse_args()))
