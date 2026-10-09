#!/usr/bin/env python3
"""Independent cancellation credit, half-close, and reset-loss checks; no timing."""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.buffer import Buffer
from aioquic.h3.connection import FrameType, encode_frame
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoError
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicStreamFrame

from interoperability import BODY, Client, deny_uring


def resets_in(plain):
    """Read server frames before delivery, so injected losses cannot be ACKed."""
    buf = Buffer(data=plain)
    resets = []
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
        elif ty == 4:
            resets.append(tuple(buf.pull_uint_var() for _ in range(3)))
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
        elif ty in (0x1A, 0x1B):
            buf.pull_bytes(8)
        else:
            raise AssertionError(f"unexpected server frame {ty:#x}")
    return resets


class ResetClient(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dropped = []
        self.injected = False

    def datagram_received(self, data, addr):
        if not self.injected:
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def lossy_decrypt(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                if len(self.dropped) < 2 and (resets := resets_in(plain)):
                    self.dropped.append(pn)
                    self._quic._quic_logger.log_event(
                        category="testing", event="packet_dropped",
                        data={"packet_number": pn, "resets": resets},
                    )
                    raise CryptoError("injected RESET_STREAM packet loss")
                return result

            crypto.decrypt_packet = lossy_decrypt
            self.injected = True
        super().datagram_received(data, addr)


# STREAM is (kind, id, end offset, payload, FIN). RESET uses the final size;
# STOP has no receive offset. These are valid QUIC frames, encrypted by aioquic.
def stream(sid, end, data=b"x", fin=False):
    return ("stream", sid, end, data, fin)


def reset(sid, size):
    return ("reset", sid, size, b"", False)


def stop(sid):
    return ("stop", sid, 0, b"", False)


async def check(port, logger):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf, create_protocol=ResetClient
    ) as client:
        for _ in range(600):
            if client._quic._handshake_confirmed and client.http.received_settings == {}:
                break
            await asyncio.sleep(0.01)
        assert client._quic._handshake_confirmed
        assert client.http.received_settings == {}
        await asyncio.wait_for(client.ping(), 2)
        q = client._quic
        trace = q._quic_logger
        initial_limit = q._remote_max_data
        initial_seen = q._remote_max_data_used
        assert initial_limit == 1 << 30
        assert q._remote_max_stream_data_uni == 1 << 24
        assert q._remote_max_stream_data_bidi_remote == 1 << 24
        assert initial_seen == sum(s.sender.highest_offset for s in q._streams.values())
        # Reserve an unseen lower stream; higher cancellations must not erase it.
        q._get_or_create_stream_for_send(0)
        pending, injected_pns, captured = [], [], {}
        original_ping = q._write_ping_frame
        original_datagrams = q.datagrams_to_send

        def write_ping(builder, uids=(), comment=""):
            if pending and uids:
                for kind, sid, end, data, fin in pending:
                    sender = q._get_or_create_stream_for_send(sid)
                    assert not sender.is_blocked
                    assert end <= sender.max_stream_data_remote
                    # Include the lost/sparse bytes represented by a reset in
                    # aioquic's normal sender budget; never overrun peer credit.
                    fresh = max(0, end - sender.sender.highest_offset)
                    assert q._remote_max_data_used + fresh <= q._remote_max_data
                    sender.sender.highest_offset += fresh
                    q._remote_max_data_used += fresh
                    payload = Buffer(capacity=128)
                    payload.push_uint_var(sid)
                    if kind == "stream":
                        payload.push_uint_var(end - len(data))
                        payload.push_uint_var(len(data))
                        payload.push_bytes(data)
                        ty = 0x0E | int(fin)
                        logged = trace.encode_stream_frame(
                            QuicStreamFrame(offset=end - len(data), data=data, fin=fin), sid
                        )
                    else:
                        payload.push_uint_var(0x10C)
                        if kind == "reset":
                            payload.push_uint_var(end)
                            ty = 4
                            logged = trace.encode_reset_stream_frame(0x10C, end, sid)
                        else:
                            ty = 5
                            logged = trace.encode_stop_sending_frame(0x10C, sid)
                    assert builder.remaining_flight_space >= 2 + payload.tell()
                    buf = builder.start_frame(ty, capacity=1 + payload.tell())
                    buf.push_bytes(payload.data)
                    builder.quic_logger_frames.append(logged)
                injected_pns.append(builder.packet_number)
                pending.clear()
            original_ping(builder, uids=uids, comment=comment)

        def datagrams_to_send(now):
            start = len(trace._events)
            datagrams = original_datagrams(now=now)
            packets = [e["data"] for e in list(trace._events)[start:]
                       if e["name"] == "transport:packet_sent"]
            if any(p["header"]["packet_number"] in injected_pns for p in packets):
                assert len(packets) == len(datagrams)
                for packet, datagram in zip(packets, datagrams):
                    pn = packet["header"]["packet_number"]
                    if pn in injected_pns:
                        assert packet["header"]["packet_type"] == "1RTT"
                        assert packet["raw"]["length"] == len(datagram[0])
                        captured[pn] = datagram
            return datagrams

        async def inject(frames):
            assert not pending
            pending.extend(frames)
            await asyncio.wait_for(client.ping(), 2)
            assert not pending and injected_pns[-1] in captured
            return injected_pns[-1]

        q._write_ping_frame = write_ping
        q.datagrams_to_send = datagrams_to_send
        try:
            first = [stream(12, 32), stream(16, 16), stream(14, 32), stop(16),
                     reset(8, 128), reset(12, 128), reset(14, 128), reset(18, 128)]
            first_pn = await inject(first)
            def received_frames():
                return [f for e in trace._events if e["name"] == "transport:packet_received"
                        for f in e["data"]["frames"]]

            # A PING ACK alone does not imply the lost reset has recovered.
            # Observe all resets before finishing the other direction, then
            # use a PING to flush their ACK. Retain the outcome until after the
            # credit checks so broken baselines also print exact credit values.
            recovered = False
            for _ in range(600):
                ids = {f["stream_id"] for f in received_frames()
                       if f["frame_type"] == "reset_stream"}
                if ids == {8, 12, 16}:
                    recovered = True
                    break
                await asyncio.sleep(0.01)
            # ACK the server's recovered resets before completing stream 16's
            # receive side. STOP_SENDING alone must not retire this stream.
            await asyncio.wait_for(client.ping(), 2)
            future = asyncio.get_running_loop().create_future()
            client.pending[20] = (future, [], bytearray())
            # The independent sending-direction case is a complete, valid
            # HTTP/3 POST. Keep its size fixed for the exact-credit assertions.
            updates, section = client.http._encoder.encode(20, [
                (b":method", b"POST"), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", b"/"),
            ])
            assert not updates, "the peer advertised no dynamic QPACK table"
            request = encode_frame(FrameType.HEADERS, section)
            assert len(request) <= 30
            request += encode_frame(FrameType.DATA, b"x" * (30 - len(request)))
            assert len(request) == 32
            await inject([stream(16, 64), reset(16, 128),
                          stream(20, 32, request, True), reset(20, 32)])

            def sparse(first):
                return [stream(sid, 1 << 24) for sid in range(first, first + 128, 4)]

            await inject(sparse(128))
            expected = initial_limit + initial_seen + 5 * 128 + 32 + initial_limit // 2
            checks = [(q._remote_max_data, expected)]
            await asyncio.wait_for(client.ping(), 2)
            for _ in range(2):
                data, addr = captured[first_pn]
                client._transport.sendto(data, addr)
            second_pn = await inject(first)
            assert second_pn != first_pn
            assert q._remote_max_data == checks[0][0]
            await inject([reset(sid, 128) for sid in (8, 12, 16, 14, 18)]
                         + [stream(14, 64), stream(18, 128, b"", True)] + sparse(256))
            expected += initial_limit // 2
            checks.append((q._remote_max_data, expected))
            print(f"MAX_DATA (received, expected): {checks}", flush=True)
            assert all(got == want for got, want in checks), checks
            assert q._remote_max_data_used == expected - initial_limit
            assert recovered, "server resets did not recover before receive-side completion"
            headers, body = await asyncio.wait_for(future, 2)
            assert (b":status", b"200") in headers and body == BODY
            del client.pending[20]
            assert len(client.dropped) == 2, client.dropped
            space = q._spaces[tls.Epoch.ONE_RTT]
            assert all(pn not in space.ack_queue for pn in client.dropped)
            received = received_frames()
            resets = [f for f in received if f["frame_type"] == "reset_stream"]
            assert {f["stream_id"] for f in resets} == {8, 12, 16}, resets
            assert all(f["final_size"] == 0 and f["error_code"] == 0x10C for f in resets)
            assert not any(f["frame_type"] == "stream" and f["stream_id"] in {8, 12, 16}
                           for f in received), "cancelled request received an HTTP success"
            print(f"PASS: exact credit; replay {first_pn}, retransmission {second_pn}; "
                  f"recovered resets after drops {client.dropped}; independent response", flush=True)
        finally:
            q._write_ping_frame = original_ping
            q.datagrams_to_send = original_datagrams

        # Finish the lower request after higher stream resets were acknowledged.
        future = asyncio.get_running_loop().create_future()
        client.pending[0] = (future, [], bytearray())
        client.http.send_headers(0, [(b":method", b"GET"), (b":scheme", b"https"),
                                    (b":authority", b"localhost"), (b":path", b"/")],
                                 end_stream=True)
        client.transmit()
        headers, body = await asyncio.wait_for(future, 2)
        assert (b":status", b"200") in headers and body == BODY
        del client.pending[0]
        for post in (False, True):
            await asyncio.gather(*(client.request(post) for _ in range(64)))
        assert not client.pending
        assert not any(f["stream_id"] in range(128, 384, 4)
                       for e in trace._events if e["name"] == "transport:packet_received"
                       for f in e["data"]["frames"] if f["frame_type"] == "stream"), \
            "an unfinished sparse stream was answered"
        print("PASS: lower unseen request and 128 exact GET/POST responses", flush=True)


async def main(args):
    logger = QuicLogger()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen(
        [args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=deny_uring if args.epoll else None,
    )
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None, "server exited during startup"
        await asyncio.wait_for(check(port, logger), 15)
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.qlog:
            with open(args.qlog, "x") as out:
                json.dump(logger.to_dict(), out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--epoll", action="store_true")
    parser.add_argument("--qlog")
    asyncio.run(main(parser.parse_args()))
