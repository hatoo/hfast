#!/usr/bin/env python3
"""Independent aioquic check of exact credit after uni gaps and retransmission."""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic.asyncio import connect
from aioquic.buffer import Buffer, size_uint_var
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicStreamFrame

from interoperability import Client, deny_uring


async def check(port, logger):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf, create_protocol=Client
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
        assert q._remote_max_streams_uni == 8
        assert q.get_next_available_stream_id() == 0
        assert q.get_next_available_stream_id(is_unidirectional=True) <= 14
        assert initial_seen == sum(s.sender.highest_offset for s in q._streams.values())

        # Pinned aioquic 1.3 internals: insert STREAM frames into its encrypted
        # PING packet, retaining normal packet numbers, loss tracking and ACKs.
        # Sparse offsets reach hfast's half-window update threshold without
        # allocating or transmitting 512 MiB. Every offset and the connection
        # total stay within the advertised limits. No FIN on these incomplete
        # bidi streams: they must never generate HTTP responses.
        pending = []
        injected_pns = []
        captured = {}
        original_ping = q._write_ping_frame
        original_datagrams = q.datagrams_to_send

        def write_ping(builder, uids=(), comment=""):
            if pending and uids:
                capacity = sum(
                    1 + size_uint_var(sid) + size_uint_var(offset)
                    + size_uint_var(len(data)) + len(data)
                    for sid, offset, data, _ in pending
                )
                assert builder.remaining_flight_space >= capacity + 1
                for sid, offset, data, fin in pending:
                    stream = q._get_or_create_stream_for_send(sid)
                    assert not stream.is_blocked
                    end = offset + len(data)
                    assert end <= stream.max_stream_data_remote
                    fresh = max(0, end - stream.sender.highest_offset)
                    assert q._remote_max_data_used + fresh <= q._remote_max_data
                    stream.sender.highest_offset += fresh
                    q._remote_max_data_used += fresh
                    payload = Buffer(capacity=capacity)
                    payload.push_uint_var(sid)
                    payload.push_uint_var(offset)
                    payload.push_uint_var(len(data))
                    payload.push_bytes(data)
                    buf = builder.start_frame(0x0E | int(fin), capacity=1 + payload.tell())
                    buf.push_bytes(payload.data)
                    builder.quic_logger_frames.append(trace.encode_stream_frame(
                        QuicStreamFrame(offset=offset, data=data, fin=fin), stream_id=sid
                    ))
                injected_pns.append(builder.packet_number)
                pending.clear()
            original_ping(builder, uids=uids, comment=comment)

        def datagrams_to_send(now):
            start = len(trace._events)
            datagrams = original_datagrams(now=now)
            packets = [
                e["data"] for e in list(trace._events)[start:]
                if e["name"] == "transport:packet_sent"
            ]
            if any(p["header"]["packet_number"] in injected_pns for p in packets):
                assert len(packets) == len(datagrams)
                for packet, datagram in zip(packets, datagrams):
                    assert packet["header"]["packet_type"] == "1RTT"
                    assert packet["raw"]["length"] == len(datagram[0])
                    pn = packet["header"]["packet_number"]
                    if pn in injected_pns:
                        captured[pn] = datagram
            return datagrams

        async def inject(frames):
            assert not pending
            pending.extend(frames)
            await asyncio.wait_for(client.ping(), 2)
            assert not pending
            assert injected_pns[-1] in captured
            return injected_pns[-1]

        q._write_ping_frame = write_ping
        q.datagrams_to_send = datagrams_to_send
        try:
            uni = [
                (14, 96, b"x" * 32, False),
                (14, 64, b"x" * 64, False),  # overlap
                (18, 16, b"y" * 16, False),
            ]
            # End offsets 128 + 32, regardless of arrival order or overlap.
            uni_seen = 160
            step = initial_limit // 2

            def sparse_bidi(first):
                return [(sid, (1 << 24) - 1, b"z", False)
                        for sid in range(first, first + 32 * 4, 4)]

            first_pn = await inject(uni + sparse_bidi(0))
            expected = initial_limit + initial_seen + uni_seen + step
            checks = [(q._remote_max_data, expected)]
            # A fresh PING ACKs the credit packet before the duplicate phase.
            await asyncio.wait_for(client.ping(), 2)
            for _ in range(2):
                data, addr = captured[first_pn]
                client._transport.sendto(data, addr)
            second_pn = await inject(uni)
            assert second_pn != first_pn
            assert q._remote_max_data == checks[0][0]
            # Fill gaps and repeat a FIN, then provoke the next update. Any
            # credit inflated by replay or new-PN retransmission is now visible.
            tail = [(14, 0, b"x" * 64, False), (18, 0, b"y" * 32, True),
                    (14, 128, b"", True), (14, 128, b"", True)]
            await inject(tail + sparse_bidi(128))
            expected += step
            checks.append((q._remote_max_data, expected))
            print(f"MAX_DATA (received, expected): {checks}", flush=True)
            assert all(got == want for got, want in checks), checks
            assert q._remote_max_data_used == expected - initial_limit
            credits = [
                f["maximum"] for e in trace._events
                if e["name"] == "transport:packet_received"
                for f in e["data"]["frames"] if f["frame_type"] == "max_data"
            ]
            assert set(credits) == {expected - step, expected}, credits
            print(f"PASS: exact MAX_DATA {credits}; replay PN {first_pn}, "
                  f"retransmission PN {second_pn}; uni bytes {uni_seen}", flush=True)
        finally:
            q._write_ping_frame = original_ping
            q.datagrams_to_send = original_datagrams

        for post in (False, True):
            await asyncio.gather(*(client.request(post) for _ in range(64)))
        assert not client.pending
        assert not any(
            f["stream_id"] < 256
            for e in trace._events if e["name"] == "transport:packet_received"
            for f in e["data"]["frames"]
            if f["frame_type"] == "stream" and f["stream_id"] % 4 == 0
        ), "an unfinished sparse stream was answered"
        print("PASS: 128 exact GET/POST responses; no unfinished-stream responses", flush=True)


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
