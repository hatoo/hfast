#!/usr/bin/env python3
"""Independent aioquic regression: delay stream 0 until stream 4 is ACKed."""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from interoperability import Client, deny_uring


def frames(packet, kind):
    return [f for f in packet["frames"] if f["frame_type"] == kind]


async def acknowledge_response(client, stream, delivered):
    """Prove the server received an ACK of this response before proceeding."""
    trace = client._quic._quic_logger
    responses = [
        e["data"]["header"]["packet_number"]
        for e in trace._events
        if e["name"] == "transport:packet_received"
        and any(f["stream_id"] == stream for f in frames(e["data"], "stream"))
    ]
    assert responses
    event_start, sent_start = len(trace._events), len(delivered)
    client._quic._spaces[tls.Epoch.ONE_RTT].ack_at = client._loop.time()
    await asyncio.wait_for(client.ping(), 2)
    ack_packets = [
        packet["header"]["packet_number"]
        for packet in delivered[sent_start:]
        if any(lo <= responses[-1] <= hi
               for f in frames(packet, "ack") for lo, hi in f["acked_ranges"])
    ]
    assert any(
        lo <= pn <= hi
        for e in list(trace._events)[event_start:]
        if e["name"] == "transport:packet_received"
        for f in frames(e["data"], "ack") for lo, hi in f["acked_ranges"]
        for pn in ack_packets
    ), f"server did not acknowledge the packet ACKing response {stream}"


async def check(port, mode, logger):
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

        # Pinned aioquic 1.3 internals. Its qlog describes the encrypted packets
        # already charged to loss recovery. Drop whole datagrams at that point,
        # before the transport sends them. Assert the one-packet correspondence
        # instead of silently trusting a log-to-datagram mapping.
        trace = client._quic._quic_logger
        original = client._quic.datagrams_to_send
        holding = True
        held = []
        lower_sent = []
        delivered_packets = []
        first_drop = asyncio.Event()

        def filtered_datagrams(now):
            start = len(trace._events)
            datagrams = original(now=now)
            packets = [
                e["data"]
                for e in list(trace._events)[start:]
                if e["name"] == "transport:packet_sent"
            ]
            assert len(packets) == len(datagrams)
            delivered = []
            for (data, addr), packet in zip(datagrams, packets):
                assert packet["header"]["packet_type"] == "1RTT"
                assert packet["raw"]["length"] == len(data)
                streams = [f["stream_id"] for f in frames(packet, "stream")]
                pn = packet["header"]["packet_number"]
                if 0 in streams and holding:
                    held.append((data, addr, pn))
                    trace.log_event(
                        category="testing", event="request_held",
                        data={"packet_number": pn, "streams": streams},
                    )
                    first_drop.set()
                else:
                    delivered.append((data, addr))
                    delivered_packets.append(packet)
                    if 0 in streams:
                        lower_sent.append(pn)
            return delivered

        client._quic.datagrams_to_send = filtered_datagrams
        lower = asyncio.create_task(client.request())
        try:
            await asyncio.wait_for(first_drop.wait(), 2)
            assert 0 in client.pending
            await client.request()
            assert 4 not in client.pending and 0 in client.pending

            # ACK the higher response and wait until the server ACKs that
            # packet, before a lower request can arrive. No timing guess.
            await acknowledge_response(client, 4, delivered_packets)
            assert not lower.done()
            print(f"Higher response ACKed; held lower packet numbers {[p for _, _, p in held]}", flush=True)

            holding = False
            trace.log_event(category="testing", event="release_lower", data={"mode": mode})
            if mode == "reorder":
                data, addr, _ = held[0]
                client._transport.sendto(data, addr)
            # In loss mode aioquic must retransmit in a new packet number.
            await asyncio.wait_for(lower, 6)
            if mode == "loss":
                assert lower_sent and not set(lower_sent).intersection(p for _, _, p in held)

            # Delayed duplicate ciphertext must not reopen completed requests.
            await acknowledge_response(client, 0, delivered_packets)
            for _ in range(2):
                data, addr, _ = held[0]
                client._transport.sendto(data, addr)
            await asyncio.wait_for(client.ping(), 2)
            for post in (False, True):
                await asyncio.gather(*(client.request(post) for _ in range(64)))
            assert not client.pending
            print(
                f"PASS: {mode}, delayed stream 0 after ACKed stream 4, duplicates, "
                "130 exact GET/POST responses", flush=True,
            )
        finally:
            client._quic.datagrams_to_send = original
            if not lower.done():
                lower.cancel()
            await asyncio.gather(lower, return_exceptions=True)


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
        for mode in ([args.mode] if args.mode else ["reorder", "loss"]):
            await asyncio.wait_for(check(port, mode, logger), 15)
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.qlog:
            with open(args.qlog, "x") as out:
                json.dump(logger.to_dict(), out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--mode", choices=["reorder", "loss"])
    parser.add_argument("--epoll", action="store_true")
    parser.add_argument("--qlog")
    asyncio.run(main(parser.parse_args()))
