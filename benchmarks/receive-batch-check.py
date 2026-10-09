#!/usr/bin/env python3
"""Independent aioquic check: queued single-peer bursts and peer transitions.

SIGSTOP lets the client queue a known burst before the server can receive it.
Packet/ACK counts are mechanism evidence, not throughput measurements.
"""

import argparse
import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger

from interoperability import Client, deny_uring


async def ready(client):
    for _ in range(600):
        if client._quic._handshake_confirmed and client.http.received_settings == {}:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("handshake and SETTINGS did not complete")


async def burst(server, client, count):
    trace = client._quic._quic_logger
    event_start = len(trace._events)
    tasks = []
    try:
        os.kill(server.pid, signal.SIGSTOP)
        try:
            waited, status = os.waitpid(server.pid, os.WUNTRACED)
            assert waited == server.pid and os.WIFSTOPPED(status)
            # Each task transmits before waiting for its response. There is no
            # server activity until all these datagrams are queued in the kernel.
            tasks = [
                asyncio.create_task(client.request(post=i % 2 == 0))
                for i in range(count)
            ]
            await asyncio.sleep(0)
            sent = [
                e["data"] for e in list(trace._events)[event_start:]
                if e["name"] == "transport:packet_sent"
            ]
            request_packets = [
                p for p in sent if any(
                    f["frame_type"] == "stream" and f["stream_id"] % 4 == 0
                    for f in p["frames"]
                )
            ]
            assert len(request_packets) == count, (len(request_packets), count)
            assert all(p["header"]["packet_type"] == "1RTT" for p in sent)
            assert all(not task.done() for task in tasks)
        finally:
            if server.poll() is None:
                os.kill(server.pid, signal.SIGCONT)
        await asyncio.wait_for(asyncio.gather(*tasks), 10)
        assert not client.pending
        received = [
            e["data"] for e in list(trace._events)[event_start:]
            if e["name"] == "transport:packet_received"
        ]
        ack_frames = [f for p in received for f in p["frames"] if f["frame_type"] == "ack"]
        sent_pns = {p["header"]["packet_number"] for p in request_packets}
        acked = {
            pn for pn in sent_pns
            if any(lo <= pn <= hi for f in ack_frames for lo, hi in f["acked_ranges"])
        }
        assert acked == sent_pns, (acked, sent_pns)
        result = {"requests": count, "queued_request_packets": len(request_packets),
                  "server_packets": len(received), "server_ack_frames": len(ack_frames),
                  "acknowledged_request_packets": len(acked)}
        print(json.dumps(result), flush=True)
        return result
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def check(server, port, logger):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    config.verify_mode = ssl.CERT_NONE
    results = []
    async with connect("127.0.0.1", port, configuration=config, create_protocol=Client) as first:
        await ready(first)
        await asyncio.gather(*(first.request() for _ in range(64)))
        # Includes serial/partial input after a large burst and a quiet socket.
        for count in [1, 8, 32, 1]:
            await first.ping()
            results.append(await burst(server, first, count))
        await asyncio.sleep(0.03)
        await first.request(post=True)
        async with connect("127.0.0.1", port, configuration=config, create_protocol=Client) as second:
            await ready(second)
            await asyncio.gather(*(client.request() for client in [first, second] for _ in range(32)))
        # aioquic sends CONNECTION_CLOSE before its context exits. The first
        # peer remains valid as the server returns from two peers to one.
        await first.ping()
        results.append(await burst(server, first, 8))
        await first.request(post=True)
    async with connect("127.0.0.1", port, configuration=config, create_protocol=Client) as fresh:
        await ready(fresh)
        await fresh.request()
    print("PASS: 181 exact GET/POST responses; queued bursts, idle, 0->1->2->1->0->1 peers", flush=True)
    return results


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
        assert server.poll() is None
        await asyncio.wait_for(check(server, port, logger), 30)
    finally:
        if server.poll() is None:
            os.kill(server.pid, signal.SIGCONT)
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
