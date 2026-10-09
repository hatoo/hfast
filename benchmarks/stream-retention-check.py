#!/usr/bin/env python3
"""Independent long-connection check: hold POST stream 0 across a small window."""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from interoperability import BODY, Client, deny_uring


async def check(port, requests):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
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
        assert client._quic._remote_max_streams_bidi == 64

        stream = client._quic.get_next_available_stream_id()
        assert stream == 0
        lower = asyncio.get_running_loop().create_future()
        client.pending[0] = (lower, [], bytearray())
        client.http.send_headers(0, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/"),
            (b"content-length", b"9"),
        ], end_stream=False)
        client.http.send_data(0, b"test", end_stream=False)
        client.transmit()
        await asyncio.wait_for(client.ping(), 2)
        assert not lower.done()

        # At most 16 ordinary requests plus the held request are active. The
        # absolute stream id crosses many windows, so success depends on exact
        # credit return and retention of the independent lower receive state.
        for start in range(0, requests, 16):
            count = min(16, requests - start)
            await asyncio.gather(*(client.request((start + i) % 2 == 0) for i in range(count)))
            assert not lower.done(), "unfinished POST received an early response"
        await asyncio.wait_for(client.ping(), 2)
        assert list(client.pending) == [0]
        assert client._quic._remote_max_streams_bidi >= requests

        client.http.send_data(0, b" body", end_stream=True)
        client.transmit()
        headers, body = await asyncio.wait_for(lower, 10)
        assert (b":status", b"200") in headers and body == BODY
        del client.pending[0]
        # Keep the connection alive after closing the old gap too.
        await asyncio.gather(*(client.request() for _ in range(16)))
        assert not client.pending
        return {
            "requests": requests + 17,
            "exact_responses": requests + 17,
            "advertised_window": 64,
            "max_active_requests": 17,
            "higher_requests_before_stream_0_fin": requests,
            "remote_max_streams_bidi": client._quic._remote_max_streams_bidi,
        }


async def main(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen(
        [args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port),
         "--max-streams", "64"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=deny_uring if args.epoll else None,
    )
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None
        result = await asyncio.wait_for(check(port, args.requests), 120)
        result["epoll"] = args.epoll
        print(json.dumps(result))
    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--requests", type=int, default=100_000)
    parser.add_argument("--epoll", action="store_true")
    args = parser.parse_args()
    assert args.requests >= 128, "must cross the dense-to-sparse threshold"
    asyncio.run(main(args))
