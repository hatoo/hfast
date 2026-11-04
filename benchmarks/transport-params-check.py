#!/usr/bin/env python3
"""Independent encrypted-handshake oracle; correctness only, no rate claims."""

import argparse
import json
import socket
import ssl
import subprocess
import time
from pathlib import Path

from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


def check(port, suffix, *, drop_first=False, replay=False):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], initial_rtt=0.05)
    config.verify_mode = ssl.CERT_NONE
    quic = QuicConnection(configuration=config)
    original = quic._serialize_transport_parameters
    # aioquic 1.3.0 is pinned in interop-requirements.txt. Keep its ordinary
    # transport declarations and append an opaque extension to the TLS input.
    quic._serialize_transport_parameters = lambda: original() + suffix
    http = H3Connection(quic)
    target = ("127.0.0.1", port)
    valid = suffix in (b"", b"\x3f\x03\xff\xff\xff\x3e\x00")
    handshake = False
    response = bytearray()
    status = []
    dropped = False
    initial = None
    replayed = False
    server_packets = 0
    end = time.monotonic() + 6
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        quic.connect(target, now=time.monotonic())
        while time.monotonic() < end:
            now = time.monotonic()
            for data, addr in quic.datagrams_to_send(now=now):
                if initial is None:
                    initial = data
                sock.sendto(data, addr)
            timer = quic.get_timer()
            sock.settimeout(max(0.001, min(0.05, (timer or end) - now)))
            try:
                data, addr = sock.recvfrom(65536)
            except socket.timeout:
                data = None
            now = time.monotonic()
            if data is not None:
                server_packets += 1
                if drop_first and not dropped:
                    dropped = True
                else:
                    quic.receive_datagram(data, addr, now=now)
                if replay and not replayed:
                    # Keep the original destination ID and encrypted packet
                    # number, independently of aioquic's retry machinery.
                    sock.sendto(initial, target)
                    replayed = True
            timer = quic.get_timer()
            if timer is not None and timer <= now:
                quic.handle_timer(now=now)
            while (event := quic.next_event()) is not None:
                if isinstance(event, HandshakeCompleted):
                    handshake = True
                    assert valid, "malformed parameters completed a TLS handshake"
                    http.send_headers(0, [
                        (b":method", b"GET"), (b":scheme", b"https"),
                        (b":authority", b"localhost"), (b":path", b"/"),
                    ], end_stream=True)
                if isinstance(event, ConnectionTerminated):
                    assert not valid, event
                    assert not handshake
                    assert event.error_code == 0x08, event
                    assert event.frame_type == 0, event
                    assert not drop_first or (dropped and server_packets >= 2)
                    assert not replay or replayed
                    return dict(error_code=event.error_code, handshake=False,
                                server_datagrams=server_packets, dropped=dropped,
                                replayed=replayed)
                for ev in http.handle_event(event):
                    if isinstance(ev, HeadersReceived):
                        status.extend(ev.headers)
                    if isinstance(ev, DataReceived):
                        response.extend(ev.data)
                        if ev.stream_ended:
                            assert valid and handshake
                            assert (b":status", b"200") in status
                            assert response == b"Hello, World!"
                            quic.close()
                            for packet, addr in quic.datagrams_to_send(now=now):
                                sock.sendto(packet, addr)
                            return dict(handshake=True, status=200, body_bytes=len(response))
    raise AssertionError("handshake rejection or valid response timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    cases = [("valid", b"", {}),
             ("valid-unknown", b"\x3f\x03\xff\xff\xff\x3e\x00", {}),
             ("truncated-body", b"\x3f\x03\x01", {}),
             ("truncated-id", b"\x40", {}),
             ("missing-length", b"\x3f", {}),
             ("truncated-integer", b"\x03\x01\x40", {}),
             ("empty-integer", b"\x03\x00", {}),
             ("lost-close-replay", b"\x03\x01\x40", dict(drop_first=True, replay=True))]
    server = subprocess.Popen([str(args.binary.resolve()), "--threads", "1", "--tcp", "0",
                               "--quic", str(port)], stdout=subprocess.DEVNULL)
    rows = []
    try:
        time.sleep(0.15)
        assert server.poll() is None
        for name, suffix, options in cases:
            result = check(port, suffix, **options)
            rows.append(dict(case=name, **result))
            print("PASS", name, result, flush=True)
        # Rejecting earlier peers must not contaminate subsequent handshakes.
        rows.append(dict(case="valid-after-rejections", **check(port, b"")))
        assert server.poll() is None
    finally:
        server.terminate()
        server.wait(timeout=5)
    if args.json:
        with args.json.open("x") as output:
            json.dump(rows, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    main()
