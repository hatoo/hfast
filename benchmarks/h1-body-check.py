#!/usr/bin/env python3
"""Raw TCP checks for complete HTTP/1 request bodies, pipelines and teardown.

No timing from this fixture is performance evidence. TCP can coalesce writes;
the unit tests separately exhaust receive boundaries inside the decoder.
"""

import argparse
import json
import select
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path


RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 13\r\n\r\nHello, World!")
GET = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"


def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def replies(sock, count):
    expected = RESPONSE * count
    data = bytearray()
    while len(data) < len(expected):
        part = sock.recv(len(expected) - len(data))
        assert part, "EOF before all responses"
        data.extend(part)
    assert data == expected, "response content or count changed"


def quiet(sock):
    assert not select.select([sock], [], [], 0.03)[0], "premature or duplicate response"


def fragmented(sock, wire):
    at = 0
    sizes = [1, 3, 53, 4096, 16384]
    i = 0
    while at < len(wire):
        part = wire[at:at + sizes[i % len(sizes)]]
        sock.sendall(part)
        at += len(part)
        i += 1


def body_case(port, size, split):
    pattern = b"GET /inside-body HTTP/1.1\r\n\r\n\0\xff"
    body = (pattern * (size // len(pattern) + 1))[:size]
    head = f"POST / HTTP/1.1\r\nContent-Length: {size}\r\n\r\n".encode()
    at = {"first": 1, "last": len(head) - 1, "whole": len(head)}[split]
    with connect(port) as sock:
        sock.sendall(GET + head[:at])
        replies(sock, 1)
        if at < len(head):
            quiet(sock)
        fragmented(sock, head[at:] + body[:-1])
        if size:
            quiet(sock)
        # The last byte and following headers share a write. The third request
        # has its own delayed body, so completion cannot leak between requests.
        tail = b"POST /tail HTTP/1.1\r\nContent-Length: 2\r\n\r\nx"
        sock.sendall(body[-1:] + GET + tail)
        replies(sock, 2)
        quiet(sock)
        sock.sendall(b"y" + GET)
        replies(sock, 2)
        quiet(sock)
    return {"size": size, "header_split": split, "responses": 5}


def pipeline(port):
    wire = bytearray()
    for i in range(257):
        body = b"body\r\n\r\nGET /not-a-request\r\n\r\n" * (i % 33)
        wire.extend(f"POST / HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n".encode())
        wire.extend(body)
    with connect(port) as sock:
        fragmented(sock, wire)
        replies(sock, 257)
        quiet(sock)
    return {"pipelined_responses": 257}


def closed_without_response(sock):
    try:
        assert sock.recv(1024) == b"", "responded to an incomplete or invalid request"
    except ConnectionResetError:
        pass


def teardown(port, overflow):
    abandoned = [b"POST / HTTP/1.1\r\nContent-Len",
                 b"POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\nshort"]
    for wire in abandoned:
        with connect(port) as sock:
            fragmented(sock, wire)
            quiet(sock)
            sock.shutdown(socket.SHUT_WR)
            closed_without_response(sock)
        with connect(port) as sock:
            fragmented(sock, GET)
            replies(sock, 1)
    lengths = ["", "-1", "+1", "1x"]
    if overflow:
        maximum = (1 << (struct.calcsize("P") * 8)) - 1
        lengths.extend([str(maximum), str(maximum) + "0"])
    for length in lengths:
        with connect(port) as sock:
            fragmented(sock, f"POST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\n".encode())
            closed_without_response(sock)
        with connect(port) as sock:
            sock.sendall(GET)
            replies(sock, 1)
    return {"abandoned": len(abandoned), "invalid": len(lengths),
            "replacement_responses": len(abandoned) + len(lengths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--skip-overflow", action="store_true",
                        help="compare ordinary behavior with historical binaries")
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(args.binary.resolve()), "--tcp", str(port),
                                   "--quic", "0", "--threads", "1"],
                                  stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None, "server exited during startup"
                try:
                    with connect(port):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "server did not start"
                    time.sleep(0.02)
            results = [body_case(port, size, split)
                       for size in [0, 1, 1024, 1048576]
                       for split in ["first", "last", "whole"]]
            results.extend([pipeline(port), teardown(port, not args.skip_overflow)])
            assert server.poll() is None
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
