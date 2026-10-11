#!/usr/bin/env python3
"""Flush exact HTTP/1 and HTTP/2 replies after input EOF under backpressure.

Raw sockets and an independent HPACK decoder verify every response and EOF.
Linux TCP queue state proves input (including FIN) has been consumed while
output is blocked, before the client starts reading. No throughput claims.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

import hpack


COUNT = 131072
BODY = b"Hello, World!"
GET = b"GET /halfclose HTTP/1.1\r\nHost: localhost\r\n\r\n"
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 13\r\n\r\n" + BODY)
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(kind, stream, payload=b"", flags=0):
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + stream.to_bytes(4, "big") + payload)


def connect(port):
    sock = socket.socket()
    sock.settimeout(15)
    # Set before connect so the initial window cannot absorb all responses.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect(("127.0.0.1", port))
    return sock


def tcp_state(port, peer):
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if (int(fields[1].split(":")[1], 16) == port
                and int(fields[2].split(":")[1], 16) == peer):
            tx, rx = (int(value, 16) for value in fields[4].split(":"))
            return dict(state=fields[3], tx=tx, rx=rx, inode=int(fields[9]))
    return None


def blocked_after_fin(port, sock):
    deadline = time.monotonic() + 15
    while True:
        state = tcp_state(port, sock.getsockname()[1])
        # CLOSE_WAIT is the repaired path; LAST_ACK also permits a broken
        # server to reach the exact-byte assertion instead of timing out here.
        if state and state["state"] in ["08", "09"] and state["rx"] == 0:
            assert state["tx"] > 0, ("output did not face backpressure", state)
            return state
        assert time.monotonic() < deadline, ("input EOF was not consumed", state)
        time.sleep(.01)


def exact_read(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, ("early EOF", len(data), count)
        data.extend(chunk)
    return bytes(data)


def read_frame(sock):
    head = exact_read(sock, 9)
    return (head[3], head[4], int.from_bytes(head[5:], "big"),
            exact_read(sock, int.from_bytes(head[:3], "big")))


def until_eof(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    data = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data.extend(chunk)


def h1_case(port, count, tail, label):
    with connect(port) as sock:
        # A header and body split across writes precede the ordinary pipeline.
        sock.sendall(b"POST /halfclose HTTP/1.1\r\nContent-Len")
        sock.sendall(b"gth: 3\r\n\r\nab")
        sock.sendall(b"c" + GET * (count - 1) + tail)
        sock.shutdown(socket.SHUT_WR)
        state = blocked_after_fin(port, sock) if count == COUNT else None
        data = until_eof(sock)
        assert data == RESPONSE * count, (label, "incorrect replies", len(data), count * len(RESPONSE))
    return dict(case=label, replies=count, bytes=len(data), blocked=state)


def h2_setup(sock):
    # Grant all connection credit up front: no WINDOW_UPDATE is possible after
    # SHUT_WR. Per-stream default credit already covers the 13-byte body.
    sock.sendall(PREFACE + frame(4, 0)
                 + frame(8, 0, (0x7fffffff - 65535).to_bytes(4, "big")))
    kind, flags, stream, settings = read_frame(sock)
    assert (kind, flags, stream) == (4, 0, 0) and len(settings) % 6 == 0
    assert read_frame(sock) == (4, 1, 0, b"")
    sock.sendall(frame(4, 0, flags=1))


def h2_requests(count):
    # Static-table GET/http/root plus literal :authority, without indexing.
    headers = b"\x82\x86\x84\x01\x09localhost"
    return b"".join(frame(1, 2 * i + 1, headers, flags=5) for i in range(count))


def h2_verify(data, count, goaway):
    decoder = hpack.Decoder()
    seen = bytearray(count)
    at = 0
    errors = []
    while at < len(data):
        assert len(data) - at >= 9, ("truncated frame header", at, len(data))
        length = int.from_bytes(data[at:at + 3], "big")
        kind, flags = data[at + 3:at + 5]
        stream = int.from_bytes(data[at + 5:at + 9], "big")
        end = at + 9 + length
        assert end <= len(data), ("truncated frame payload", at, end, len(data))
        payload = data[at + 9:end]
        if kind == 7:
            assert goaway and stream == 0 and flags == 0 and len(payload) >= 8
            assert int.from_bytes(payload[:4], "big") == 2 * count - 1
            errors.append(int.from_bytes(payload[4:8], "big"))
        else:
            assert stream & 1 and 1 <= stream <= 2 * count - 1, (kind, stream)
            index = stream // 2
            if kind == 1:
                assert flags == 4 and seen[index] == 0, ("duplicate or incomplete headers", stream)
                assert decoder.decode(payload, raw=True) == [
                    (b":status", b"200"), (b"content-type", b"text/plain"),
                    (b"content-length", b"13")]
                seen[index] = 1
            else:
                assert kind == 0 and flags == 1 and seen[index] == 1, (kind, flags, stream)
                assert payload == BODY
                seen[index] = 2
        at = end
    assert seen == bytes([2]) * count, ("missing responses", seen.count(2), count)
    assert errors == ([1] if goaway else []), errors


def h2_case(port, count, tail, label, goaway=False):
    with connect(port) as sock:
        h2_setup(sock)
        wire = h2_requests(count)
        sock.sendall(wire[:7])  # Split the first frame header.
        sock.sendall(wire[7:] + tail)
        sock.shutdown(socket.SHUT_WR)
        # A protocol error stops reads before FIN and uses the existing H2
        # closing path; only ordinary EOF cases require FIN consumption.
        state = blocked_after_fin(port, sock) if count == COUNT and not goaway else None
        data = until_eof(sock)
        h2_verify(data, count, goaway)
    return dict(case=label, replies=count, bytes=len(data), blocked=state)


def reset_after_eof(server, port):
    with connect(port) as sock:
        sock.sendall(GET * COUNT)
        sock.shutdown(socket.SHUT_WR)
        state = blocked_after_fin(port, sock)
        inode = state["inode"]
        assert inode, ("server retired a connection with unsent output", state)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    # A reset must retire the server descriptor, even after read EOF. Checking
    # the socket inode avoids mistaking a reused descriptor for a leaked one.
    deadline = time.monotonic() + 5
    while True:
        links = []
        for fd in Path(f"/proc/{server.pid}/fd").iterdir():
            try:
                links.append(os.readlink(fd))
            except FileNotFoundError:
                pass
        if f"socket:[{inode}]" not in links:
            break
        assert time.monotonic() < deadline, "reset left an EOF connection alive"
        time.sleep(.01)
    result = h1_case(port, 257, b"", "replacement-after-reset")
    return dict(case="reset-after-eof", retired_inode=inode, replacement=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--threads", type=int, choices=[1, 2], default=1)
    parser.add_argument("--protocol", choices=["h1", "h2"], help="run one protocol's cases")
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(args.binary.resolve()), "--tcp", str(port), "--quic", "0",
                                   "--threads", str(args.threads)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None, "server exited during startup"
                try:
                    with connect(port):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "server did not start"
                    time.sleep(.01)
            results = []
            if args.protocol != "h2":
                for count, tail, label in [
                    (COUNT, b"", "h1-backpressure"),
                    (COUNT, b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab", "h1-incomplete-body"),
                    (257, b"GET / HTTP/1.1\r\nHost: local", "h1-incomplete-header"),
                ]:
                    results.append(h1_case(port, count, tail, label))
                results.append(reset_after_eof(server, port))
            if args.protocol != "h1":
                results.append(h2_case(port, COUNT, b"", "h2-backpressure"))
                partial = frame(1, 2 * COUNT + 1, b"\x82\x86\x84", flags=5)[:-1]
                results.append(h2_case(port, COUNT, partial, "h2-incomplete-frame"))
                results.append(h2_case(port, COUNT, frame(8, 0, bytes(4)), "h2-goaway", goaway=True))
            assert server.poll() is None, "server exited during checks"
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
