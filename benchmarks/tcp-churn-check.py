#!/usr/bin/env python3
"""Exact replies while ready connections span batches and abandoned fds are reused.

No throughput claims: each wave leaves responses queued while other connections
abandon partial H1 headers/H2 prefaces and are replaced with fresh H1 connections.
Per-connection request counts change so stale output cannot pass as a new reply.
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
REQUEST = b"GET /churn HTTP/1.1\r\nHost: localhost\r\n\r\n"


def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def check(port):
    sockets = []
    replies = abandoned = 0
    try:
        sockets.extend(connect(port) for _ in range(257))
        for wave in range(6):
            expected = []
            for index, sock in enumerate(sockets):
                count = 1 + (index * 3 + wave * 5) % 7
                if (index + wave) % 3 == 0:
                    # Alternate graceful EOF and resets, with both protocol
                    # discriminators incomplete when the descriptor is retired.
                    partial = b"PRI * HTTP/2.0" if index % 2 else REQUEST[:17]
                    sock.sendall(partial)
                    if index % 2:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                        struct.pack("ii", 1, 0))
                    else:
                        sock.shutdown(socket.SHUT_WR)
                    sock.close()
                    sock = sockets[index] = connect(port)
                    abandoned += 1
                # Leave every connection's output unread until all 257 have
                # queued work, crossing the server's 128-event batch boundary.
                sock.sendall(REQUEST[:3])
                sock.sendall(REQUEST[3:] + REQUEST * (count - 1))
                expected.append(count)
            # Reverse drain order on alternating waves; arrival order must not
            # change which connection owns an output buffer or a rearmed poll.
            order = range(len(sockets)) if wave % 2 else reversed(range(len(sockets)))
            for index in order:
                wanted = RESPONSE * expected[index]
                data = bytearray()
                while len(data) < len(wanted):
                    chunk = sockets[index].recv(len(wanted) - len(data))
                    assert chunk, (wave, index, "EOF before expected replies")
                    data.extend(chunk)
                assert data == wanted, (wave, index, "wrong response bytes/count")
                replies += expected[index]
            assert not select.select(sockets, [], [], .03)[0], "duplicate response or premature EOF"
        return {"connections": len(sockets), "waves": 6, "abandoned_and_replaced": abandoned,
                "exact_responses": replies, "unexpected_bytes": 0}
    finally:
        for sock in sockets:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--threads", type=int, choices=[1, 2], default=1)
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(args.binary.resolve()), "--tcp", str(port),
                                   "--quic", "0", "--threads", str(args.threads)], stdout=log, stderr=log)
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
            print(json.dumps(check(port), indent=2))
            assert server.poll() is None
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
