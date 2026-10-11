#!/usr/bin/env python3
"""Exact TCP progress when all input is queued before the worker resumes.

The client finishes writing >16 KiB per socket while the server is stopped, then
sends no more application data until every response is verified. Reading only a
single chunk per readiness notification can strand the rest. Hundreds of sockets
also cross both io_uring queue sizes. This fixture makes no timing claims.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import time

RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 13\r\n\r\nHello, World!")
GET = b"GET /buffered HTTP/1.1\r\nHost: localhost\r\n\r\n"


def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def queued(port):
    queues = {}
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[1].split(":")[1], 16) == port and fields[3] == "01":
            peer = int(fields[2].split(":")[1], 16)
            queues[peer] = int(fields[4].split(":")[1], 16)
    return queues


def exact(sock, count):
    wanted = RESPONSE * count
    data = bytearray()
    while len(data) < len(wanted):
        chunk = sock.recv(len(wanted) - len(data))
        assert chunk, "EOF before all buffered requests were answered"
        data.extend(chunk)
    assert data == wanted, "incorrect, duplicated, or missing response bytes"


def check(server, port):
    sockets = []
    stopped = False
    try:
        sockets.extend(connect(port) for _ in range(257))
        # Establish protocol state and ensure every socket was accepted.
        for sock in sockets:
            sock.sendall(GET)
        for sock in sockets:
            exact(sock, 1)
        os.kill(server.pid, signal.SIGSTOP)
        stopped = True
        pid, status = os.waitpid(server.pid, os.WUNTRACED)
        assert pid == server.pid and os.WIFSTOPPED(status)
        expected = {}
        replies = 0
        for index, sock in enumerate(sockets):
            body = b"x" * (32769 + index)
            count = 601 + index % 5
            payload = (b"POST /buffered HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                       + str(len(body)).encode() + b"\r\n\r\n" + body + GET * (count - 1))
            sock.sendall(payload)
            expected[sock.getsockname()[1]] = len(payload)
            replies += count
        # Prove the bytes are already in each kernel receive queue, rather than
        # relying on a delay or on the sender having copied them to its own queue.
        deadline = time.monotonic() + 10
        while True:
            observed = queued(port)
            if all(observed.get(peer, 0) == size for peer, size in expected.items()):
                break
            assert time.monotonic() < deadline, ("input was not fully queued", observed, expected)
            time.sleep(.01)
        os.kill(server.pid, signal.SIGCONT)
        stopped = False
        # No further writes, shutdowns, or closes until all buffered replies.
        for index in reversed(range(len(sockets))):
            exact(sockets[index], 601 + index % 5)
        assert not select.select(sockets, [], [], .03)[0], "extra response or EOF"
        # An actual new edge must still work after the local drain reached EAGAIN.
        for sock in sockets:
            sock.sendall(GET)
        for sock in sockets:
            exact(sock, 1)
        assert not select.select(sockets, [], [], .03)[0], "extra follow-up response or EOF"
        return {"connections": len(sockets), "queued_request_bytes": sum(expected.values()),
                "minimum_queued_bytes_per_socket": min(expected.values()),
                "buffered_exact_responses": replies, "setup_and_followup_responses": 514,
                "unexpected_bytes": 0}
    finally:
        if stopped:
            os.kill(server.pid, signal.SIGCONT)
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
                    assert time.monotonic() < deadline
                    time.sleep(.01)
            print(json.dumps(check(server, port), indent=2))
            assert server.poll() is None
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
