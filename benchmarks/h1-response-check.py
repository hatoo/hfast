#!/usr/bin/env python3
"""Check exact pipelined responses, incomplete suffixes and socket backpressure."""

import argparse
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


spec = importlib.util.spec_from_file_location(
    "body", Path(__file__).with_name("h1-body-check.py"))
body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(body)


def pipelines(port):
    total = 0
    tail = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"
    for count in [1, 2, 63, 64, 65, 127, 128, 129, 4096]:
        with body.connect(port) as sock:
            sock.sendall(body.GET * count + tail)
            body.replies(sock, count)
            body.quiet(sock)
            sock.sendall(b"c" + body.GET * count + b"GET / HTTP/1.1\r")
            body.replies(sock, count + 1)
            body.quiet(sock)
            sock.sendall(b"\n\r\n")
            body.replies(sock, 1)
            body.quiet(sock)
            total += count * 2 + 2
    return {"pipeline_responses": total}


def backpressure(port):
    count = 131072
    errors = []
    with body.connect(port) as sock:
        sock.settimeout(15)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

        def send():
            try:
                # More response data than the socket can buffer while reads
                # are withheld. Concurrent sending avoids a client deadlock.
                sock.sendall(body.GET * count)
            except BaseException as error:
                errors.append(error)

        sender = threading.Thread(target=send)
        sender.start()
        try:
            time.sleep(0.1)
            with body.connect(port) as probe:
                probe.sendall(body.GET)
                body.replies(probe, 1)
            body.replies(sock, count)
            sender.join(timeout=15)
            assert not sender.is_alive(), "sender stalled"
            assert not errors, errors
            body.quiet(sock)
            sock.sendall(body.GET * 65)
            body.replies(sock, 65)
            body.quiet(sock)
        finally:
            if sender.is_alive():
                sock.shutdown(socket.SHUT_RDWR)
                sender.join(timeout=5)
    return {"backpressure_responses": count + 66,
            "response_bytes_before_reuse": len(body.RESPONSE) * count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen(
            [str(args.binary.resolve()), "--tcp", str(port), "--quic", "0",
             "--threads", "1"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None, "server exited during startup"
                try:
                    with body.connect(port):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "server did not start"
                    time.sleep(0.02)
            results = [pipelines(port), backpressure(port)]
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
