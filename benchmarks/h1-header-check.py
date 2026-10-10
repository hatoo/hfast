#!/usr/bin/env python3
"""Raw TCP regression checks for fragmented HTTP/1 request headers.

No timing here is performance evidence. Unit tests exhaust receive boundaries;
this peer checks delayed completion and error handling through real sockets.
"""

import argparse
import importlib.util
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "body_checks", Path(__file__).with_name("h1-body-check.py"))
body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(body)


def large(port, method, single_line):
    fields = (b"X: " + b"x" * (1 << 20) + b"\r\n" if single_line else
              (b"X: " + b"x" * 61 + b"\r\n") * 16384)
    head = (method + b" / HTTP/1.1\r\n" + fields +
            b"Content-Length: 3\r\nContent-Length: invalid\r\n\r\n")
    with body.connect(port) as sock:
        sock.sendall(body.GET + head[:1])
        body.replies(sock, 1)
        body.quiet(sock)
        body.fragmented(sock, head[1:-1])
        body.quiet(sock)
        sock.sendall(head[-1:])
        if method == b"POST":
            body.quiet(sock)
            sock.sendall(b"ab")
            body.quiet(sock)
            sock.sendall(b"c")
        body.replies(sock, 1)
        body.quiet(sock)
        sock.sendall(body.GET)
        body.replies(sock, 1)
        body.quiet(sock)
    return {"method": method.decode(), "single_line": single_line,
            "header_bytes": len(head), "responses": 3}


def delayed_errors(port):
    for length in [b"", b"-1", b"1x", b"9" * 128]:
        head = b"POST / HTTP/1.1\r\nContent-Length:" + length + b"\r\n"
        with body.connect(port) as sock:
            body.fragmented(sock, head)
            body.quiet(sock)
            sock.sendall(b"X: irrelevant\r\n\r")
            body.quiet(sock)
            sock.sendall(b"\n")
            body.closed_without_response(sock)
        with body.connect(port) as sock:
            sock.sendall(body.GET)
            body.replies(sock, 1)
    return {"delayed_errors": 4, "replacement_responses": 4}


def delimiter_splits(port):
    requests = [b"POST / HTTP/1.1\r\nContent-Length:1\nX: y\r\n\r\nx",
                b"POST / HTTP/1.1\r\nContent-Length:\nContent-Length:2\r\n\r\nxy",
                b"HEAD / HTTP/1.1\r\nContent-Length:invalid\r\n\r\n",
                b"PRINT / HTTP/1.1\r\r\nX: y\r\n\r\n"]
    count = 0
    for wire in requests:
        end = wire.index(b"\r\n\r\n") + 4
        for split in range(end - 3, end):
            with body.connect(port) as sock:
                sock.sendall(wire[:split])
                body.quiet(sock)
                sock.sendall(wire[split:] + body.GET)
                body.replies(sock, 2)
                body.quiet(sock)
                count += 2
    return {"delimiter_split_responses": count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
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
                    with body.connect(port):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "server did not start"
                    time.sleep(0.02)
            results = [large(port, method, single_line)
                       for method in [b"GET", b"HEAD", b"POST"]
                       for single_line in [False, True]]
            results.extend([delayed_errors(port), delimiter_splits(port)])
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
