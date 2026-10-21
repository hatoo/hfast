#!/usr/bin/env python3
"""Independent upload-fragment, delayed DATA boundary and half-close checks.

hyper-h2 validates every response, stream and flow-controlled body. Linux TCP
receive queues plus a separate PING witness establish processing before a final
payload byte is released. These checks are not throughput measurements.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = load("h2-flow-control-check")
halfclose = load("tcp-halfclose-check")


def consumed(port, sock):
    deadline = time.monotonic() + 5
    while True:
        state = halfclose.tcp_state(port, sock.getsockname()[1])
        assert state is not None, "connection closed before the final DATA byte"
        if state["rx"] == 0:
            break
        assert time.monotonic() < deadline, ("server did not consume partial DATA", state)
        time.sleep(.002)
    # Force a round trip through the worker after the original receive left
    # the kernel. The original connection must still be open and silent.
    witness = flow.Peer(port)
    witness.close()
    assert not select.select([sock], [], [], 0)[0], "unexpected output/EOF before final byte"


def uploads(port, fragmented, blocked):
    peer = flow.Peer(port, initial=0 if blocked else 65535, fragmented=fragmented)
    try:
        stream = peer.request(post=True)
        peer.exchange()
        peer.expect(stream, 0 if blocked else 13, not blocked)
        # Legal 16KiB DATA frames stay below the default connection window.
        # Fake frame bytes inside the body must never generate a PING ACK.
        body = (flow.frame(6, 0, b"notframe") * 964)[:16_384]
        assert len(body) == 16_384
        for index in range(3):
            peer.client.send_data(stream, body, end_stream=index == 2)
            wire = peer.client.data_to_send()
            peer.send(wire[:-1])
            consumed(port, peer.sock)
            peer.send(wire[-1:])
            peer.exchange()
            peer.expect(stream, 0 if blocked else 13, not blocked)
        if blocked:
            peer.grant(13, stream)
            peer.exchange()
            peer.expect(stream, 13, True)
        # DATA completion cannot invent another response or consume the next
        # request header; a new stream must still complete exactly once.
        fresh = peer.request()
        if blocked:
            peer.grant(13, fresh)
        peer.exchange()
        peer.expect(fresh, 13, True)
        assert len(peer.states) == 2
        return dict(case="upload", fragmented=fragmented, blocked=blocked,
                    upload_bytes=3 * len(body), responses=2)
    finally:
        peer.close()


def delayed_interleaving(port, fragmented, size):
    peer = flow.Peer(port, fragmented=fragmented)
    try:
        # This field block lacks END_HEADERS. The current parser closes only
        # once the interleaved frame is complete, including its final byte.
        peer.send(flow.frame(1, 1, b"\x83\x86\x84"))
        consumed(port, peer.sock)
        wire = flow.frame(0, 1, bytes(size), flags=1)
        peer.send(wire[:-1])
        consumed(port, peer.sock)
        peer.send(wire[-1:])
        try:
            assert peer.sock.recv(1) == b"", "invalid interleaving produced output"
        except ConnectionResetError:
            pass
        return dict(case="interleaving", fragmented=fragmented, payload_bytes=size,
                    closed_after_final_byte=True)
    finally:
        peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(args.binary.resolve()), "--tcp", str(port),
                                   "--quic", "0", "--threads", str(args.threads)],
                                  stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline
                    time.sleep(.02)
            results = [uploads(port, fragmented, blocked)
                       for fragmented in [False, True] for blocked in [False, True]]
            results += [delayed_interleaving(port, fragmented, size)
                        for fragmented in [False, True] for size in [0, 1, 16_384]]
            tail = flow.frame(0, 1, bytes(16_384))[:-1]
            # 131072 responses plus a partial upload force output backpressure
            # before FIN; every response and the final EOF are decoded exactly.
            results.append(halfclose.h2_case(port, halfclose.COUNT, tail, "data-eof-backpressure"))
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
