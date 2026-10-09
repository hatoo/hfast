#!/usr/bin/env python3
"""Independent hyper-h2 checks for request header blocks spanning frames.

A trailing PING ACK proves the server processed the whole batch: missing
responses fail immediately, without relying on a request timeout. No timings
from this fixture are performance evidence.
"""

import argparse
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
from hyperframe.frame import ContinuationFrame, Frame


BODY = b"Hello, World!"
REQUEST_BODY = b"test body"


def frames(wire):
    result = []
    at = 0
    while at < len(wire):
        frame, length = Frame.parse_frame_header(memoryview(wire[at:at + 9]))
        frame.parse_body(memoryview(wire[at + 9:at + 9 + length]))
        result.append(frame)
        at += 9 + length
    assert at == len(wire)
    return result


def send(sock, wire, fragmented):
    if not fragmented:
        sock.sendall(wire)
        return
    at = 0
    # Exercise frame headers, payload boundaries and TCP receive carry. The
    # Rust tests exhaust every split; TCP may coalesce these application writes.
    sizes = [1, 8, 9, 53, 16384, 4096]
    while at < len(wire):
        for size in sizes:
            part = wire[at:at + size]
            if part:
                sock.sendall(part)
            at += len(part)


class Peer:
    def __init__(self, port, fragmented):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.fragmented = fragmented
        self.client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        self.client.initiate_connection()
        send(self.sock, self.client.data_to_send(), fragmented)
        self.barrier = 0
        self.responses = 0
        self.continuations = 0

    def request(self, post, large, empty_fragments=False):
        stream = self.client.get_next_available_stream_id()
        headers = [
            (b":method", b"POST" if post else b"GET"),
            (b":scheme", b"http"),
            (b":authority", b"localhost"),
            (b":path", b"/continuations"),
        ]
        if large:
            headers.append((b"x-large", b"!" * 50000))
        if post:
            headers.append((b"content-length", str(len(REQUEST_BODY)).encode()))
        self.client.send_headers(stream, headers, end_stream=not post)
        encoded = frames(self.client.data_to_send())
        if large:
            assert encoded[0].type == 1 and "END_HEADERS" not in encoded[0].flags
            assert sum(f.type == 9 for f in encoded) >= 2
        else:
            assert len(encoded) == 1 and "END_HEADERS" in encoded[0].flags
        if empty_fragments:
            # Empty intermediate and final fragments are both valid. Retain
            # the independent encoder's HPACK bytes exactly.
            assert large
            encoded.insert(1, ContinuationFrame(stream))
            encoded[-1].flags.remove("END_HEADERS")
            encoded.append(ContinuationFrame(stream, flags=["END_HEADERS"]))
        self.continuations += sum(f.type == 9 for f in encoded)
        wire = b"".join(f.serialize() for f in encoded)
        if post:
            self.client.send_data(stream, REQUEST_BODY[:4])
            wire += self.client.data_to_send()
        return stream, wire

    def exchange(self, wire, expected):
        self.barrier += 1
        token = self.barrier.to_bytes(8, "big")
        self.client.ping(token)
        send(self.sock, wire + self.client.data_to_send(), self.fragmented)
        bodies = {stream: bytearray() for stream in expected}
        responses, ended = [], []
        ack = False
        while not ack:
            data = self.sock.recv(65536)
            assert data, "EOF before the processing barrier"
            for event in self.client.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    assert event.stream_id in bodies
                    assert event.stream_id not in responses, "duplicate response"
                    headers = dict(event.headers)
                    assert headers[b":status"] == b"200"
                    assert headers[b"content-length"] == b"13"
                    assert headers[b"content-type"] == b"text/plain"
                    responses.append(event.stream_id)
                elif isinstance(event, h2.events.DataReceived):
                    assert event.stream_id in responses
                    bodies[event.stream_id].extend(event.data)
                    self.client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    assert event.stream_id not in ended, "duplicate stream completion"
                    ended.append(event.stream_id)
                elif isinstance(event, h2.events.PingAckReceived):
                    assert event.ping_data == token
                    ack = True
                elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                    raise AssertionError(event)
            pending = self.client.data_to_send()
            if pending:
                send(self.sock, pending, self.fragmented)
        assert responses == expected and ended == expected, {
            "expected": expected, "responses": responses, "ended": ended,
            "missing": sorted(set(expected) - set(ended)), "ping_ack": True,
        }
        assert all(bytes(body) == BODY for body in bodies.values())
        self.responses += len(ended)

    def close(self):
        self.sock.close()


def check(port, post, fragmented):
    peer = Peer(port, fragmented)
    try:
        for _ in range(2):
            requests = [peer.request(post, large=i != 0, empty_fragments=i % 3 == 2)
                        for i in range(17)]
            streams = [stream for stream, _ in requests]
            peer.exchange(b"".join(wire for _, wire in requests), streams)
            if post:
                # The existing early response policy is preserved. Completing
                # the request bodies must not emit another response.
                for stream in streams:
                    peer.client.send_data(stream, REQUEST_BODY[4:], end_stream=True)
                peer.exchange(peer.client.data_to_send(), [])
        peer.exchange(b"", [])
        return {"method": "POST" if post else "GET", "fragmented": fragmented,
                "responses": peer.responses, "continuations": peer.continuations}
    finally:
        peer.close()


def abandoned_connection(port):
    # An incomplete block (including a partial frame) dies with its connection.
    peer = Peer(port, True)
    try:
        _, wire = peer.request(False, True)
        first_size = 9 + int.from_bytes(wire[:3], "big")
        send(peer.sock, wire[:first_size + 5], True)
        peer.sock.shutdown(socket.SHUT_WR)
    finally:
        peer.close()
    replacement = Peer(port, True)
    try:
        stream, wire = replacement.request(False, False)
        replacement.exchange(wire, [stream])
        return {"abandoned_reconnect_responses": replacement.responses}
    finally:
        replacement.close()


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
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "server did not start"
                    time.sleep(0.02)
            results = [check(port, post, fragmented)
                       for fragmented in [False, True] for post in [False, True]]
            results.extend(abandoned_connection(port) for _ in range(4))
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
