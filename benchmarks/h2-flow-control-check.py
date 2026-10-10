#!/usr/bin/env python3
"""Independent hyper-h2 response-credit checks; PING barriers prove blocking.

Never acknowledge DATA implicitly: each test controls both receive windows.
hyper-h2 validates flow control, HPACK, content length and stream completion.
These checks are correctness evidence, not throughput measurements.
"""

import argparse
import json
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import h2.settings
import hpack
from hyperframe.frame import Frame

BODY = b"Hello, World!"


def frame(kind, stream, payload, flags=0):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


class Peer:
    def __init__(self, port, initial=65535, fragmented=False):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        self.fragmented = fragmented
        self.states = {}
        self.sequence = 0
        self.settings_acks = 0
        self.client.initiate_connection()
        self.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: initial})
        self.exchange()
        assert self.settings_acks == 2

    def send(self, wire):
        if not self.fragmented:
            self.sock.sendall(wire)
            return
        at = 0
        sizes = [1, 8, 9, 53, 4096, 16384]
        while at < len(wire):
            for size in sizes:
                part = wire[at:at + size]
                if part:
                    self.sock.sendall(part)
                    at += len(part)

    def request(self, large=False, post=False):
        stream = self.client.get_next_available_stream_id()
        fields = [(b":method", b"POST" if post else b"GET"),
                  (b":scheme", b"http"), (b":authority", b"localhost"),
                  (b":path", b"/credit")]
        if large:
            fields.append((b"x-large", b"!" * 50000))
        self.client.send_headers(stream, fields, end_stream=not post)
        self.states[stream] = dict(headers=False, body=bytearray(), ended=False, reset=None)
        return stream

    def exchange(self, extra=b"", delay=0, expected_error=None):
        self.sequence += 1
        token = self.sequence.to_bytes(8, "big")
        wire = self.client.data_to_send() + extra
        if expected_error is None:
            self.client.ping(token)
        self.send(wire + self.client.data_to_send())
        if delay:
            time.sleep(delay)
        ack = False
        errors = []
        while not ack:
            wire = self.sock.recv(65536)
            if not wire:
                assert expected_error is not None and errors == [expected_error], errors
                return
            for event in self.client.receive_data(wire):
                if isinstance(event, h2.events.ResponseReceived):
                    state = self.states[event.stream_id]
                    assert not state["headers"], "duplicate response"
                    fields = dict(event.headers)
                    assert fields[b":status"] == b"200"
                    assert fields[b"content-length"] == b"13"
                    assert fields[b"content-type"] == b"text/plain"
                    state["headers"] = True
                elif isinstance(event, h2.events.DataReceived):
                    state = self.states[event.stream_id]
                    assert state["headers"] and not state["ended"]
                    assert event.flow_controlled_length == len(event.data)
                    state["body"].extend(event.data)
                    assert BODY.startswith(state["body"])
                elif isinstance(event, h2.events.StreamEnded):
                    state = self.states[event.stream_id]
                    assert not state["ended"] and state["body"] == BODY
                    state["ended"] = True
                elif isinstance(event, h2.events.SettingsAcknowledged):
                    self.settings_acks += 1
                elif isinstance(event, h2.events.StreamReset):
                    self.states[event.stream_id]["reset"] = int(event.error_code)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    assert expected_error is not None, event
                    errors.append(int(event.error_code))
                    assert event.last_stream_id == max(self.states, default=0)
                elif isinstance(event, h2.events.PingAckReceived):
                    assert event.ping_data == token
                    ack = True
            pending = self.client.data_to_send()
            if pending:
                self.send(pending)

    def expect(self, stream, length, ended=False):
        state = self.states[stream]
        assert state["headers"] and state["body"] == BODY[:length], state
        assert state["ended"] == ended, state
        assert state["reset"] is None, state

    def grant(self, amount, stream=None):
        self.client.increment_flow_control_window(amount, stream_id=stream)

    def close(self):
        self.sock.close()


def stream_zero(port, fragmented):
    peer = Peer(port, initial=0, fragmented=fragmented)
    try:
        stream = peer.request(large=fragmented)
        peer.exchange()
        peer.expect(stream, 0)
        peer.grant(1, stream)
        peer.exchange()
        peer.expect(stream, 1)
        peer.grant(12, stream)
        peer.exchange()
        peer.expect(stream, 13, True)
        return {"case": "stream-zero", "fragmented": fragmented, "replies": 1}
    finally:
        peer.close()


def connection_credit(port, fragmented):
    peer = Peer(port, fragmented=fragmented)
    try:
        streams = []
        # 5,041 complete bodies consume 65,533 bytes; the next gets only 2.
        for start in range(0, 5050, 128):
            streams.extend(peer.request() for _ in range(min(128, 5050 - start)))
            peer.exchange()
        for stream in streams[:5041]:
            peer.expect(stream, 13, True)
        peer.expect(streams[5041], 2)
        for stream in streams[5042:]:
            peer.expect(stream, 0)
        assert peer.client.inbound_flow_control_window == 0
        # Stream credit cannot release a connection-blocked response.
        peer.grant(10, streams[-1])
        peer.exchange()
        peer.expect(streams[-1], 0)
        peer.grant(1)
        peer.exchange()
        peer.expect(streams[5041], 3)
        peer.grant(5050 * 13 - 65536)
        peer.exchange()
        for stream in streams:
            peer.expect(stream, 13, True)
        assert peer.client.inbound_flow_control_window == 0
        # With the connection still blocked, stream credit cannot be consumed
        # before the next overflowing update is checked.
        overflow = peer.request()
        peer.exchange()
        peer.expect(overflow, 0)
        peer.exchange(frame(8, overflow, (0x7fffffff).to_bytes(4, "big")))
        assert peer.states[overflow]["reset"] == 3
        return {"case": "connection", "fragmented": fragmented, "replies": len(streams)}
    finally:
        peer.close()


def settings_and_resets(port, fragmented):
    peer = Peer(port, initial=5, fragmented=fragmented)
    try:
        a = peer.request(post=True)
        b = peer.request(large=True)
        c = peer.request()
        peer.exchange()
        for stream in [a, b, c]:
            peer.expect(stream, 5)
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peer.exchange()
        assert peer.settings_acks == 3
        peer.grant(5, a)  # -5 -> 0, still blocked
        peer.grant(13, b)  # -5 -> 8, later stream is eligible first
        peer.client.reset_stream(c)
        # Trailers must not produce another response or reset a's send window.
        peer.client.send_headers(a, [(b"x-trailer", b"done")], end_stream=True)
        peer.exchange()
        peer.expect(a, 5)
        peer.expect(b, 13, True)
        before = peer.client.inbound_flow_control_window
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 8})
        peer.exchange()
        assert peer.settings_acks == 4
        peer.expect(a, 13, True)
        assert peer.states[c]["body"] == BODY[:5] and not peer.states[c]["ended"]
        assert peer.client.inbound_flow_control_window == before - 8
        fresh = peer.request()
        peer.exchange()
        peer.expect(fresh, 8)
        peer.grant(5, fresh)
        peer.exchange()
        peer.expect(fresh, 13, True)
        return {"case": "settings-reset-trailers", "fragmented": fragmented,
                "replies": 3, "cancelled_partial": 1}
    finally:
        peer.close()


def invalid_updates(port, fragmented):
    results = []
    peer = Peer(port, initial=0, fragmented=fragmented)
    try:
        a, b = peer.request(), peer.request()
        peer.exchange()
        peer.exchange(frame(8, a, bytes(4)))
        assert peer.states[a]["reset"] == 1
        peer.grant(13, b)
        peer.exchange()
        peer.expect(b, 13, True)
        results.append({"stream_zero_increment": "RST_STREAM PROTOCOL_ERROR"})
    finally:
        peer.close()
    invalid = [
        (frame(8, 0, bytes(4)), 1),
        (frame(8, 0, (0x7fffffff).to_bytes(4, "big")), 3),
        (frame(8, 0, bytes(3)), 6),
        (frame(4, 0, b"\0\4\x80\0\0\0"), 3),
        (frame(4, 0, bytes(5)), 6),
        (frame(4, 0, bytes(6), flags=1), 6),
        (frame(8, 1, (1).to_bytes(4, "big")), 1),
    ]
    for wire, expected in invalid:
        peer = Peer(port, fragmented=fragmented)
        try:
            peer.send(wire)
            errors = []
            while True:
                data = peer.sock.recv(65536)
                if not data:
                    break
                for event in peer.client.receive_data(data):
                    if isinstance(event, h2.events.ConnectionTerminated):
                        errors.append(int(event.error_code))
                        assert event.last_stream_id == 0
            assert errors == [expected], errors
            results.append({"goaway": expected, "eof": True})
        finally:
            peer.close()
    return {"case": "invalid-updates", "fragmented": fragmented, "results": results}


def pending_queue(port, fragmented):
    """Retire/refill a blocked queue, then update both sides of its storage."""
    peer = Peer(port, initial=0, fragmented=fragmented)
    try:
        active = [peer.request() for _ in range(256)]
        peer.exchange()
        replies = cancelled = 0
        for cycle in range(12):
            retiring, active = active[:192], active[192:]
            if cycle % 3 == 1:
                retiring.reverse()
            elif cycle % 3 == 2:
                retiring = retiring[::2] + retiring[1::2]
            for i, stream in enumerate(retiring):
                if i % 7 == 0:
                    peer.client.reset_stream(stream)
                    cancelled += 1
                else:
                    peer.grant(5, stream)
            peer.exchange()
            for i, stream in enumerate(retiring):
                if i % 7 != 0:
                    peer.expect(stream, 5)
                    peer.grant(8, stream)
            peer.exchange()
            for i, stream in enumerate(retiring):
                if i % 7 != 0:
                    peer.expect(stream, 13, True)
                    replies += 1
            active.extend(peer.request() for _ in range(192))
            peer.exchange()
            for stream in active:
                peer.expect(stream, 0)
        # SETTINGS visits all live entries in order, including wrapped storage,
        # and negative credit must survive partial DATA and later reductions.
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 5})
        peer.exchange()
        for stream in active:
            peer.expect(stream, 5)
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peer.exchange()
        for stream in reversed(active):
            peer.grant(13, stream)  # -5 + 13 releases the final eight bytes.
        peer.exchange()
        for stream in active:
            peer.expect(stream, 13, True)
        replies += len(active)
        assert peer.client.inbound_flow_control_window == 65535 - replies * 13
        return {"case": "pending-queue", "fragmented": fragmented,
                "replies": replies, "cancelled": cancelled, "refills": 12}
    finally:
        peer.close()


def connection_trickle(port, fragmented):
    peer = Peer(port, fragmented=fragmented)
    try:
        streams = []
        for start in range(0, 5042, 128):
            streams.extend(peer.request() for _ in range(min(128, 5042 - start)))
            peer.exchange()
        for stream in streams[:-1]:
            peer.expect(stream, 13, True)
        head = streams[-1]
        peer.expect(head, 2)
        assert peer.client.inbound_flow_control_window == 0
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peer.exchange()  # The partial head now has negative stream credit.
        replies = 5041
        cancelled = 0
        for grant in [1, 12, 13, 14]:
            blocked = [peer.request() for _ in range(8)]
            active = [peer.request() for _ in range(64)]
            peer.exchange()
            # With connection credit exhausted, every eligible stream waits.
            for stream in active:
                peer.grant(13, stream)
            peer.exchange()
            sent = 0
            while sent < len(active) * len(BODY):
                amount = min(grant, len(active) * len(BODY) - sent)
                peer.grant(amount)
                peer.exchange()
                sent += amount
                for index, stream in enumerate(active):
                    length = min(13, max(0, sent - index * 13))
                    peer.expect(stream, length, length == 13)
                for stream in blocked:
                    peer.expect(stream, 0)
                assert peer.client.inbound_flow_control_window == 0
            replies += len(active)
            for stream in blocked:
                peer.client.reset_stream(stream)
            cancelled += len(blocked)
            peer.exchange()
            # Retire the negative head after testing the sparse fallback, then
            # repeat the same credit pattern through the ready-front path.
            if head is not None:
                peer.expect(head, 2)
                peer.client.reset_stream(head)
                cancelled += 1
                head = None
            peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 13})
            peer.exchange()
            active = [peer.request() for _ in range(128)]
            peer.exchange()
            # Refill the same queue several times while connection grants
            # retire prefixes, exercising wrapped storage and partial bodies.
            for _ in range(3):
                sent = 0
                while sent < 65 * 13:
                    amount = min(grant, 65 * 13 - sent)
                    peer.grant(amount)
                    peer.exchange()
                    sent += amount
                    for index, stream in enumerate(active):
                        length = min(13, max(0, sent - index * 13))
                        peer.expect(stream, length, length == 13)
                    assert peer.client.inbound_flow_control_window == 0
                replies += 65
                active = active[65:] + [peer.request() for _ in range(65)]
                peer.exchange()
            peer.grant(128 * 13)
            peer.exchange()
            for stream in active:
                peer.expect(stream, 13, True)
            replies += len(active)
            assert peer.client.inbound_flow_control_window == 0
            peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
            peer.exchange()
        return {"case": "connection-trickle", "fragmented": fragmented,
                "replies": replies, "cancelled": cancelled,
                "grants": [1, 12, 13, 14], "refills": 12}
    finally:
        peer.close()


def backpressure(port, fragmented):
    # Complete valid responses exceed the TCP send and receive buffers; queued
    # DATA and GOAWAY must survive partial socket writes. For this large batch,
    # hyperframe/hpack decode the wire directly: hyper-h2's active-stream count
    # scans make constructing 131,072 simultaneously active streams quadratic.
    with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        count = 131072
        headers = hpack.Encoder().encode([(":method", "GET"), (":scheme", "http"),
                                         (":authority", "localhost"), (":path", "/")])
        wire = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, b"")
                + frame(8, 0, (count * 13).to_bytes(4, "big"))
                + b"".join(frame(1, i * 2 + 1, headers, flags=5) for i in range(count))
                + frame(8, 0, bytes(4)))
        failures = []

        def send_batch():
            try:
                sock.sendall(wire)
            except BaseException as error:
                failures.append(error)

        sender = threading.Thread(target=send_batch)
        sender.start()
        try:
            time.sleep(0.1)
            probe = Peer(port)
            try:
                stream = probe.request()
                probe.exchange()
                probe.expect(stream, 13, True)
            finally:
                probe.close()
            decoder = hpack.Decoder()
            carry = bytearray()
            replies = 0
            awaiting_body = False
            settings = []
            goaways = []
            credit = 65535 + count * 13
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                carry.extend(data)
                at = 0
                while len(carry) - at >= 9:
                    received, length = Frame.parse_frame_header(memoryview(bytes(carry[at:at + 9])))
                    if len(carry) - at < 9 + length:
                        break
                    received.parse_body(memoryview(bytes(carry[at + 9:at + 9 + length])))
                    at += 9 + length
                    if received.type == 4:
                        settings.append("ACK" in received.flags)
                    elif received.type == 1:
                        assert not awaiting_body and not goaways
                        assert received.stream_id == replies * 2 + 1
                        assert set(received.flags) == {"END_HEADERS"}
                        assert dict(decoder.decode(received.data)) == {
                            ":status": "200", "content-type": "text/plain", "content-length": "13"}
                        awaiting_body = True
                    elif received.type == 0:
                        assert awaiting_body and not goaways
                        assert received.stream_id == replies * 2 + 1
                        assert set(received.flags) == {"END_STREAM"} and received.data == BODY
                        credit -= length
                        assert credit >= 0 and length <= 65535
                        replies += 1
                        awaiting_body = False
                    elif received.type == 7:
                        assert replies == count and not awaiting_body
                        goaways.append((received.last_stream_id, received.error_code))
                    else:
                        raise AssertionError(received)
                del carry[:at]
            assert not carry and not awaiting_body and replies == count
            assert settings == [False, True] and goaways == [(count * 2 - 1, 1)]
            assert credit == 65535
            sender.join(timeout=15)
            assert not sender.is_alive() and not failures, failures
        finally:
            if sender.is_alive():
                sock.shutdown(socket.SHUT_RDWR)
                sender.join(timeout=5)
        return {"case": "backpressure", "replies": count + 1,
                "goaway_after_bodies": True, "eof": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--case", choices=["stream-zero", "connection", "settings",
                                          "invalid", "pending-queue", "connection-trickle", "backpressure",
                                          "all"], default="all")
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
            checks = {"stream-zero": stream_zero, "connection": connection_credit,
                      "settings": settings_and_resets, "invalid": invalid_updates,
                      "pending-queue": pending_queue,
                      "connection-trickle": connection_trickle,
                      "backpressure": backpressure}
            results = [check(port, fragmented) for name, check in checks.items()
                       if args.case in [name, "all"]
                       for fragmented in ([False] if name == "backpressure" else [False, True])]
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
