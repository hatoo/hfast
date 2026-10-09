#!/usr/bin/env python3
"""Correctness under sustained output backpressure; no rate measurements."""

import json
import socket
import subprocess
import sys
import time

import h2.config
import h2.connection
import h2.events

BODY = b"Hello, World!"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n" + BODY
)
REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"


def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=20)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    return sock


def assert_idle(sock):
    sock.settimeout(0.05)
    try:
        extra = sock.recv(1)
    except TimeoutError:
        return
    raise AssertionError(f"unexpected trailing output or EOF: {extra!r}")


def http1(port):
    with connect(port) as sock:
        sent = 0
        received = 0

        def read_to(target):
            nonlocal received
            while received < target * len(RESPONSE):
                data = sock.recv(min(16384, target * len(RESPONSE) - received))
                assert data, "EOF with responses outstanding"
                off = received % len(RESPONSE)
                expected = RESPONSE * ((off + len(data)) // len(RESPONSE) + 1)
                assert data == expected[off : off + len(data)]
                received += len(data)

        # A large fragmented POST also exercises input buffering while responses
        # are pending. Reading only half the replies before appending requests
        # keeps the output occupied across repeated receive/send batches.
        sock.sendall(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 70000\r\n\r\n"
            + b"x" * 33333
        )
        time.sleep(0.01)
        sock.sendall(b"x" * (70000 - 33333) + REQUEST * 79999)
        sent += 80000
        for _ in range(3):
            time.sleep(0.02)
            read_to(sent - 40000)
            sock.sendall(REQUEST * 40000)
            sent += 40000
        read_to(sent)
        # Reuse the same connection after a complete drain.
        sock.sendall(REQUEST * 17)
        sent += 17
        read_to(sent)
        assert_idle(sock)
        return sent


def http2(port):
    with connect(port) as sock:
        client = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        client.initiate_connection()
        client.increment_flow_control_window(2**28)
        sock.sendall(client.data_to_send())
        # Learn the peer's concurrency limit before creating the large flight.
        settings_received = False
        while not settings_received:
            data = sock.recv(16384)
            assert data
            events = client.receive_data(data)
            settings_received = any(
                isinstance(e, h2.events.RemoteSettingsChanged) for e in events
            )
        sock.sendall(client.data_to_send())
        pending = {}
        last_end = -1
        ended = 0
        sent = 0

        pings_sent = 0
        pings_acked = 0

        def send(count, pings=0):
            nonlocal sent, pings_sent
            # PING ACKs supply several MiB of queued output without making the
            # independent client's stream-count scan quadratic in the fixture.
            for _ in range(pings):
                client.ping(pings_sent.to_bytes(8, "big"))
                pings_sent += 1
                if pings_sent % 1024 == 0:
                    sock.sendall(client.data_to_send())
            for _ in range(count):
                stream = client.get_next_available_stream_id()
                client.send_headers(
                    stream,
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"http"),
                        (b":authority", b"localhost"),
                        (b":path", b"/"),
                    ],
                    end_stream=True,
                )
                pending[stream] = [False, bytearray()]
                sent += 1
                if sent % 1024 == 0:
                    sock.sendall(client.data_to_send())
            data = client.data_to_send()
            if data:
                sock.sendall(data)

        def read_to(target, ping_target):
            nonlocal ended, last_end, pings_acked
            while ended < target or pings_acked < ping_target:
                data = sock.recv(16384)
                assert data, "EOF with streams outstanding"
                for event in client.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        record = pending[event.stream_id]
                        assert not record[0], "duplicate headers"
                        assert (b":status", b"200") in event.headers
                        assert (b"content-length", b"13") in event.headers
                        record[0] = True
                    elif isinstance(event, h2.events.DataReceived):
                        pending[event.stream_id][1].extend(event.data)
                        client.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        headers, body = pending.pop(event.stream_id)
                        assert headers and bytes(body) == BODY
                        assert event.stream_id == last_end + 2
                        last_end = event.stream_id
                        ended += 1
                    elif isinstance(event, h2.events.PingAckReceived):
                        assert event.ping_data == pings_acked.to_bytes(8, "big")
                        pings_acked += 1
                    elif isinstance(
                        event, (h2.events.StreamReset, h2.events.ConnectionTerminated)
                    ):
                        raise AssertionError(event)
                data = client.data_to_send()
                if data:
                    sock.sendall(data)

        send(256, 262144)
        for _ in range(2):
            time.sleep(0.02)
            read_to(0, pings_sent - 131072)
            send(256, 131072)
        read_to(sent, pings_sent)
        send(17)
        read_to(sent, pings_sent)
        assert not pending and pings_acked == pings_sent
        assert_idle(sock)
        return {"responses": ended, "ping_acks": pings_acked}


def main():
    # Reserve a currently free port; the child listener binds it next.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen(
        [sys.argv[1], "--threads", "1", "--tcp", str(port), "--quic", "0"],
        stdout=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            assert server.poll() is None, "server exited before listening"
            try:
                with connect(port):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        counts = {"http1": http1(port), "http2": http2(port)}
        # Repeated closes and accepts check that a reused descriptor never
        # receives a previous connection's buffered output.
        for _ in range(64):
            with connect(port) as sock:
                sock.sendall(REQUEST * 4)
                data = bytearray()
                while len(data) < 4 * len(RESPONSE):
                    part = sock.recv(4 * len(RESPONSE) - len(data))
                    assert part
                    data.extend(part)
                assert data == RESPONSE * 4
        counts["reconnect_http1"] = 256
        print(json.dumps(counts), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    main()
