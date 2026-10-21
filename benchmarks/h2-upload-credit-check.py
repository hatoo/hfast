#!/usr/bin/env python3
"""Independent HTTP/2 request connection-credit and progress regression checks.

hyper-h2 enforces the advertised windows and validates every response. PING ACKs
fence consumed input, including uploads sent after the server's early response.
No timing result is inferred from the old server's exhausted connection window.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import h2.events
import h2.settings


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = load("h2-flow-control-check")
data = load("h2-data-check")


def accounting(peer, sent):
    updates = peer.window_updates
    assert all(stream == 0 and 32768 <= increment <= 65535 for stream, increment in updates), updates
    returned = sum(increment for _, increment in updates)
    assert 0 <= sent - returned < 32768, (sent, returned)
    assert peer.client.outbound_flow_control_window == 65535 + returned - sent
    return returned


def large_uploads(port, fragmented, blocked):
    peer = flow.Peer(port, initial=0 if blocked else 65535, fragmented=fragmented)
    try:
        sent = 0
        streams = []
        # One 1MiB body, followed by 17 bodies on the same connection. None
        # can finish with the old fixed 65535-byte connection receive window.
        body = (flow.frame(6, 0, b"bodyonly") * 964)[:16384]
        assert len(body) == 16384
        for frames in [64] + [3] * 17:
            stream = peer.request(post=True)
            streams.append(stream)
            peer.exchange()
            for index in range(frames):
                peer.client.send_data(stream, body, end_stream=index + 1 == frames)
                sent += len(body)
                # Fence every pair, plus the final odd frame. Every byte
                # precedes a PING and the peer must retain credit to proceed.
                if index % 2 or index + 1 == frames:
                    peer.exchange()
                    accounting(peer, sent)
            peer.expect(stream, 0 if blocked else 13, not blocked)
        assert len(peer.window_updates) == 57
        assert accounting(peer, sent) == 57 * 32768
        # Replenishing request credit never opens a blocked response window.
        if blocked:
            for stream in streams:
                peer.grant(13, stream)
            peer.exchange()
        for stream in streams:
            peer.expect(stream, 13, True)
        return dict(case="large-uploads", fragmented=fragmented, blocked=blocked,
                    uploaded_bytes=sent, returned_credit=accounting(peer, sent),
                    updates=len(peer.window_updates), responses=len(streams))
    finally:
        peer.close()


def boundaries_and_padding(port, fragmented):
    peer = flow.Peer(port, fragmented=fragmented)
    try:
        stream = peer.request(post=True)
        peer.exchange()
        sent = 0
        for size in [16384, 16383, 1, 16384, 16383, 1]:
            peer.client.send_data(stream, bytes(size))
            sent += size
            peer.exchange()
            accounting(peer, sent)
        assert sent == 65536 and peer.window_updates == [(0, 32768), (0, 32768)]
        # Empty DATA consumes no credit; padding consumes all 256 payload
        # bytes even though the application body is empty.
        for _ in range(128):
            peer.client.send_data(stream, b"")
            peer.client.send_data(stream, b"", pad_length=255)
        sent += 32768
        peer.exchange()
        assert peer.window_updates == [(0, 32768)] * 3
        accounting(peer, sent)
        # Non-DATA frames, peer SETTINGS and response WINDOW_UPDATE cannot
        # mint request credit. The 9-byte DATA header is never charged either.
        peer.client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peer.grant(13)
        peer.exchange(flow.frame(0xff, 0, bytes(32768)))
        assert accounting(peer, sent) == sent
        peer.client.send_data(stream, b"", end_stream=True)
        peer.exchange()
        peer.expect(stream, 13, True)
        return dict(case="boundary-padding", fragmented=fragmented,
                    uploaded_bytes=sent, updates=len(peer.window_updates), responses=1)
    finally:
        peer.close()


def small_frames(port):
    peer = flow.Peer(port)
    try:
        stream = peer.request(post=True)
        peer.exchange()
        for _ in range(32767):
            peer.client.send_data(stream, b"x")
        peer.exchange()
        assert peer.window_updates == []
        assert peer.client.outbound_flow_control_window == 32768
        peer.client.send_data(stream, b"x", end_stream=True)
        peer.exchange()
        assert peer.window_updates == [(0, 32768)]
        peer.expect(stream, 13, True)
        return dict(case="small-frames", uploaded_bytes=32768, frames=32768, updates=1, responses=1)
    finally:
        peer.close()


def response_connection_blocked(port):
    peer = flow.Peer(port)
    try:
        streams = []
        for start in range(0, 5042, 128):
            streams.extend(peer.request() for _ in range(min(128, 5042 - start)))
            peer.exchange()
        assert peer.client.inbound_flow_control_window == 0
        peer.expect(streams[-1], 2)
        upload = peer.request(post=True)
        peer.exchange()
        for _ in range(4):
            peer.client.send_data(upload, bytes(16384))
            peer.exchange()
        assert accounting(peer, 65536) == 65536
        peer.expect(streams[-1], 2)
        peer.expect(upload, 0)
        peer.client.send_data(upload, b"", end_stream=True)
        peer.grant(24)
        peer.exchange()
        for stream in streams + [upload]:
            peer.expect(stream, 13, True)
        return dict(case="response-connection-blocked", uploaded_bytes=65536,
                    updates=2, responses=len(streams) + 1)
    finally:
        peer.close()


def delayed_credit_and_eof(port, fragmented):
    peer = flow.Peer(port, fragmented=fragmented)
    try:
        stream = peer.request(post=True)
        peer.exchange()
        peer.client.send_data(stream, bytes(16384))
        peer.exchange()
        peer.client.send_data(stream, bytes(16384))
        wire = peer.client.data_to_send()
        peer.send(wire[:-1])
        data.consumed(port, peer.sock)
        assert peer.window_updates == []
        peer.send(wire[-1:])
        peer.exchange()
        assert peer.window_updates == [(0, 32768)]
        peer.expect(stream, 13, True)
        # Queue another grant, then EOF in an incomplete DATA frame. The
        # complete payload gets credit and that output must drain before EOF.
        for _ in range(2):
            peer.client.send_data(stream, bytes(16384))
        peer.send(peer.client.data_to_send() + flow.frame(0, stream, bytes(16384))[:-1])
        peer.sock.shutdown(socket.SHUT_WR)
        events = []
        while wire := peer.sock.recv(65536):
            events.extend(peer.client.receive_data(wire))
        assert len(events) == 1 and isinstance(events[0], h2.events.WindowUpdated), events
        assert (events[0].stream_id, events[0].delta) == (0, 32768)
        assert peer.client.outbound_flow_control_window == 65535
        return dict(case="delayed-credit-eof", fragmented=fragmented,
                    uploaded_bytes=65536, incomplete_payload=16383, updates=2, responses=1)
    finally:
        peer.close()


def overrun_and_invalid(port, fragmented, case):
    peer = flow.Peer(port, fragmented=fragmented)
    try:
        stream = peer.request(post=True)
        peer.exchange()
        peer.client.send_data(stream, bytes(16384))
        peer.client.send_data(stream, bytes(16383))
        peer.exchange()
        assert peer.window_updates == []
        wire, error = {
            "overrun": (flow.frame(0, stream, bytes(32769)), 3),
            "stream-zero": (flow.frame(0, 0, b"x"), 1),
            "padding": (flow.frame(0, stream, b"\x02\x00", flags=8), 1),
            "missing-pad-length": (flow.frame(0, stream, b"", flags=8), 6),
        }[case]
        peer.send(wire[:-1])
        data.consumed(port, peer.sock)
        peer.exchange(wire[-1:], expected_error=error)
        assert peer.window_updates == []
        peer.expect(stream, 13, True)
        return dict(case=case, fragmented=fragmented, error=error, responses=1)
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
            results = [large_uploads(port, fragmented, blocked)
                       for fragmented in [False, True] for blocked in [False, True]]
            results += [boundaries_and_padding(port, fragmented) for fragmented in [False, True]]
            results += [small_frames(port), response_connection_blocked(port)]
            results += [delayed_credit_and_eof(port, fragmented) for fragmented in [False, True]]
            results += [overrun_and_invalid(port, fragmented, case)
                        for fragmented in [False, True]
                        for case in ["overrun", "stream-zero", "padding", "missing-pad-length"]]
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == "__main__":
    main()
