#!/usr/bin/env python3
"""Independent hyper-h2 qualification of the bounded drain peer, never a timer."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import time

import h2.config
import h2.connection
import h2.events
import h2.settings

BODY = b"Hello, World!"


def run_case(port, mode, read_size=65536, write_size=65536):
    total = 256
    c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    c.initiate_connection()
    if mode == "partial":
        c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 5})
    active = {}
    ended = set()
    cancelled = set()
    headers = set()
    started = 0
    paused = False
    barriers = 0
    resumed = False
    partial = 0
    expected_timeout = 0
    first_header = False
    negative_done = False
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        deadline = time.monotonic() + 15

        def send():
            wire = c.data_to_send()
            for offset in range(0, len(wire), write_size):
                s.sendall(wire[offset:offset + write_size])

        def fill():
            nonlocal started
            limit = 1 if mode in ("timeout", "goaway") and not negative_done else 32
            limit = min(limit, c.remote_settings.max_concurrent_streams)
            while started < total and len(active) < limit:
                stream = c.get_next_available_stream_id()
                active[stream] = bytearray()
                c.send_headers(stream, [(":method", "GET"), (":scheme", "http"),
                                        (":authority", "localhost"), (":path", "/")], end_stream=True)
                started += 1

        fill()
        send()
        while len(ended) + len(cancelled) < total:
            assert time.monotonic() < deadline, "fixture deadline exceeded"
            data = s.recv(read_size)
            assert data, "unexpected EOF"
            for event in c.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    assert event.stream_id in active and event.stream_id not in headers
                    assert (b":status", b"200") in event.headers
                    assert (b"content-length", b"13") in event.headers
                    headers.add(event.stream_id)
                    if event.stream_id == 1:
                        first_header = True
                        if mode == "reset":
                            assert not active[1]
                            c.reset_stream(1, error_code=8)
                            cancelled.add(1)
                            del active[1]
                elif isinstance(event, h2.events.DataReceived):
                    assert event.stream_id in active and event.stream_id in headers
                    active[event.stream_id].extend(event.data)
                    assert BODY.startswith(active[event.stream_id])
                    c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if mode == "partial" and len(active[event.stream_id]) < len(BODY):
                        partial += 1
                elif isinstance(event, h2.events.StreamEnded):
                    assert bytes(active.pop(event.stream_id)) == BODY
                    assert event.stream_id not in ended
                    ended.add(event.stream_id)
                elif isinstance(event, h2.events.RemoteSettingsChanged):
                    setting = event.changed_settings.get(h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS)
                    if setting is not None:
                        if setting.new_value == 0:
                            assert not paused and barriers == 0
                            paused = True
                        elif paused:
                            assert barriers == 1 and not active
                            assert setting.new_value == 0x7fffffff
                            resumed = True
                elif isinstance(event, h2.events.PingReceived):
                    assert paused and not resumed and not active
                    assert c.open_outbound_streams == 0
                    assert len(ended) + len(cancelled) >= 97
                    assert barriers == 0
                    barriers += 1
                elif isinstance(event, (h2.events.ConnectionTerminated, h2.events.StreamReset)):
                    raise AssertionError(f"unexpected protocol failure: {event}")
            if first_header and not negative_done and mode in ("timeout", "goaway"):
                assert started == 1 and active == {1: bytearray()} and not ended
                if mode == "timeout":
                    s.settimeout(.15)
                    try:
                        extra = s.recv(4096)
                    except socket.timeout:
                        expected_timeout += 1
                    else:
                        raise AssertionError(f"held body unexpectedly progressed: {extra!r}")
                    s.settimeout(5)
                    c.reset_stream(1, error_code=8)
                    cancelled.add(1)
                    del active[1]
                else:
                    c.close_connection()
                    send()
                    assert s.recv(4096) == b"", "GOAWAY did not close the fixture"
                    return dict(mode=mode, started=1, completed=0, cancelled=1,
                                expected_goaway=1, barriers=0)
                negative_done = True
            fill()
            send()
        assert not active and started == total and barriers == 1 and resumed
        assert headers == ended | cancelled
        assert len(cancelled) == (1 if mode in ("reset", "timeout") else 0)
        if mode == "partial":
            assert partial >= 97
        if mode == "timeout":
            assert expected_timeout == 1
        return dict(mode=mode, read_size=read_size, write_size=write_size, started=started,
                    completed=len(ended), cancelled=len(cancelled), headers=len(headers),
                    body_bytes=13 * len(ended), partial_frames=partial,
                    expected_timeouts=expected_timeout, barriers=barriers)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--threads", type=int, default=1)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [str(args.binary.resolve()), "--tcp", str(port), "--quic", "0",
               "--threads", str(args.threads)]
    (args.output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (args.output / "server.log").open("x") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                assert process.poll() is None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                raise AssertionError("server readiness deadline")
            rows = []
            for case in [("normal", 65536, 65536), ("normal", 1, 7)] + [
                    (mode, 65536, 65536) for mode in ("partial", "reset", "timeout", "goaway")]:
                result = run_case(port, *case)
                rows.append(result)
                with (args.output / "completed.jsonl").open("a") as progress:
                    progress.write(json.dumps(result) + "\n")
            (args.output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
            print(json.dumps(dict(threads=args.threads, cases=rows), indent=2))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
