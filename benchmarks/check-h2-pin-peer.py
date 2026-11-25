#!/usr/bin/env python3
"""Independent hyper-h2 checks of timed pins, credit and complete final drains."""
import argparse
import hashlib
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


def run_case(port, mode, quota=256, cycles=1, read_size=65536, write_size=65536):
    c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    c.initiate_connection()
    if mode == "partial":
        c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 5})
    active, ended, headers, cancelled = {}, set(), set(), set()
    started = barriers = partial = conn_credit = expected_timeout = 0
    paused = False
    negative_done = False
    holds, credit_grants = [], 0
    cycle_start = time.monotonic()
    total = quota * cycles
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        deadline = time.monotonic() + 20

        def send():
            nonlocal cycle_start
            wire = c.data_to_send()
            if cycle_start is None and wire:
                cycle_start = time.monotonic()
            for offset in range(0, len(wire), write_size):
                s.sendall(wire[offset:offset + write_size])

        def fill():
            nonlocal started, cycle_start
            limit = min(32, c.remote_settings.max_concurrent_streams)
            while started < min(total, (barriers + 1) * quota) and len(active) < limit and not paused:
                if started % quota == 0:
                    cycle_start = None
                stream = c.get_next_available_stream_id()
                active[stream] = bytearray()
                fields = [(":method", "GET"), (":scheme", "http"),
                          (":authority", "localhost"), (":path", "/")]
                if mode == "large":
                    fields.append(("x-fragment", "0123456789abcdef" * 4096))
                c.send_headers(stream, fields, end_stream=True)
                started += 1

        fill()
        send()
        while len(ended) + len(cancelled) < total or barriers < cycles:
            assert time.monotonic() < deadline, "fixture deadline exceeded"
            data = s.recv(read_size)
            assert data, "unexpected EOF"
            for event in c.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    assert event.stream_id in active and event.stream_id not in headers
                    assert (b":status", b"200") in event.headers
                    assert (b"content-length", b"13") in event.headers
                    headers.add(event.stream_id)
                elif isinstance(event, h2.events.DataReceived):
                    assert event.stream_id in active and event.stream_id in headers
                    body = active[event.stream_id]
                    body.extend(event.data)
                    assert BODY.startswith(body)
                    if mode == "credit":
                        conn_credit += event.flow_controlled_length
                        # Deliberately exhaust the original connection window;
                        # all younger streams still have ample stream credit.
                        if conn_credit == 65535:
                            s.settimeout(.10)
                            try:
                                extra = s.recv(4096)
                            except socket.timeout:
                                pass
                            else:
                                raise AssertionError(f"connection credit did not stall: {extra!r}")
                            s.settimeout(5)
                            c.increment_flow_control_window(65535)
                            credit_grants += 1
                    else:
                        c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    partial += int(len(body) < len(BODY))
                elif isinstance(event, h2.events.StreamEnded):
                    assert bytes(active.pop(event.stream_id)) == BODY
                    assert event.stream_id not in ended
                    ended.add(event.stream_id)
                elif isinstance(event, h2.events.RemoteSettingsChanged):
                    setting = event.changed_settings.get(h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS)
                    if setting is not None:
                        if setting.new_value == 0:
                            assert not paused
                            held_for = time.monotonic() - cycle_start
                            assert held_for >= .90, "timer released pins too early"
                            holds.append(held_for)
                            paused = True
                        elif paused:
                            assert not active and barriers == len(holds)
                            assert setting.new_value == 0x7fffffff
                            paused = False
                elif isinstance(event, h2.events.PingReceived):
                    assert paused and not active and c.open_outbound_streams == 0
                    assert len(ended) + len(cancelled) == min(total, (barriers + 1) * quota)
                    barriers += 1
                elif isinstance(event, (h2.events.ConnectionTerminated, h2.events.StreamReset)):
                    raise AssertionError(f"unexpected protocol failure: {event}")
            if not negative_done and mode in ("reset", "timeout", "goaway") and len(active.get(1, b"")) == 12:
                assert 1 not in ended
                if mode == "timeout":
                    s.settimeout(.15)
                    try:
                        extra = s.recv(4096)
                    except socket.timeout:
                        expected_timeout += 1
                    else:
                        raise AssertionError(f"held tail unexpectedly progressed: {extra!r}")
                    s.settimeout(5)
                if mode == "goaway":
                    c.close_connection()
                    send()
                    assert s.recv(4096) == b"", "GOAWAY did not close peer"
                    return dict(mode=mode, started=1, completed=0, cancelled=1,
                                expected_goaway=1, barriers=0)
                c.reset_stream(1, error_code=8)
                cancelled.add(1)
                del active[1]
                negative_done = True
            fill()
            send()
        assert not active and started == total and headers == ended | cancelled
        assert len(cancelled) == int(mode in ("reset", "timeout"))
        if mode == "partial":
            assert partial >= total
        if mode == "credit":
            assert credit_grants == 1
        if mode == "timeout":
            assert expected_timeout == 1
        return dict(mode=mode, started=started, completed=len(ended), cancelled=len(cancelled),
                    headers=len(headers), body_bytes=13 * len(ended), partial_frames=partial,
                    expected_timeouts=expected_timeout, barriers=barriers, hold_seconds=holds,
                    connection_credit_grants=credit_grants, read_size=read_size, write_size=write_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    binary = args.binary.resolve()
    command = [str(binary), "--tcp", str(port), "--quic", "0", "--threads", str(args.threads)]
    (args.output / "command.json").write_text(json.dumps(dict(command=command,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2) + "\n")
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
            cases = [("normal", 256, 3, 65536, 65536), ("single", 1, 1, 65536, 65536),
                     ("fragmented", 128, 1, 1, 7), ("partial", 128, 1, 65536, 65536),
                     ("credit", 6000, 1, 65536, 65536), ("reset", 256, 1, 65536, 65536),
                     ("timeout", 1, 1, 65536, 65536), ("goaway", 1, 1, 65536, 65536),
                     ("large", 4, 1, 65536, 1024)]
            rows = []
            for case in cases:
                result = run_case(port, *case)
                rows.append(result)
                with (args.output / "completed.jsonl").open("a") as progress:
                    progress.write(json.dumps(result) + "\n")
                print(json.dumps(result), flush=True)
            (args.output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
