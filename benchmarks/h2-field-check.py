#!/usr/bin/env python3
"""Independent hyper-h2 checks for fragmented fields and the fixed native peer."""
import argparse
import importlib.util
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
import hpack

from h2_field_report import validate_report

spec = importlib.util.spec_from_file_location("continuations", Path(__file__).with_name("h2-continuation-check.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class PlainEncoder(hpack.Encoder):
    # Large test fields need no Huffman compression. Avoid spending the test
    # in Python's growing-integer Huffman encoder rather than exercising I/O.
    def encode(self, headers, huffman=True):
        return super().encode(headers, huffman=False)


def request(peer, size):
    peer.client.encoder = PlainEncoder()
    stream = peer.client.get_next_available_stream_id()
    peer.client.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"http"),
        (b":authority", b"localhost"), (b":path", b"/"), (b"x-fill", b"x" * size)], end_stream=True)
    wire = peer.client.data_to_send()
    parts = base.frames(wire)
    assert all(len(f.serialize()) <= 16_393 for f in parts)
    assert "END_HEADERS" in parts[-1].flags
    return stream, wire


def fragmented(port, size, chunk):
    p = base.Peer(port, False)
    try:
        p.exchange(b"", [])
        stream, wire = request(p, size)
        for at in range(0, len(wire), chunk):
            p.sock.sendall(wire[at:at + chunk])
        p.exchange(b"", [stream])
        return dict(size=size, chunk=chunk, wire_bytes=len(wire), responses=p.responses)
    finally:
        p.close()


def truncated(port, size, cut):
    p = base.Peer(port, False)
    try:
        p.exchange(b"", [])
        _, wire = request(p, size)
        end = cut if cut >= 0 else len(wire) + cut
        for at in range(0, end, 53):
            p.sock.sendall(wire[at:min(at + 53, end)])
        p.sock.shutdown(socket.SHUT_WR)
        observed = []
        while data := p.sock.recv(65536):
            observed.extend(p.client.receive_data(data))
        assert not any(isinstance(e, (h2.events.ResponseReceived, h2.events.DataReceived,
            h2.events.StreamEnded, h2.events.StreamReset, h2.events.ConnectionTerminated)) for e in observed), observed
        return dict(size=size, truncated_at=end, premature_responses=0, eof=True)
    finally:
        p.close()


def frame(kind, flags, stream, payload):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


HEADERS = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33"
SETTINGS = bytes([0, 3, 127, 255, 255, 255, 0, 4, 127, 255, 255, 255])
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"



def native_oracle(binary, size, pipeline=1, count=2, fault=None, chunk=65536, legacy=False):
    """Withhold replies until each full/short group arrives, independently decode
    its HPACK and track both connection and stream credit with hyper-h2."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen(); listener.settimeout(10)
        port = listener.getsockname()[1]
        result = dict(size=size, pipeline=pipeline, count=count, requests=0, fault=fault,
            groups=[], sent_bytes=0, received_bytes=0, credit_updates=0, returned_credit=0,
            fence=False, eof=False, injected=False)
        errors = []

        def serve():
            try:
                with listener.accept()[0] as sock:
                    sock.settimeout(10)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    def send(wire):
                        sock.sendall(wire)
                        result["sent_bytes"] += len(wire)
                    def exact(n):
                        wire = bytearray()
                        while len(wire) < n:
                            part = sock.recv(n - len(wire))
                            assert part, "native client truncated input"
                            wire.extend(part)
                        result["received_bytes"] += n
                        return bytes(wire)
                    def injected(wire):
                        result["injected"] = True
                        send(wire)
                        sock.shutdown(socket.SHUT_WR)
                        while sock.recv(65536):
                            pass
                    peer = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
                    peer.initiate_connection(); peer.data_to_send()
                    peer.decoder.max_header_list_size = 2_097_152
                    assert exact(24) == PREFACE
                    peer.receive_data(PREFACE)
                    send(frame(4, 0, 0, SETTINGS))
                    pending = []
                    block_size = 0
                    response_decoder = hpack.Decoder()
                    response_decoder.max_allowed_table_size = 0
                    while True:
                        # EOF is legal only after a complete PING round trip.
                        first = sock.recv(1)
                        if not first:
                            assert result["fence"] and result["requests"] == count
                            assert not pending and block_size == 0
                            result["eof"] = True
                            return
                        result["received_bytes"] += 1
                        header = first + exact(8)
                        length = int.from_bytes(header[:3], "big")
                        assert length <= 16384
                        wire = header + exact(length)
                        kind, flags = header[3:5]
                        stream = int.from_bytes(header[5:9], "big")
                        if kind in (1, 9):
                            assert stream == 2 * result["requests"] + 1
                            assert kind == (1 if block_size == 0 else 9)
                            block_size += length
                            assert flags == (1 if kind == 1 else 0) | (4 if block_size == size else 0)
                            assert block_size <= size
                        events = peer.receive_data(wire)
                        peer.data_to_send()  # Keep hyper-h2 state, emit hfast's fixed representation.
                        for event in events:
                            if isinstance(event, h2.events.RemoteSettingsChanged):
                                send(frame(4, 1, 0, b""))
                            elif isinstance(event, h2.events.RequestReceived):
                                headers = dict(event.headers)
                                assert len(event.headers) == 5
                                assert {k: headers[k] for k in [b":method", b":scheme", b":authority", b":path"]} == {
                                    b":method": b"GET", b":scheme": b"http", b":authority": b"localhost", b":path": b"/"}
                                value = headers[b"x-fill"]
                                assert value and value == b"x" * len(value)
                                assert size - 32 <= len(value) < size
                                assert block_size == size
                            elif isinstance(event, h2.events.StreamEnded):
                                assert event.stream_id == 2 * result["requests"] + 1
                                result["requests"] += 1
                                block_size = 0
                                pending.append(event.stream_id)
                                if len(pending) == pipeline or result["requests"] == count:
                                    replies = []
                                    result["groups"].append(len(pending))
                                    for sid in pending:
                                        # Independent state checks ensure connection credit never
                                        # exceeds 65535 and new streams have enough stream credit.
                                        peer.send_headers(sid, [(b":status", b"200"),
                                            (b"content-type", b"text/plain"), (b"content-length", b"13")])
                                        peer.send_data(sid, b"Hello, World!", end_stream=True)
                                        peer.data_to_send()
                                        block = (b"\x20" if sid == 1 else b"") + HEADERS
                                        assert response_decoder.decode(block) == [
                                            (":status", "200"), ("content-type", "text/plain"), ("content-length", "13")]
                                        replies.append(frame(1, 4, sid, block) + frame(0, 1, sid, b"Hello, World!"))
                                    pending.clear()
                                    if fault and fault not in ["wrong-ping", "missing-ping", "extra-after-fence"]:
                                        if fault == "body":
                                            replies[0] = replies[0][:-13] + b"Wrong, World!"
                                        elif fault == "truncated":
                                            replies[-1] = replies[-1][:-1]
                                        elif fault == "duplicate":
                                            replies.insert(1, replies[0])
                                        elif fault == "missing":
                                            replies.pop(0)
                                        elif fault == "reordered":
                                            assert len(replies) >= 2
                                            replies[0], replies[1] = replies[1], replies[0]
                                        elif fault == "missing-fin":
                                            r = bytearray(replies[0]); r[9 + int.from_bytes(r[:3], "big") + 4] = 0
                                            replies[0] = bytes(r)
                                        elif fault in ["missing-table-update", "wrong-table-update", "duplicate-table-update"]:
                                            prefix = {"missing-table-update": b"", "wrong-table-update": b"\x21",
                                                      "duplicate-table-update": b"\x20\x20"}[fault]
                                            replies[0] = frame(1, 4, 1, prefix + HEADERS) + frame(0, 1, 1, b"Hello, World!")
                                        else:
                                            raise AssertionError(fault)
                                        injected(b"".join(replies))
                                        return
                                    send(b"".join(replies))
                            elif isinstance(event, h2.events.WindowUpdated):
                                assert event.stream_id == 0
                                assert 32768 <= event.delta <= 32768 + 64 * 13
                                result["credit_updates"] += 1
                                result["returned_credit"] += event.delta
                                assert peer.outbound_flow_control_window <= 65535
                            elif isinstance(event, h2.events.PingReceived):
                                assert result["requests"] == count and not pending
                                assert event.ping_data == b"complete" and not result["fence"]
                                result["fence"] = True
                                if fault == "wrong-ping":
                                    injected(frame(6, 1, 0, b"incorrect"[:8])); return
                                if fault == "missing-ping":
                                    injected(b""); return
                                if fault == "extra-after-fence":
                                    injected(frame(6, 1, 0, b"complete") + b"extra"); return
                                send(frame(6, 1, 0, event.ping_data))
                            else:
                                assert isinstance(event, h2.events.SettingsAcknowledged), event
            except Exception as exc:
                errors.append(repr(exc))

        thread = threading.Thread(target=serve, daemon=True); thread.start()
        cmd = [str(binary), str(port), str(size), str(chunk), str(count), "1"]
        if not legacy:
            cmd.append(str(pipeline))
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        thread.join(timeout=12)
        assert not thread.is_alive() and not errors, (result, errors, run.stderr)
        if fault:
            assert result["injected"] and run.returncode != 0
            assert not run.stdout.strip(), "failed peer emitted a benchmark result"
            reason = ("unexpected frames after final fence" if fault == "extra-after-fence" else
                "missing/truncated response" if fault in ["truncated", "missing-ping"] or (fault == "missing" and pipeline == 1) else
                "unexpected response/frame order")
            assert reason in run.stderr, (reason, run.stderr)
        else:
            assert run.returncode == 0, run.stderr
            report = json.loads(run.stdout)
            validate_report(report, size, chunk, count, 1, pipeline)
            ledger = report["peers"][0]
            assert result["sent_bytes"] == report["received_bytes"]
            assert result["received_bytes"] == report["sent_bytes"]
            assert result["credit_updates"] == ledger["credit_updates"]
            assert result["returned_credit"] == ledger["returned_credit"]
            assert result["eof"] and result["fence"]
            assert result["groups"] == [min(pipeline, count - i) for i in range(0, count, pipeline)]
        result["returncode"] = run.returncode
        return result


def live_peer(binary, port, size, pipeline, count, connections, chunk):
    run = subprocess.run([str(binary), str(port), str(size), str(chunk), str(count),
        str(connections), str(pipeline)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    validate_report(report, size, chunk, count, connections, pipeline)
    del report["latencies_ns"]
    return dict(live=report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=lambda p: Path(p).resolve())
    parser.add_argument("--peer", type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    results = []
    if args.peer:
        # Include the legacy five-argument CLI and enough responses to exhaust
        # the initial connection window without multiple correct credit updates.
        results.append(native_oracle(args.peer, 16_384, legacy=True, chunk=4096))
        results += [native_oracle(args.peer, size, pipeline, count)
                    for size in [16_384, 1_048_576] for pipeline in [1, 8, 64]
                    for count in [pipeline, pipeline + 3]]
        results += [native_oracle(args.peer, 32, pipeline, 5201) for pipeline in [1, 8, 64]]
        results += [native_oracle(args.peer, size, pipeline, pipeline + 3, fault)
                    for size in [16_384, 1_048_576] for pipeline in [1, 8, 64]
                    for fault in ["body", "truncated", "duplicate", "missing", "missing-fin",
                                  "missing-table-update", "wrong-table-update", "duplicate-table-update",
                                  "wrong-ping", "missing-ping", "extra-after-fence"]]
        results += [native_oracle(args.peer, size, pipeline, pipeline + 3, "reordered")
                    for size in [16_384, 1_048_576] for pipeline in [8, 64]]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(args.server), "--tcp", str(port), "--quic", "0", "--threads", "1"], stdout=log, stderr=log)
        try:
            end = time.monotonic() + 5
            while True:
                assert server.poll() is None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < end
                    time.sleep(.01)
            if args.peer:
                results += [live_peer(args.peer, port, size, pipeline, count, 3, 65536)
                            for size in [16_384, 1_048_576] for pipeline in [1, 8, 64]
                            for count in [pipeline, pipeline + 3]]
                results += [live_peer(args.peer, port, 32, pipeline, 5201, 3, 53)
                            for pipeline in [1, 8, 64]]
            results += [fragmented(port, size, chunk) for size in [32, 16_384, 1_048_576]
                        for chunk in [53, 4096]]
            results += [truncated(port, size, cut) for size in [32, 1_048_576]
                        for cut in [0, 1, 8, 9, 10, -1]]
        finally:
            server.terminate(); server.wait(timeout=5)
            if server.returncode not in [0, -15]:
                log.seek(0); raise AssertionError(log.read())
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
