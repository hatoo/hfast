#!/usr/bin/env python3
"""Validate the native H2 upload peer against an independent wire oracle.

Successful runs must upload 1 MiB within connection credit, finish 17 responses,
observe every grant and the unique PING, and drain to EOF after half-closing.
Fault runs must fail for the intended reason and emit no timing result.
"""
import argparse
import errno
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

import hpack

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS = bytes.fromhex("00037fffffff00047fffffff")
HEADERS = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33"
BODY = b"Hello, World!"
WINDOW, BATCH, PAYLOAD, UPLOAD = 65535, 32768, 16384, 1048576


def frame(kind, stream=0, payload=b"", flags=0):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def exact(sock, size):
    wire = bytearray()
    while len(wire) < size:
        part = sock.recv(size - len(wire))
        assert part, f"client truncated a {size}-byte field"
        wire.extend(part)
    return bytes(wire)


def read_frame(sock):
    header = exact(sock, 9)
    size = int.from_bytes(header[:3], "big")
    stream = int.from_bytes(header[5:], "big")
    assert size <= PAYLOAD and stream < 2**31
    return header[3], header[4], stream, exact(sock, size)


def send(sock, wire, fragmented):
    if not fragmented:
        sock.sendall(wire)
        return
    at = 0
    while at < len(wire):
        for size in [1, 2, 7, 8, 9]:
            sock.sendall(wire[at:at + size])
            at += size
            if at >= len(wire):
                break


FAULTS = {
    "unsolicited-credit": "missing, duplicated or excessive credit",
    "missing-credit": "missing server frame/credit",
    "zero-credit": "WINDOW_UPDATE increment",
    "excess-credit": "missing, duplicated or excessive credit",
    "wrong-stream-credit": "WINDOW_UPDATE framing",
    "short-credit": "WINDOW_UPDATE framing",
    "reserved-credit": "WINDOW_UPDATE increment",
    "duplicate-credit": "missing, duplicated or excessive credit",
    "missing-final-credit": "missing credit at fence",
    "bad-status": "response HEADERS bytes",
    "bad-body": "response DATA bytes",
    "wrong-response-stream": "response HEADERS stream/order",
    "missing-end-stream": "response DATA bytes",
    "duplicate-response": "response HEADERS stream/order",
    "missing-final-response": "premature fence/response completion",
    "early-fence": "unexpected PING/fence",
    "wrong-fence": "unexpected PING/fence",
    "missing-fence": "missing server frame/credit",
    "truncated-header": "missing server frame/credit",
    "truncated-payload": "truncated server frame",
    "goaway": "unexpected frame type 7",
    "reset": "unexpected frame type 3",
    "extra-after-fence": "bytes after final fence",
    "delayed-after-fence": "bytes after final fence",
}


def scripted_connection(sock, case, cycle, padding):
    """Decode client requests independently; do not import the Rust oracle."""
    fragmented = case == "valid-fragmented"
    sock.settimeout(5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    assert exact(sock, len(PREFACE)) == PREFACE
    assert read_frame(sock) == (4, 0, 0, b"")
    send(sock, frame(4, payload=SETTINGS), fragmented)
    if case == "unsolicited-credit":
        send(sock, frame(8, payload=BATCH.to_bytes(4, "big")), fragmented)
        return {"fault_injected": True}
    send(sock, frame(4, flags=1), fragmented)
    assert read_frame(sock) == (4, 1, 0, b"")
    decoder = hpack.Decoder()
    window, uncredited, packets, requests, updates = WINDOW, 0, 0, 0, 0
    uploaded = 0
    while True:
        kind, flags, stream, payload = read_frame(sock)
        if kind == 1:
            assert packets % 4 == 0 and requests == packets // 4
            assert stream == requests * 2 + 1
            assert flags == (5 if packets == 64 else 4)
            fields = decoder.decode(payload, raw=True)
            assert len(fields) == 4 and dict(fields) == {
                b":method": b"GET" if packets == 64 else b"POST",
                b":scheme": b"http", b":path": b"/", b":authority": b"localhost",
            }, fields
            requests += 1
            response = frame(1, stream, HEADERS, 4) + frame(0, stream, BODY, 1)
            if requests == 1:
                bad = {
                    "bad-status": frame(1, stream, b"\x8d" + HEADERS[1:], 4),
                    "bad-body": frame(1, stream, HEADERS, 4) + frame(0, stream, b"Hello, World?", 1),
                    "wrong-response-stream": frame(1, stream + 2, HEADERS, 4),
                    "missing-end-stream": frame(1, stream, HEADERS, 4) + frame(0, stream, BODY),
                    "duplicate-response": response * 2,
                    "early-fence": frame(6, payload=cycle.to_bytes(8, "big"), flags=1),
                    "truncated-header": response[:8],
                    "truncated-payload": response[:10],
                    "goaway": frame(7, payload=bytes(8)),
                    "reset": frame(3, stream, bytes(4)),
                }
                if case in bad:
                    send(sock, bad[case], fragmented)
                    return {"fault_injected": True}
            if not (case == "missing-final-response" and requests == 17):
                send(sock, response, fragmented)
        elif kind == 0:
            assert packets < 64 and requests == packets // 4 + 1
            assert stream == (packets // 4) * 2 + 1
            assert flags == (int(packets % 4 == 3) | (8 if padding else 0))
            assert len(payload) == PAYLOAD
            if padding:
                assert payload[0] == padding and payload[-padding:] == bytes(padding)
                assert payload[1:-padding] == b"\xa5" * (PAYLOAD - padding - 1)
            else:
                assert payload == b"\xa5" * PAYLOAD
            # Charge all DATA, including padding, before returning credit.
            window -= len(payload)
            assert window >= 0, "native peer exceeded connection receive window"
            uploaded += len(payload)
            uncredited += len(payload)
            packets += 1
            if uncredited >= BATCH:
                grant = frame(8, payload=uncredited.to_bytes(4, "big"))
                if updates == 0:
                    bad = {
                        "missing-credit": b"",
                        "zero-credit": frame(8, payload=bytes(4)),
                        "excess-credit": frame(8, payload=(BATCH + 1).to_bytes(4, "big")),
                        "wrong-stream-credit": frame(8, 1, uncredited.to_bytes(4, "big")),
                        "short-credit": frame(8, payload=bytes(3)),
                        "reserved-credit": frame(8, payload=(2**31 + BATCH).to_bytes(4, "big")),
                    }
                    if case in bad:
                        send(sock, bad[case], fragmented)
                        return {"fault_injected": True}
                if not (case == "missing-final-credit" and packets == 64):
                    send(sock, grant, fragmented)
                    window += uncredited
                    updates += 1
                # At the final grant there is no future upload whose equal
                # grant could temporarily mask a duplicated increment.
                if case == "duplicate-credit" and packets == 64:
                    send(sock, grant, fragmented)
                    return {"fault_injected": True}
                uncredited = 0
        else:
            assert (kind, flags, stream, payload) == (6, 0, 0, cycle.to_bytes(8, "big"))
            assert packets == 64 and requests == 17 and uploaded == UPLOAD
            assert uncredited == 0
            assert (updates, window) == ((31, WINDOW - BATCH) if case == "missing-final-credit" else (32, WINDOW))
            if case == "missing-fence":
                return {"fault_injected": True}
            token = (cycle + 1).to_bytes(8, "big") if case == "wrong-fence" else payload
            reply = frame(6, payload=token, flags=1)
            if case == "extra-after-fence":
                reply += frame(8, payload=BATCH.to_bytes(4, "big"))
            send(sock, reply, fragmented)
            # Deterministic ordering, no sleep: the extra bytes are sent only
            # after the client validated the fence and half-closed its request
            # direction. They cannot already be buffered with the PING ACK.
            assert sock.recv(1) == b"", "bytes followed the client's final PING"
            if case == "delayed-after-fence":
                send(sock, frame(8, payload=BATCH.to_bytes(4, "big")), fragmented)
            return dict(upload_bytes=uploaded, requests=requests, updates=updates,
                        padding=padding, fault_injected=case in FAULTS)


def check_result(result, cycles, padding):
    assert result.returncode == 0, result.stderr
    assert not result.stderr, result.stderr
    row = json.loads(result.stdout)
    assert row["cycles"] == cycles and row["responses"] == cycles * 17
    assert row["fences"] == cycles and row["eofs"] == cycles
    assert row["upload_bytes"] == cycles * UPLOAD and row["updates"] == cycles * 32
    assert row["errors"] == 0 and row["padding"] == padding
    sent = len(PREFACE) + 18 + 64 * (9 + PAYLOAD) + 17 * (9 + 14) + 17
    received = 21 + 9 + 17 * (9 + len(HEADERS) + 9 + len(BODY)) + 32 * 13 + 17
    assert row["sent_bytes"] == cycles * sent
    assert row["received_bytes"] == cycles * received
    assert len(row["cycle_latencies_ns"]) == cycles and min(row["cycle_latencies_ns"]) > 0
    assert row["elapsed_ns"] >= sum(row["cycle_latencies_ns"])
    return row


def scripted_case(peer, case):
    cycles = 2 if case.startswith("valid") else 1
    padding = 255 if case == "valid-fragmented" else 0
    chunk = 53 if padding else 16384
    results, errors = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)

        def serve():
            try:
                for cycle in range(cycles):
                    sock, _ = listener.accept()
                    with sock:
                        results.append(scripted_connection(sock, case, cycle, padding))
                        try:
                            sock.shutdown(socket.SHUT_WR)
                        except OSError as error:
                            # A rejecting peer may already have closed. Its
                            # exit status and exact diagnostic are checked below.
                            if case not in FAULTS or error.errno != errno.ENOTCONN:
                                raise
                        # Let queued client writes finish even on an injected
                        # error, so the observed failure is the intended oracle.
                        try:
                            while sock.recv(65536):
                                pass
                        except ConnectionResetError:
                            if case not in FAULTS:
                                raise
            except Exception as error:
                errors.append(repr(error))

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port = listener.getsockname()[1]
        result = subprocess.run([str(peer), f"127.0.0.1:{port}", str(cycles), str(chunk), str(padding)],
                                text=True, capture_output=True, timeout=20)
        thread.join(timeout=6)
        assert not thread.is_alive() and not errors, (case, errors, result.stderr)
        assert len(results) == cycles, (case, results)
        if case in FAULTS:
            assert result.returncode != 0 and not result.stdout, (case, result)
            assert FAULTS[case] in result.stderr, (case, result.stderr)
            assert results[0]["fault_injected"]
            return dict(case=case, rejected=True, reason=FAULTS[case], wire=results)
        row = check_result(result, cycles, padding)
        return dict(case=case, wire=results, peer=row)


def live_cases(peer, binary, threads, cycles):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        server = subprocess.Popen([str(binary), "--tcp", str(port), "--quic", "0", "--threads", str(threads)],
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
                    time.sleep(.01)
            rows = []
            for chunk in [16384, 53]:
                for padding in [0, 255]:
                    result = subprocess.run([str(peer), f"127.0.0.1:{port}", str(cycles), str(chunk), str(padding)],
                                            text=True, capture_output=True, timeout=30)
                    rows.append(dict(threads=threads, write_bytes=chunk,
                                     peer=check_result(result, cycles, padding)))
            assert server.poll() is None
            return rows
        except Exception:
            log.seek(0)
            print(log.read())
            raise
        finally:
            server.terminate()
            server.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", type=lambda p: Path(p).resolve())
    parser.add_argument("--server", type=lambda p: Path(p).resolve())
    parser.add_argument("--cycles", type=int, default=4)
    parser.add_argument("--case", choices=["valid", "valid-fragmented", *FAULTS])
    args = parser.parse_args()
    assert args.cycles > 0
    cases = [args.case] if args.case else ["valid", "valid-fragmented", *FAULTS]
    results = [scripted_case(args.peer, case) for case in cases]
    if args.server:
        for threads in [1, 2]:
            results.extend(live_cases(args.peer, args.server, threads, args.cycles))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
