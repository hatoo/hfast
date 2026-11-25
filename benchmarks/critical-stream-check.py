#!/usr/bin/env python3
"""Independent encrypted HTTP/3 critical-stream closure oracle (aioquic 1.3.0).

Every case completes two requests before the terminal frame. Critical cases must
then receive application CONNECTION_CLOSE 0x104; harmless cases must complete two
more requests. Reset cases require acknowledged type bytes, not merely queued
bytes. --observe uses the same 30 ordinary cases to record old behavior. Candidate
validation adds six cases dropping the first authenticated close before delivery.
"""

import argparse
import hashlib
import json
import math
import os
import socket
import ssl
import subprocess
import time
from pathlib import Path

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionState
from aioquic.quic.crypto import CryptoError
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

BODY = b"Hello, World!"
CRITICAL = {"control": 0, "encoder": 2, "decoder": 3}


def remote_close(quic):
    # aioquic delays ConnectionTerminated until its draining timer expires.
    # PTO backoff after injected loss can extend that timer beyond our fixed
    # observation interval. DRAINING is entered only after receiving the peer's
    # close; a locally generated close remains CLOSING and is not accepted here.
    if quic._state == QuicConnectionState.DRAINING:
        event = quic._close_event
        return dict(error_code=event.error_code, frame_type=event.frame_type,
                    reason=event.reason_phrase)
    return None


class WideTypes(H3Connection):
    """Pinned aioquic stream creation with a legal, non-minimal type encoding."""

    def __init__(self, quic, width):
        self.width = width
        super().__init__(quic)

    def _create_uni_stream(self, stream_type, push_id=None):
        stream = self._quic.get_next_available_stream_id(is_unidirectional=True)
        self._log_stream_type(push_id=push_id, stream_id=stream, stream_type=stream_type)
        prefix = bytearray(stream_type.to_bytes(self.width, "big"))
        prefix[0] |= {1: 0, 2: 0x40, 4: 0x80, 8: 0xc0}[self.width]
        self._quic.send_stream_data(stream, bytes(prefix))
        return stream


class CloseLoss:
    """Drop one authenticated close before frame processing or PN accounting."""

    def __init__(self, decrypt):
        self.decrypt = decrypt
        self.dropped = []
        self.delivered = []

    def __call__(self, *args, **kwargs):
        result = self.decrypt(*args, **kwargs)
        _, plain, pn = result
        if plain[:1] == b"\x1d":
            buf = Buffer(data=plain)
            assert buf.pull_uint_var() == 0x1d
            code = buf.pull_uint_var()
            reason = buf.pull_bytes(buf.pull_uint_var())
            assert buf.eof(), "unexpected frames after terminal close"
            row = dict(pn=pn, code=code, reason=reason.hex(),
                       sha256=hashlib.sha256(args[0]).hexdigest())
            if not self.dropped and code == 0x104:
                self.dropped.append(row)
                raise CryptoError("injected critical-stream close loss")
            self.delivered.append(row)
        return result


class Peer:
    def __init__(self, port, width=1):
        config = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                   initial_rtt=0.02)
        config.verify_mode = ssl.CERT_NONE
        self.quic = QuicConnection(configuration=config)
        self.http = WideTypes(self.quic, width)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.target = ("127.0.0.1", port)
        self.handshake = False
        self.close = None
        self.requests = {}
        self.completed = set()
        self.started_at = {}
        self.samples = []
        self.sent = self.received = 0
        self.quic.connect(self.target, now=time.monotonic())

    def step(self):
        now = time.monotonic()
        for data, addr in self.quic.datagrams_to_send(now=now):
            self.sock.sendto(data, addr)
            self.sent += 1
        timer = self.quic.get_timer()
        self.sock.settimeout(max(0.001, min(0.01, (timer or now + 0.01) - now)))
        try:
            data, addr = self.sock.recvfrom(65536)
        except socket.timeout:
            data = None
        now = time.monotonic()
        if data is not None:
            self.received += 1
            self.quic.receive_datagram(data, addr, now=now)
            self.close = remote_close(self.quic) or self.close
        timer = self.quic.get_timer()
        if timer is not None and timer <= now:
            self.quic.handle_timer(now=now)
        while (event := self.quic.next_event()) is not None:
            if isinstance(event, HandshakeCompleted):
                self.handshake = True
            if isinstance(event, ConnectionTerminated):
                self.close = dict(error_code=event.error_code,
                                  frame_type=event.frame_type,
                                  reason=event.reason_phrase)
            for ev in self.http.handle_event(event):
                if isinstance(ev, (HeadersReceived, DataReceived)):
                    assert ev.stream_id in self.requests, ev
                    assert ev.stream_id not in self.completed, "duplicate response"
                    headers, body = self.requests[ev.stream_id]
                    if isinstance(ev, HeadersReceived):
                        headers.extend(ev.headers)
                    else:
                        body.extend(ev.data)
                    if ev.stream_ended:
                        assert [v for k, v in headers if k == b":status"] == [b"200"]
                        assert body == BODY, body
                        self.completed.add(ev.stream_id)
                        self.samples.append(time.monotonic() - self.started_at[ev.stream_id])

    def until(self, predicate, timeout=2):
        end = time.monotonic() + timeout
        while not predicate() and time.monotonic() < end:
            self.step()
        return predicate()

    def request_pair(self):
        ids = []
        for _ in range(2):
            stream = self.quic.get_next_available_stream_id()
            self.requests[stream] = ([], bytearray())
            self.started_at[stream] = time.monotonic()
            ids.append(stream)
            self.http.send_headers(stream, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", b"/"),
            ], end_stream=True)
        assert self.until(lambda: all(s in self.completed for s in ids) or self.close)
        assert all(s in self.completed for s in ids), self.close

    def finish(self):
        if self.close is None:
            self.quic.close(error_code=0x100, reason_phrase="fixture complete")
            for data, addr in self.quic.datagrams_to_send(now=time.monotonic()):
                self.sock.sendto(data, addr)
        self.sock.close()


def validate(row, observe=False):
    assert row["kind"] in (*CRITICAL, "unknown", "empty", "partial"), row
    assert row["terminal"] in ("fin", "reset"), row
    assert row["critical"] == (row["kind"] in CRITICAL), row
    assert row["handshake"] and row["before_completed"] == 2, row
    assert row["acked_prefix"] == row["prefix_length"], row
    if row["critical"]:
        assert row["prefix_length"] >= row["width"] > 0, row
    if row["critical"] and (not observe or row["close"] is not None):
        assert row["close"] is not None, row
        assert row["close"]["error_code"] == 0x104, row
        assert row["close"]["frame_type"] is None, row
        assert row["started"] == row["completed"] == 2, row
    else:
        assert row["close"] is None, row
        assert row["started"] == row["completed"] == 4, row
    assert row["body_bytes"] == row["completed"] * len(BODY), row
    assert len(row["latency_seconds"]) == row["completed"], row
    assert all(math.isfinite(s) and s >= 0 for s in row["latency_seconds"]), row
    if row["drop_first"]:
        assert len(row["dropped"]) == len(row["delivered"]) == 1, row
        assert row["dropped"] == row["delivered"], row
    else:
        assert row["dropped"] == row["delivered"] == [], row


def check(port, kind, terminal, *, width=1, drop_first=False):
    peer = Peer(port, width)
    loss = None
    try:
        assert peer.until(lambda: peer.handshake)
        peer.request_pair()
        if kind in CRITICAL:
            stream = {"control": peer.http._local_control_stream_id,
                      "encoder": peer.http._local_encoder_stream_id,
                      "decoder": peer.http._local_decoder_stream_id}[kind]
        else:
            stream = peer.quic.get_next_available_stream_id(is_unidirectional=True)
            prefix = {"unknown": b"\x21", "empty": b"", "partial": b"\x40"}[kind]
            peer.quic.send_stream_data(stream, prefix)
        sender = peer.quic._streams[stream].sender
        prefix_length = sender._buffer_stop
        assert peer.until(lambda: sender._buffer_start == prefix_length or peer.close)
        assert peer.close is None, peer.close
        acked_prefix = sender._buffer_start
        assert acked_prefix == prefix_length
        if drop_first:
            crypto = peer.quic._cryptos[tls.Epoch.ONE_RTT]
            loss = CloseLoss(crypto.decrypt_packet)
            crypto.decrypt_packet = loss
        before = len(peer.completed)
        if terminal == "fin":
            peer.quic.send_stream_data(stream, b"", end_stream=True)
        else:
            peer.quic.reset_stream(stream, error_code=0x100)
        # H3Connection emits empty QPACK writes while encoding/decoding even
        # when the static table needs no instructions. aioquic rejects these
        # API calls after FIN/reset. Elide only that wire-empty no-op so the
        # unchanged independent H3 decoder can expose a non-closing baseline.
        send_stream_data = peer.quic.send_stream_data

        def send_after_terminal(stream_id, data, end_stream=False):
            if stream_id == stream and not data and not end_stream:
                return
            send_stream_data(stream_id, data, end_stream=end_stream)

        peer.quic.send_stream_data = send_after_terminal
        # Ordinary before/after cases use the same interval. Loss cases must
        # allow hfast's initial ~1s PTO and the peer's exponential probe backoff;
        # they are a separate recovery workload, never a throughput comparison.
        peer.until(lambda: peer.close is not None, timeout=4 if drop_first else 0.8)
        if peer.close is None and not drop_first:
            peer.request_pair()
        row = dict(kind=kind, terminal=terminal, critical=kind in CRITICAL,
                   width=width, drop_first=drop_first,
                   handshake=peer.handshake, stream_id=stream,
                   prefix_length=prefix_length, acked_prefix=acked_prefix,
                   before_completed=before, started=len(peer.requests),
                   completed=len(peer.completed), body_bytes=sum(
                       len(body) for _, body in peer.requests.values()),
                   latency_seconds=peer.samples,
                   dropped=loss.dropped if loss else [],
                   delivered=loss.delivered if loss else [],
                   close=peer.close, sent_datagrams=peer.sent,
                   received_datagrams=peer.received)
        return row
    except Exception:
        # Retain useful partial evidence even if a deadline or decoder fails
        # before a complete result can be validated and saved by the driver.
        print(json.dumps(dict(failed_case=[kind, terminal, width, drop_first],
                              close=peer.close, started=len(peer.requests),
                              completed=len(peer.completed),
                              samples=peer.samples,
                              dropped=loss.dropped if loss else [],
                              delivered=loss.delivered if loss else [])), flush=True)
        raise
    finally:
        peer.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--threads", type=int, choices=(1, 2), default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observe", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    before_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    rows = []
    passed = False
    with (args.output / "server.stderr").open("w") as log:
        server = subprocess.Popen([str(binary), "--threads", str(args.threads),
                                   "--tcp", "0", "--quic", str(port)],
                                  stdout=log, stderr=log)
        try:
            time.sleep(0.2)
            assert server.poll() is None, "server exited"
            cases = [(kind, terminal, width, False)
                     for kind in CRITICAL for terminal in ("fin", "reset")
                     for width in (1, 2, 4, 8)]
            cases += [(kind, terminal, 1, False)
                      for kind in ("unknown", "empty", "partial")
                      for terminal in ("fin", "reset")]
            if not args.observe:
                cases += [(kind, terminal, 1, True)
                          for kind in CRITICAL for terminal in ("fin", "reset")]
            for kind, terminal, width, drop_first in cases:
                row = check(port, kind, terminal, width=width, drop_first=drop_first)
                rows.append(row)
                name = f"{kind}-{terminal}-w{width}-loss{int(drop_first)}"
                (args.output / f"{name}.json").write_text(json.dumps(row, indent=2) + "\n")
                print(json.dumps(row), flush=True)
                validate(row, args.observe)
            assert server.poll() is None, "server exited during matrix"
            passed = True
        finally:
            server.terminate()
            server.wait(timeout=5)
            (args.output / "summary.json").write_text(json.dumps(dict(
                binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                sha256_before=before_hash,
                actual_gro_binary=os.environ.get("HFAST_GRO_BINARY"), passed=passed,
                threads=args.threads, observe=args.observe, rows=rows), indent=2) + "\n")
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == before_hash


if __name__ == "__main__":
    main()
