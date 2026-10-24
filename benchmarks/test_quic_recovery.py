"""Fault oracles, schedule reproducibility and bounded process lifecycle tests."""

import asyncio
import copy
import datetime
import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import unittest

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import quic_recovery as q

spec = importlib.util.spec_from_file_location(
    "loss_check", Path(__file__).with_name("quic-loss-check.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def headers(stream=0, values=None, ended=False):
    return HeadersReceived(headers=values or [(b":status", b"200")],
                           stream_id=stream, stream_ended=ended)


def data(body=q.BODY, stream=0, ended=True):
    return DataReceived(data=body, stream_id=stream, stream_ended=ended)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = q.Ledger()
        self.ledger.register(0, "GET")

    def complete(self):
        self.ledger.receive(headers())
        self.ledger.receive(data())

    def test_fragmented_body_and_empty_fin(self):
        self.ledger.receive(headers())
        for byte in q.BODY:
            self.ledger.receive(data(bytes([byte]), ended=False))
        self.ledger.receive(data(b""))
        result = self.ledger.finish(1)
        self.assertEqual((result[0]["body_bytes"], result[0]["ends"]), (13, 1))

    def test_missing_response_and_fin(self):
        with self.assertRaisesRegex(RuntimeError, "missing responses"):
            self.ledger.finish(1)
        self.ledger.receive(headers())
        self.ledger.receive(data(ended=False))
        with self.assertRaisesRegex(RuntimeError, "missing responses"):
            self.ledger.finish(1)

    def test_duplicate_request(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate request"):
            self.ledger.register(0, "POST")

    def test_unknown_stream(self):
        with self.assertRaisesRegex(RuntimeError, "unknown response"):
            self.ledger.receive(headers(4))

    def test_duplicate_headers_status_and_length(self):
        for values in ([(b":status", b"200")] * 2,
                       [(b":status", b"404")],
                       [(b":status", b"200"), (b"content-length", b"12")],
                       [(b":status", b"200"), (b"content-length", b"13")]
                       + [(b"content-length", b"13")]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.ledger.receive(headers(values=values))
        self.ledger.receive(headers())
        with self.assertRaisesRegex(RuntimeError, "duplicate response headers"):
            self.ledger.receive(headers())

    def test_body_before_headers(self):
        with self.assertRaisesRegex(RuntimeError, "body before headers"):
            self.ledger.receive(data())

    def test_truncated_body(self):
        self.ledger.receive(headers())
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            self.ledger.receive(data(q.BODY[:-1]))

    def test_wrong_and_extra_body(self):
        for body in (b"Hello, world!", q.BODY + b"!", q.BODY * 2):
            with self.subTest(body=body):
                ledger = q.Ledger()
                ledger.register(0, "GET")
                ledger.receive(headers())
                with self.assertRaisesRegex(RuntimeError, "wrong/extra"):
                    ledger.receive(data(body))

    def test_duplicate_end_or_late_data(self):
        self.complete()
        for event in (data(b""), data(), headers()):
            with self.assertRaisesRegex(RuntimeError, "duplicate/late"):
                self.ledger.receive(event)

    def test_exact_request_count(self):
        self.complete()
        with self.assertRaisesRegex(RuntimeError, "request count"):
            self.ledger.finish(2)

    def test_out_of_order_stream_completions(self):
        self.ledger.register(4, "POST")
        self.ledger.receive(headers(4))
        self.ledger.receive(data(stream=4))
        self.complete()
        self.assertEqual([r["stream"] for r in self.ledger.finish(2)], [0, 4])

    def test_native_report_counts_status_and_protocol(self):
        good = dict(requests=dict(total=128, ok=128, errors=0, connectErrors=0),
                    statusCodes={"200": 128}, protocol="HTTP/3")
        runner.validate_native(good, 128)
        for key, bad in (("total", 127), ("ok", 127), ("errors", 1), ("connectErrors", 1)):
            result = copy.deepcopy(good)
            result["requests"][key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "accounting"):
                runner.validate_native(result, 128)
        for statuses in ({"200": 127}, {"500": 128}, {"200": 128, "500": 1}):
            result = dict(good, statusCodes=statuses)
            with self.assertRaisesRegex(RuntimeError, "status accounting"):
                runner.validate_native(result, 128)
        with self.assertRaisesRegex(RuntimeError, "wrong protocol"):
            runner.validate_native(dict(good, protocol="HTTP/2"), 128)


class Transport:
    def __init__(self):
        self.sent = []

    def sendto(self, payload, address):
        self.sent.append((payload, address))


class ScheduleTests(unittest.TestCase):
    target = ("127.0.0.1", 10001)
    peer = ("127.0.0.1", 10002)

    def relay(self, name, **kwargs):
        relay = q.Relay(self.target, name, **kwargs)
        relay.connection_made(Transport())
        relay.peer = self.peer
        return relay

    def feed(self, relay, phase, order):
        relay.arm(phase)
        for index, direction in enumerate(order):
            payload = (b"\xc0" if phase == "handshake" else b"\x40") + bytes([index % 256])
            relay.datagram_received(payload, self.target if direction == "server" else self.peer)

    def actions(self, relay):
        return sorted((r["phase"], r["direction"], r["index"], r["action"])
                      for r in relay.trace)

    def test_all_named_impairments_and_interleaving_independence(self):
        for name in q.SCENARIOS:
            with self.subTest(name=name):
                a, b = self.relay(name), self.relay(name)
                for phase in ("handshake", "GET", "POST"):
                    self.feed(a, phase, ["client", "server"] * 4)
                    self.feed(b, phase, ["server"] * 4 + ["client"] * 4)
                self.assertEqual(a.finish(), b.finish())
                self.assertEqual(self.actions(a), self.actions(b))

    def test_seeded_rng_is_per_direction(self):
        a, b = self.relay("seeded"), self.relay("seeded")
        self.feed(a, "GET", ["client", "server"] * 100)
        self.feed(b, "GET", ["server"] * 100 + ["client"] * 100)
        self.assertEqual(self.actions(a), self.actions(b))
        self.assertEqual(a.finish(), b.finish())

    def test_exact_reorder_delivery_order(self):
        relay = self.relay("reorder")
        self.feed(relay, "GET", ["client", "client"])
        self.assertEqual([v[0] for v in relay.transport.sent], [b"\x40\x01", b"\x40\x00"])
        self.assertEqual(relay.trace[1]["deliveries"], [1, 0])

    def test_exact_duplicate_bytes(self):
        relay = self.relay("duplicate")
        self.feed(relay, "GET", ["server"])
        self.assertEqual(relay.transport.sent, [(b"\x40\x00", self.peer)] * 2)

    def test_missing_impairment_is_failure(self):
        with self.assertRaisesRegex(RuntimeError, "impairment missing"):
            self.relay("server-loss").finish()

    def test_unreleased_hold_is_failure(self):
        relay = self.relay("reorder")
        self.feed(relay, "GET", ["client"])
        with self.assertRaisesRegex(RuntimeError, "overtaking"):
            relay.finish()
        with self.assertRaisesRegex(RuntimeError, "unreleased"):
            relay.arm("POST")

    def test_callback_errors_are_not_swallowed(self):
        relay = self.relay("clean")
        relay.datagram_received(b"", self.peer)
        with self.assertRaisesRegex(RuntimeError, "empty UDP"):
            relay.finish()

    def test_second_peer_is_failure(self):
        relay = self.relay("clean")
        relay.datagram_received(b"\x40", ("127.0.0.1", 10003))
        with self.assertRaisesRegex(RuntimeError, "second client"):
            relay.check()

    def test_replay_and_packetization_divergence(self):
        original = self.relay("seeded")
        self.feed(original, "GET", ["client", "server"] * 20)
        plan = q.replay_plan(original.trace)
        replay = self.relay("replay", replay=plan)
        self.feed(replay, "GET", ["server"] * 20 + ["client"] * 20)
        replay.finish()
        self.assertEqual(self.actions(original), self.actions(replay))
        replay = self.relay("replay", replay=plan)
        replay.arm("GET")
        replay.datagram_received(b"\x40longer", self.peer)
        with self.assertRaisesRegex(RuntimeError, "packetization diverged"):
            replay.check()

    def test_incomplete_or_duplicate_replay(self):
        original = self.relay("clean")
        self.feed(original, "GET", ["client"])
        with self.assertRaisesRegex(RuntimeError, "duplicate replay"):
            q.replay_plan(original.trace * 2)
        replay = self.relay("replay", replay=q.replay_plan(original.trace))
        with self.assertRaisesRegex(RuntimeError, "omitted"):
            replay.finish()


class FaultServer(QuicConnectionProtocol):
    def __init__(self, *args, fault, **kwargs):
        super().__init__(*args, **kwargs)
        self.http, self.fault = H3Connection(self._quic), fault

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if not isinstance(item, HeadersReceived):
                continue
            stream = item.stream_id
            if self.fault == "missing":
                continue
            if self.fault == "reset":
                self._quic.reset_stream(stream, 0x100)
            else:
                status = b"500" if self.fault == "status" else b"200"
                self.http.send_headers(stream, [(b":status", status)])
                body = {"wrong": b"Hello, world!", "truncated": q.BODY[:-1],
                        "extra": q.BODY * 2}.get(self.fault, q.BODY)
                self.http.send_data(stream, body, end_stream=self.fault != "no-fin")
            self.transmit()


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.callback_errors = []
        asyncio.get_running_loop().set_exception_handler(
            lambda loop, context: self.callback_errors.append(context))

    async def asyncTearDown(self):
        await asyncio.sleep(0)
        self.assertEqual(self.callback_errors, [], self.callback_errors)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        cls.config.load_cert_chain(root / "cert.pem", root / "key.pem")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    async def test_live_response_faults(self):
        for fault, expected in (("clean", None), ("wrong", "wrong/extra"),
                                ("truncated", "truncated"), ("status", "status"),
                                ("extra", "wrong/extra"), ("reset", "stream failure"),
                                ("missing", "timeout"), ("no-fin", "timeout")):
            with self.subTest(fault=fault):
                server = await serve("127.0.0.1", 0, configuration=self.config,
                                     create_protocol=lambda *a, **k: FaultServer(*a, fault=fault, **k))
                port = server._transport.get_extra_info("sockname")[1]
                report = {}
                try:
                    if expected == "timeout":
                        with self.assertRaises(TimeoutError):
                            await asyncio.wait_for(runner.ready(port, report), 0.4)
                        self.assertEqual(report["missing"], [0])
                    elif expected:
                        with self.assertRaisesRegex(RuntimeError, expected):
                            await asyncio.wait_for(runner.ready(port, report), 2)
                    else:
                        await asyncio.wait_for(runner.ready(port, report), 2)
                        self.assertEqual(len(report["responses"]), 1)
                    self.assertTrue(report.get("closed"), report)
                finally:
                    server.close()

    async def test_server_exit_and_startup_timeout_cleanup(self):
        for source, expected in (("raise SystemExit(17)", "server exited"),
                                 ("import time; time.sleep(60)", "deadline"),
                                 ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                                  "time.sleep(60)", "deadline")):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as root:
                binary = Path(root) / "fake-server"
                binary.write_text(f"#!{sys.executable}\n{source}\n")
                binary.chmod(0o755)
                report = await asyncio.wait_for(
                    runner.run_case(binary, "clean", timeout=0.15), 4)
                self.assertFalse(report["passed"])
                self.assertIn(expected, report["error"])
                if "SIG_IGN" in source:
                    self.assertEqual(report["process"]["exit"], -signal.SIGKILL)
                with self.assertRaises(ProcessLookupError):
                    os.kill(report["process"]["pid"], 0)
                for key in ("server_port", "relay_port"):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.bind(("127.0.0.1", report[key]))


if __name__ == "__main__":
    unittest.main()
