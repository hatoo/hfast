"""Negative ACK/wire oracles and bounded lifecycle tests for receive-ack-check."""

import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aioquic import tls
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoContext, CryptoError
from aioquic.quic.events import ConnectionTerminated

import receive_ack as a
from quic_recovery import BODY, Client, Ledger

spec = importlib.util.spec_from_file_location(
    "receive_ack_runner", Path(__file__).with_name("receive-ack-check.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def packet(ranges=((100, 100),), *, token=bytes(8), pn=1):
    return dict(header=dict(packet_number=pn, packet_type="1RTT"),
                frames=[dict(frame_type="ack", acked_ranges=list(ranges)),
                        dict(frame_type="path_response", data=token.hex())])


class ModelTests(unittest.TestCase):
    def test_evict_disjoint_but_join_oldest_before_discard(self):
        history = tuple((n, n) for n in range(128, 99, -4))
        self.assertEqual(a.retained(history, 0), history)
        self.assertEqual(a.retained(history, 99), (*history[:-1], (99, 100)))
        self.assertEqual(a.retained(history, 101), (*history[:-1], (100, 101)))
        self.assertEqual(a.retained(history, 100), history)
        self.assertEqual(a.retained(history, 132), ((132, 132), *history[:-1]))

    def test_bridge_two_oldest_ranges_reclaims_slot(self):
        history = tuple((n, n) for n in [126, 122, 118, 114, 110, 106, 102, 100])
        merged = a.retained(history, 101)
        self.assertEqual(merged, (*history[:-2], (100, 102)))
        self.assertEqual(a.retained(merged, 0), (*merged, (0, 0)))

    def test_forgotten_number_is_not_restored_by_a_later_bridge(self):
        history = tuple((n, n) for n in range(128, 99, -4))
        history = a.retained(history, 96)
        history = a.retained(history, 99)
        self.assertEqual(history[-1], (99, 100))
        self.assertFalse(any(lo <= 96 <= hi for lo, hi in history))

    def test_canonical_rejects_malformed_adjacent_and_unbounded_ranges(self):
        for ranges in ([], [(3, 2)], [(-1, 0)], [(0, 1 << 62)], [(0,)],
                       [(True, 1)], [(1, 1), (2, 2)], [(1, 3), (2, 4)],
                       [(1, 1), (1, 1)], [(n, n) for n in range(0, 18, 2)]):
            with self.subTest(ranges=ranges), self.assertRaises(RuntimeError):
                a.canonical(ranges)
        self.assertEqual(a.canonical([[0, 1], [4, 8]]), ((4, 8), (0, 1)))


class AckTests(unittest.TestCase):
    def test_only_observed_fenced_ack_advances_history(self):
        ledger = a.AckLedger(100, {})
        self.assertFalse(ledger.observe(100, bytes(8), [], {}))
        self.assertEqual(ledger.history, ())
        self.assertTrue(ledger.observe(100, bytes(8), [packet()], {}))
        self.assertEqual(ledger.history, ((100, 100),))

    def test_missing_extra_and_wrong_ranges_leave_history_uncommitted(self):
        for ranges in ([(99, 99)], [(100, 101)], [(100, 100), (104, 104)]):
            ledger = a.AckLedger(100, {})
            with self.subTest(ranges=ranges), self.assertRaisesRegex(RuntimeError, "mismatch"):
                ledger.observe(100, bytes(8), [packet(ranges)], {})
            self.assertEqual(ledger.history, ())
            self.assertEqual(ledger.last_server_pn, -1)

    def test_response_and_ack_must_share_one_fresh_authenticated_packet(self):
        for change in ("no-ack", "two-acks", "two-responses", "two-packets", "wrong-token", "split"):
            packets = [packet()]
            if change == "no-ack":
                packets[0]["frames"].pop(0)
            elif change == "two-acks":
                packets[0]["frames"].append(copy.deepcopy(packets[0]["frames"][0]))
            elif change == "two-responses":
                packets[0]["frames"].append(copy.deepcopy(packets[0]["frames"][1]))
            elif change == "two-packets":
                packets.append(copy.deepcopy(packets[0]))
            elif change == "wrong-token":
                packets[0]["frames"][1]["data"] = "01" * 8
            else:
                packets.append(copy.deepcopy(packets[0]))
                packets[0]["frames"].pop(0)
                packets[1]["frames"].pop(1)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                a.AckLedger(100, {}).observe(100, bytes(8), packets, {})

    def test_replay_needs_a_new_server_packet_and_preserves_exact_history(self):
        ledger = a.AckLedger(100, {})
        ledger.observe(100, bytes(8), [packet()], {})
        with self.assertRaisesRegex(RuntimeError, "stale"):
            ledger.observe(100, bytes(8), [packet()], {})
        self.assertTrue(ledger.observe(100, bytes(8), [packet(pn=2)], {}))
        self.assertEqual(ledger.history, ((100, 100),))

    def test_old_discard_still_requires_an_owed_ack(self):
        ledger = a.AckLedger(0, {})
        ledger.history = tuple((n, n) for n in range(128, 99, -4))
        observed = packet(ledger.history)
        self.assertTrue(ledger.observe(0, bytes(8), [observed], {}))
        observed["header"]["packet_number"] = 2
        observed["frames"].pop(0)
        with self.assertRaisesRegex(RuntimeError, "owed ACK"):
            ledger.observe(0, bytes(8), [observed], {})

    def test_handshake_history_must_disappear_after_eight_separated_probes(self):
        ledger = a.AckLedger(100, {})
        for index, n in enumerate(range(100, 128, 4)):
            history = a.retained(ledger.history, n)
            ledger.observe(n, bytes(8), [packet((*history, (1, 3)), pn=index)], {})
        expected = a.retained(ledger.history, 128)
        ledger.observe(128, bytes(8), [packet(expected, pn=8)], {})
        self.assertEqual(len(ledger.history), 8)
        # Removing a required range to keep a handshake range within the cap fails.
        wrong = (*expected[:-1], (1, 3))
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            ledger.observe(128, bytes(8), [packet(wrong, pn=9)], {})

    def test_a_bridge_cannot_restore_evicted_handshake_history(self):
        ledger = a.AckLedger(100, {})
        ledger.history = tuple((n, n) for n in [126, 122, 118, 114, 110, 106, 102, 100])
        ledger.saturated = True
        merged = a.retained(ledger.history, 101)
        with self.assertRaisesRegex(RuntimeError, "handshake range"):
            ledger.observe(101, bytes(8), [packet((*merged, (1, 3)))], {})
        self.assertEqual(len(ledger.history), 8)


class WireTests(unittest.TestCase):
    def setUp(self):
        self.key = CryptoContext()
        self.key.setup(cipher_suite=tls.CipherSuite.AES_128_GCM_SHA256,
                       secret=bytes(32), version=1)

    def test_each_plan_decrypts_across_wrap_and_reorder_without_nonce_reuse(self):
        for scenario in a.CASES:
            expected = 6
            wires = {}
            for index, (pn, width) in enumerate(a.plan(scenario, expected)):
                if pn not in wires:
                    wires[pn] = a.protected(self.key, b"D" * 8, pn, width,
                                            index.to_bytes(8, "big"), expected)
                _, plain, decoded, _ = self.key.decrypt_packet(wires[pn], 9, expected)
                self.assertEqual(decoded, pn, scenario)
                self.assertEqual(plain[:2], b"\x01\x1a")
                expected = max(expected, pn + 1)

    def test_forgery_and_wrong_reconstruction_cannot_supply_a_receive_fence(self):
        wire = a.protected(self.key, b"D" * 8, 256, 1, bytes(8), 255)
        with self.assertRaises(CryptoError):
            self.key.decrypt_packet(wire[:-1] + bytes([wire[-1] ^ 1]), 9, 255)
        with self.assertRaises(CryptoError):
            self.key.decrypt_packet(wire, 9, 0)


class ResponseTests(unittest.TestCase):
    def ledger(self):
        ledger = Ledger()
        ledger.register(0, "GET")
        return ledger

    def test_wrong_status_body_fin_and_extra_response_are_rejected(self):
        for mode in ("status", "body", "truncated", "missing-fin", "extra"):
            ledger = self.ledger()
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                ledger.receive(HeadersReceived(headers=[(b":status", b"500" if mode == "status"
                                                         else b"200")],
                                               stream_id=0, stream_ended=False))
                ledger.receive(DataReceived(data=b"wrong" if mode == "body" else
                                            BODY[:-1] if mode == "truncated" else BODY,
                                            stream_id=0, stream_ended=mode != "missing-fin"))
                if mode == "extra":
                    ledger.receive(DataReceived(data=b"", stream_id=0, stream_ended=True))
                ledger.finish(1)


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_receive_transmit_timer_and_socket_errors_propagate(self):
        for method, arguments in (("datagram_received", (b"wire", ("127.0.0.1", 1))),
                                  ("transmit", ()), ("_handle_timer", ())):
            client = a.WireClient(QuicConnection(configuration=QuicConfiguration(is_client=True)))
            with patch.object(Client, method, side_effect=RuntimeError("injected callback")):
                getattr(client, method)(*arguments)
            with self.assertRaisesRegex(RuntimeError, "injected callback"):
                client.check()
            self.assertTrue(client.changed.is_set())
        client.error_received(RuntimeError("later socket failure"))
        with self.assertRaisesRegex(RuntimeError, "injected callback"):
            client.check()  # Preserve the first error.

    async def test_normal_closure_cannot_hide_earlier_failure(self):
        client = a.WireClient(QuicConnection(configuration=QuicConfiguration(is_client=True)))
        event = ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        client.closing = True
        client.quic_event_received(event)
        client.check()
        client.fail(RuntimeError("first failure"))
        client.quic_event_received(event)
        with self.assertRaisesRegex(RuntimeError, "first failure"):
            client.check()

    async def test_missing_probe_and_callback_failure_do_not_advance_history(self):
        client = a.WireClient(QuicConnection(configuration=QuicConfiguration(
            is_client=True, quic_logger=a.QuicLogger())))
        client._quic._quic_logger = SimpleNamespace(_events=[])
        ledger = a.AckLedger(100, {})
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(a.await_probe(client, ledger, 100, bytes(8), 0, {}), 0.01)
        client.fail(RuntimeError("failed receive callback"))
        with self.assertRaisesRegex(RuntimeError, "failed receive callback"):
            await a.await_probe(client, ledger, 100, bytes(8), 0, {})
        self.assertEqual(ledger.history, ())

    async def test_server_exit_silence_and_sigterm_resistance_are_bounded(self):
        cases = (("raise SystemExit(17)", "server exited"),
                 ("import time; time.sleep(60)", "deadline"),
                 ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                  "time.sleep(60)", "deadline"))
        for source, expected in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as root:
                binary = Path(root) / "fake-server"
                binary.write_text(f"#!{sys.executable}\n{source}\n")
                binary.chmod(0o755)
                report = await asyncio.wait_for(
                    runner.run_case(binary, "ascending-oldest", timeout=0.2), 4)
                self.assertFalse(report["passed"])
                self.assertIn(expected, report["error"])
                if "SIG_IGN" in source:
                    self.assertEqual(report["process"]["exit"], -signal.SIGKILL)
                with self.assertRaises(ProcessLookupError):
                    os.kill(report["process"]["pid"], 0)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind(("127.0.0.1", report["server_port"]))

    async def test_failure_artifact_survives_and_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            args = SimpleNamespace(output=Path(root) / "evidence", scenario="oldest-boundary",
                                   binary=Path("/bin/false"), threads=1, timeout=0.2)
            with patch("builtins.print"):
                self.assertEqual(await runner.main(args), 1)
            path = args.output / "oldest-boundary.json"
            saved = path.read_bytes()
            self.assertFalse(json.loads(saved)["passed"])
            self.assertIsNotNone(json.loads(saved)["process"]["exit"])
            with self.assertRaises(FileExistsError):
                await runner.main(args)
            self.assertEqual(path.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
