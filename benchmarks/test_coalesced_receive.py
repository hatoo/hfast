"""Negative wire/accounting oracles and bounded fixture lifecycle checks."""

import asyncio
from dataclasses import replace
import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoContext

import coalesced_receive as c

spec = importlib.util.spec_from_file_location(
    "coalesced_runner", Path(__file__).with_name("coalesced-receive-check.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class WireTests(unittest.TestCase):
    def setUp(self):
        self.key = CryptoContext()
        self.key.setup(cipher_suite=tls.CipherSuite.AES_128_GCM_SHA256,
                       secret=bytes(32), version=1)
        self.dcid, self.scid = b"D" * 8, b"S" * 8

    def packet(self, pn=1, **kwargs):
        return c.protected(c.Type.INITIAL, self.key, self.dcid, self.scid, pn, **kwargs)

    def test_all_token_length_and_packet_number_widths(self):
        for token_bytes in (0, 1, 63, 64, 255):
            for width in (1, 2, 4, 8):
                for pn_width in (1, 2, 3, 4):
                    with self.subTest(token=token_bytes, width=width, pn_width=pn_width):
                        packet = self.packet(2, token=b"T" * token_bytes, width=width,
                                             pn_width=pn_width)
                        _, report = c.layout([self.packet(), packet], 8)
                        self.assertEqual(report["packets"][1]["start"], len(self.packet().wire))
                        self.assertEqual(report["packets"][1]["token_bytes"], token_bytes)

    def test_noncanonical_varints_round_trip_independent_reader(self):
        for width in (1, 2, 4, 8):
            for value in (0, 1, (1 << (width * 8 - 2)) - 1):
                buf = Buffer(data=c.varint(value, width))
                self.assertEqual(buf.pull_uint_var(), value)
                self.assertTrue(buf.eof())
        for value, width in ((64, 1), (-1, 2), (1, 3)):
            with self.assertRaises(RuntimeError):
                c.varint(value, width)

    def test_short_samples_do_not_borrow_from_successor(self):
        for length in range(20):
            packet = c.opaque(c.Type.INITIAL, self.dcid, self.scid, length,
                              mode="short-sample")
            _, report = c.layout([packet, self.packet()], 8)
            self.assertFalse(report["packets"][0]["sample_fits"])
            self.assertTrue(report["packets"][1]["sample_fits"])
            with self.assertRaisesRegex(RuntimeError, "lacks protection sample"):
                c.layout([replace(packet, crypto=self.key, mode="authenticated"),
                          self.packet()], 8)
        with self.assertRaisesRegex(RuntimeError, "unexpectedly fits"):
            c.layout([replace(self.packet(), mode="short-sample")], 8)

    def test_forged_and_valid_authentication_expectations(self):
        packet = self.packet()
        forged = replace(packet, wire=packet.wire[:-1] + bytes([packet.wire[-1] ^ 1]),
                         mode="forged")
        c.layout([forged, self.packet(2)], 8)
        with self.assertRaisesRegex(RuntimeError, "failed authentication"):
            c.layout([replace(forged, mode="authenticated")], 8)
        with self.assertRaisesRegex(RuntimeError, "forgery authenticated"):
            c.layout([replace(packet, mode="forged")], 8)
        for changed in (replace(packet, pn=2), replace(packet, plain=b"wrong")):
            with self.assertRaises(RuntimeError):
                c.layout([changed], 8)

    def test_packet_extents_and_kinds_must_match(self):
        packet = self.packet()
        for changed in (replace(packet, kind=c.Type.HANDSHAKE),
                        replace(packet, wire=packet.wire + packet.wire),
                        replace(packet, wire=packet.wire + b"\0")):
            with self.assertRaises(RuntimeError):
                c.layout([changed], 8)
        for prefix in range(1, len(packet.wire)):
            with self.assertRaises((ValueError, RuntimeError)):
                c.layout([replace(packet, wire=packet.wire[:prefix])], 8)


def event(name, kind, frames):
    return dict(name="transport:" + name, data=dict(header=dict(packet_type=kind),
                                                   frames=frames))


class AccountingTests(unittest.TestCase):
    def plan(self):
        events = [event("packet_received", "initial", [dict(frame_type="ack", acked_ranges=[[1, 1], [3, 3]])]),
                  event("packet_sent", "handshake", [dict(frame_type="crypto")]),
                  event("packet_sent", "1RTT", [dict(frame_type="stream", stream_id=0, fin=True)])]
        q = SimpleNamespace(datagrams_to_send=lambda now: [],
                            _quic_logger=SimpleNamespace(_events=events))
        plan = c.Plan(q, "skipped-forged", {})
        plan.done = True
        plan.report["layouts"].append({})
        plan.acked = {1, 3}
        plan.forbidden = {2}
        return plan, events

    def test_exact_acks_transmissions_and_injection(self):
        plan, _ = self.plan()
        plan.finish()
        self.assertEqual(plan.report["initial_acks"], [1, 3])
        self.assertEqual(plan.report["first_request_transmissions"], 1)

    def test_missing_forged_and_unbounded_ack_ranges_fail(self):
        for ranges in ([[1, 1]], [[1, 3]], [[1, 65535]]):
            plan, events = self.plan()
            events[0]["data"]["frames"][0]["acked_ranges"] = ranges
            with self.assertRaises(RuntimeError):
                plan.finish()

    def test_retransmitted_finished_or_request_fails(self):
        for index in (1, 2):
            plan, events = self.plan()
            events.append(events[index])
            with self.assertRaisesRegex(RuntimeError, "retransmitted"):
                plan.finish()

    def test_missing_injection_or_callback_error_fails(self):
        for change in ("missing", "twice", "callback"):
            plan, _ = self.plan()
            if change == "missing":
                plan.done = False
            elif change == "twice":
                plan.report["layouts"].append({})
            else:
                plan.failure = RuntimeError("injected callback error")
            with self.assertRaises(RuntimeError):
                plan.finish()


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
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
                    runner.run_case(binary, "finished", timeout=0.15), 4)
                self.assertFalse(report["passed"])
                self.assertIn(expected, report["error"])
                if "SIG_IGN" in source:
                    self.assertEqual(report["process"]["exit"], -signal.SIGKILL)
                with self.assertRaises(ProcessLookupError):
                    os.kill(report["process"]["pid"], 0)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind(("127.0.0.1", report["server_port"]))


if __name__ == "__main__":
    unittest.main()
