"""Failure controls for the independent critical-stream wire oracle."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

from aioquic.quic.crypto import CryptoError

spec = importlib.util.spec_from_file_location(
    "critical_stream", Path(__file__).with_name("critical-stream-check.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def valid(kind="control", terminal="fin"):
    critical = kind in fixture.CRITICAL
    count = 2 if critical else 4
    return dict(kind=kind, terminal=terminal, critical=critical, width=1,
                handshake=True, before_completed=2, acked_prefix=1, prefix_length=1,
                started=count, completed=count, body_bytes=13 * count,
                latency_seconds=[0.01] * count, dropped=[], delivered=[],
                drop_first=False,
                close=dict(error_code=0x104, frame_type=None) if critical else None)


class OracleTests(unittest.TestCase):
    def test_remote_close_is_observable_before_draining_timer_but_not_local_close(self):
        event = fixture.ConnectionTerminated(error_code=0x104, frame_type=None,
                                             reason_phrase="")
        quic = SimpleNamespace(_state=fixture.QuicConnectionState.DRAINING,
                               _close_event=event)
        self.assertEqual(fixture.remote_close(quic),
                         dict(error_code=0x104, frame_type=None, reason=""))
        for state in (fixture.QuicConnectionState.CLOSING,
                      fixture.QuicConnectionState.CONNECTED):
            quic._state = state
            self.assertIsNone(fixture.remote_close(quic))

    def test_all_critical_and_tolerated_cases(self):
        for kind in (*fixture.CRITICAL, "unknown", "empty", "partial"):
            for terminal in ("fin", "reset"):
                fixture.validate(valid(kind, terminal))

    def test_baseline_observation_is_not_a_passing_candidate(self):
        row = valid("unknown")
        row.update(kind="control", critical=True)
        fixture.validate(row, observe=True)
        with self.assertRaises(AssertionError):
            fixture.validate(row)

    def test_wrong_or_missing_application_close_fails(self):
        for close in (None, dict(error_code=0, frame_type=None),
                      dict(error_code=0x104, frame_type=0),
                      dict(error_code=0x08, frame_type=0)):
            row = valid()
            row["close"] = close
            with self.subTest(close=close), self.assertRaises(AssertionError):
                fixture.validate(row)

    def test_missing_prefix_ack_and_bad_case_metadata_fail(self):
        for field, value in (("acked_prefix", 0), ("prefix_length", 0),
                             ("width", 8), ("handshake", False),
                             ("critical", False), ("kind", "bogus"),
                             ("terminal", "none"), ("before_completed", 0)):
            row = valid()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                fixture.validate(row)

    def test_exact_completion_body_and_sample_counts(self):
        for field, value in (("started", 3), ("completed", 1), ("completed", 3),
                             ("body_bytes", 25), ("body_bytes", 27),
                             ("latency_seconds", [0.01]),
                             ("latency_seconds", [0.01] * 3),
                             ("latency_seconds", [float("nan"), 0.01]),
                             ("latency_seconds", [-1, 0.01])):
            row = valid()
            row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                fixture.validate(row)

    def test_harmless_close_and_incomplete_final_drain_fail(self):
        for field, value in (("close", dict(error_code=0x104, frame_type=None)),
                             ("completed", 2), ("started", 5)):
            row = valid("unknown")
            row[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                fixture.validate(row)

    def test_loss_requires_one_identical_recovered_packet(self):
        packet = dict(pn=5, code=0x104, reason="", sha256="a" * 64)
        row = valid()
        row.update(drop_first=True, dropped=[packet], delivered=[copy.copy(packet)])
        fixture.validate(row)
        for field, value in (("dropped", []), ("delivered", []),
                             ("delivered", [packet, packet]),
                             ("delivered", [dict(packet, pn=6)]),
                             ("drop_first", False)):
            bad = copy.deepcopy(row)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                fixture.validate(bad)

    def test_loss_is_injected_only_after_authentication_and_only_once(self):
        plain = b"\x1d\x41\x04\x00"
        calls = []

        def decrypt(packet):
            calls.append(packet)
            if packet == b"bad tag":
                raise CryptoError("authentication failed")
            return b"header", plain, 7

        loss = fixture.CloseLoss(decrypt)
        with self.assertRaises(CryptoError):
            loss(b"bad tag")
        self.assertEqual(loss.dropped, [])
        with self.assertRaisesRegex(CryptoError, "injected"):
            loss(b"authenticated close")
        self.assertEqual(loss(b"authenticated close"), (b"header", plain, 7))
        self.assertEqual(loss.dropped, loss.delivered)
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
