import copy
import unittest

import stop_batch as s


def fixture():
    # Independent hand-counted 1,024 response / 64 sparse stop fixture:
    # 32 request packets, one stop packet, one request fence and two PINGs.
    row = dict(responses=1025, resets=64, window=1024, survivors=960,
               prime_responses=1024, followup_responses=1, sent_packets=36,
               received_packets=36, leftover_datagrams=0, outstanding_responses=0,
               outstanding_resets=0, seconds=.1, cancellation_seconds=.01,
               server_cpu_seconds=.02, credit_before_reset_ack=2048,
               advertised_stream_limit=3072, completed_before_reset_ack=0, unadvertised_credit=1)
    second = {**row, "credit_before_reset_ack": 3072, "advertised_stream_limit": 4097,
              "completed_before_reset_ack": 1025}
    return dict(window=1024, cancellations=64, batch=32, stop_batch=64, mode="plain",
                errors=0, unexpected_packets=0, duplicate_responses=0, duplicate_resets=0,
                initial_stream_limit=2048, advertised_stream_limit=4097,
                responses=2050, resets=128, warmup=row, cycles=[second])


def validate(report):
    return s.validate(report, 1024, 64, 32, 64, 1, "plain")


class AccountingTests(unittest.TestCase):
    def test_exact_fixture_passes(self):
        validate(fixture())

    def test_missing_duplicate_unexpected_or_outstanding_work_fails(self):
        for key in ("responses", "resets", "survivors", "prime_responses", "followup_responses",
                    "sent_packets", "received_packets", "leftover_datagrams",
                    "outstanding_responses", "outstanding_resets", "completed_before_reset_ack",
                    "unadvertised_credit"):
            for delta in (-1, 1):
                with self.subTest(key=key, delta=delta):
                    r = fixture()
                    r["cycles"][0][key] += delta
                    with self.assertRaises(ValueError):
                        validate(r)

    def test_credit_missing_duplicated_and_premature_fails(self):
        for scope in ("warmup", "cycle", "final"):
            for delta in (-1, 1):
                r = fixture()
                row = r if scope == "final" else r["warmup"] if scope == "warmup" else r["cycles"][0]
                row["advertised_stream_limit"] += delta
                with self.assertRaises(ValueError):
                    validate(r)
        r = fixture()
        r["cycles"][0]["credit_before_reset_ack"] += 64
        with self.assertRaises(ValueError):
            validate(r)

    def test_corrupt_timing_fails(self):
        for key in ("seconds", "cancellation_seconds", "server_cpu_seconds"):
            for value in (-1, float("nan"), float("inf")):
                r = fixture()
                r["cycles"][0][key] = value
                with self.assertRaises(ValueError):
                    validate(r)
        for value in (0, .1, .2):
            r = fixture()
            r["cycles"][0]["cancellation_seconds"] = value
            with self.assertRaises(ValueError):
                validate(r)

    def test_errors_and_total_mismatches_fail(self):
        for key in ("errors", "unexpected_packets", "duplicate_responses", "duplicate_resets",
                    "responses", "resets", "initial_stream_limit"):
            r = fixture()
            r[key] += 1
            with self.assertRaises(ValueError):
                validate(r)

    def test_missing_extra_and_omitted_reports_fail(self):
        for rows in ([], fixture()["cycles"]*2):
            r = fixture()
            r["cycles"] = rows
            with self.assertRaises(ValueError):
                validate(r)
        for key in fixture():
            r = fixture()
            del r[key]
            with self.assertRaises((ValueError, KeyError)):
                validate(r)

    def test_wrong_workload_fails(self):
        for key in ("window", "cancellations", "batch", "stop_batch", "mode"):
            r = fixture()
            r[key] = "repeat" if key == "mode" else r[key]+1
            with self.assertRaises(ValueError):
                validate(r)

    def test_prime_count_closed_form_matches_explicit_ledger(self):
        for window in (64, 1024, 65536):
            for batch in (1, 8, 32):
                ledger, batches = 0, 0
                while ledger != window:
                    if batches and batches % 64 == 0:
                        ledger -= batch
                    ledger += batch
                    batches += 1
                self.assertEqual(s.prime_batches(window, batch), batches)
        self.assertEqual(s.prime_batches(65536, 32), 2080)

    def test_udp_loss_error_and_unread_datagrams_fail(self):
        before = dict(InDatagrams=10, OutDatagrams=10, InErrors=0, RcvbufErrors=0,
                      SndbufErrors=0, InCsumErrors=0, NoPorts=0)
        after = {**before, "InDatagrams": 50, "OutDatagrams": 50}
        s.validate_udp(before, after)
        for key in before:
            bad = copy.copy(after)
            bad[key] += 1
            with self.assertRaises(ValueError):
                s.validate_udp(before, bad)


if __name__ == "__main__":
    unittest.main()
