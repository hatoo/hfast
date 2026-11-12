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


def unsent_fixture():
    # Hand-counted: two full-response batches, one non-ACKing PING, one
    # incomplete-request batch, one STOP/reset batch, one response, two PINGs.
    row = dict(responses=65, cancelled_requests=16, resets=16, receive_resets=16,
               reset_acks=16, retired_streams=81, window=64, survivors=64,
               prime_responses=64, followup_responses=1, sent_packets=8,
               received_packets=8, leftover_datagrams=0, outstanding_responses=0,
               outstanding_resets=0, sent_request_bytes=1458, receive_reset_final_bytes=288,
               completed_before_reset_ack=0, credit_before_reset_ack=128,
               advertised_stream_limit=208, unadvertised_credit=1,
               seconds=.1, cancellation_seconds=.01, server_cpu_seconds=.02,
               response_latency_ns=[1000]*65, cancellation_latency_ns=[2000]*16)
    second = {**copy.deepcopy(row), "completed_before_reset_ack": 81,
              "credit_before_reset_ack": 208, "advertised_stream_limit": 289}
    return dict(window=64, cancellations=16, batch=32, stop_batch=64, mode="unsent",
                request_size=18, errors=0, unexpected_packets=0, duplicate_responses=0,
                duplicate_resets=0, initial_stream_limit=128, responses=130,
                cancelled_requests=32, resets=32, retired_streams=162, request_bytes=2916,
                advertised_stream_limit=289, warmup=row, cycles=[second], warmup_cycles=1, extra_warmup=[])


def validate_unsent(report):
    return s.validate(report, 64, 16, 32, 64, 1, "unsent")


class UnsentAccountingTests(unittest.TestCase):
    def test_exact_separate_ledgers(self):
        validate_unsent(unsent_fixture())

    def test_every_count_and_credit_field_is_checked(self):
        for scope in ("warmup", "cycle", "final"):
            original = unsent_fixture()
            selected = original if scope == "final" else original["warmup"] if scope == "warmup" else original["cycles"][0]
            for key, value in selected.items():
                if type(value) is not int:
                    continue
                for delta in (-1, 1):
                    with self.subTest(scope=scope, key=key, delta=delta):
                        report = copy.deepcopy(original)
                        target = report if scope == "final" else report["warmup"] if scope == "warmup" else report["cycles"][0]
                        target[key] += delta
                        with self.assertRaises(ValueError):
                            validate_unsent(report)

    def test_samples_cannot_be_lost_duplicated_or_nonfinite(self):
        for key in ("response_latency_ns", "cancellation_latency_ns"):
            for change in ("drop", "duplicate", "zero", "negative", "nan", "late"):
                report = unsent_fixture()
                samples = report["cycles"][0][key]
                if change == "drop":
                    samples.pop()
                elif change == "duplicate":
                    samples.append(samples[0])
                else:
                    samples[0] = dict(zero=0, negative=-1, nan=float("nan"), late=100_000_000)[change]
                with self.assertRaises(ValueError):
                    validate_unsent(report)

    def test_cancelled_streams_are_not_http_successes(self):
        report = unsent_fixture()
        report["responses"] += report["cancelled_requests"]
        with self.assertRaises(ValueError):
            validate_unsent(report)

    def test_extra_warmup_is_accounted_separately(self):
        report = unsent_fixture()
        report["extra_warmup"] = report["cycles"]
        row = {**copy.deepcopy(report["cycles"][0]), "completed_before_reset_ack": 162,
               "credit_before_reset_ack": 289, "advertised_stream_limit": 370}
        report.update(warmup_cycles=2, cycles=[row], responses=195, cancelled_requests=48,
                      resets=48, retired_streams=243, request_bytes=4374, advertised_stream_limit=370)
        s.validate(report, 64, 16, 32, 64, 1, "unsent", 2)
        report["extra_warmup"] = []
        with self.assertRaises(ValueError):
            s.validate(report, 64, 16, 32, 64, 1, "unsent", 2)

    def test_missing_cycles_fields_or_invalid_times_fail(self):
        for key in unsent_fixture():
            report = unsent_fixture()
            del report[key]
            with self.assertRaises((ValueError, KeyError)):
                validate_unsent(report)
        for key in ("seconds", "cancellation_seconds", "server_cpu_seconds"):
            for value in (-1, float("nan"), float("inf")):
                report = unsent_fixture()
                report["warmup"][key] = value
                with self.assertRaises(ValueError):
                    validate_unsent(report)


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
