"""Independent counts, clock brackets, overlap and exported-sample oracles."""
from copy import deepcopy
from pathlib import Path
import struct
import tempfile
import unittest

import burst_latency as latency
import burst_schedule as s
import burst_workers as workers
from test_burst_workers import fixture


def configs():
    return [dict(role='hot' if i == 0 else 'cold', batch=32 if i == 0 else 1,
                 datagrams=32 if i == 0 else 1, batches=1024 if i == 0 else 4096,
                 delay_ns=5_000_000 if i == 0 else 0) for i in range(4)]


def stamp():
    return dict(phase=1, latency=dict(producer=0, end_ns=600), phase_clock=dict(
        clock='CLOCK_MONOTONIC', namespace='time:[1]', run_at_ns=1040, start_ns=1050,
        end_ns=1800, epoch_low_ns=1000, epoch_high_ns=1002,
        first_sent_ns=100, last_complete_ns=400))


class ScheduleTests(unittest.TestCase):
    def test_explicit_fixed_counts_and_resource_bounds(self):
        self.assertEqual(s.validate(configs(), 4, 2, 64), 1024)
        for field, value in [('batches', 4097), ('batch', True), ('datagrams', 33),
                             ('delay_ns', -1), ('delay_ns', 100_000_001), ('role', 'cold')]:
            bad = configs()
            bad[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                s.validate(bad, 4, 2, 64)
        bad = configs()
        bad[1]['batch'] = 3
        with self.assertRaisesRegex(ValueError, 'divide'):
            s.validate(bad, 4, 2, 64)
        with self.assertRaises(ValueError):
            s.validate(configs()[:3], 4, 2, 64)

    def test_partial_credit_neither_omits_nor_invents_a_grant(self):
        # 512 completions with a 1024-request grant step must retain initial credit.
        row = fixture()
        for name in ('active', 'quiet'):
            row[name].update(initial_limit=2048, stream_limit=2048)
        workers.validate_report(row, None, 0, 2, 32, 8, initial_window=1024)
        for name, key, delta in [('active', 'stream_limit', 512), ('active', 'stream_limit', -1),
                                 ('quiet', 'initial_limit', -2), ('work', 'requests', -1)]:
            bad = deepcopy(row)
            bad[name][key] += delta
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                workers.validate_report(bad, None, 0, 2, 32, 8, initial_window=1024)
        with self.assertRaisesRegex(RuntimeError, 'batches'):
            workers.validate_report(row, None, 0, 3, 32, 8, initial_window=1024)

    def test_clock_mapping_is_bracketed_and_inside_the_controller_interval(self):
        result = s.clock(stamp(), 1040, 1000, 1900, 'time:[1]')
        self.assertEqual(result, dict(producer=0, phase=1, first_low_ns=1100,
            first_high_ns=1102, last_low_ns=1400, last_high_ns=1402, clock_uncertainty_ns=2))
        for key, value in [('clock', 'CLOCK_REALTIME'), ('namespace', 'time:[2]'),
                           ('run_at_ns', 1041), ('start_ns', 1039), ('end_ns', 1901),
                           ('end_ns', 1601), ('epoch_low_ns', 1003), ('epoch_high_ns', -1),
                           ('first_sent_ns', 400), ('last_complete_ns', 601),
                           ('first_sent_ns', True)]:
            bad = stamp()
            bad['phase_clock'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.clock(bad, 1040, 1000, 1900, 'time:[1]')

    def test_every_cold_interval_must_conservatively_contain_the_hot_interval(self):
        intervals = [dict(producer=i, phase=1, first_low_ns=1200 if i == 0 else 1100,
            first_high_ns=1202 if i == 0 else 1102, last_low_ns=1500 if i == 0 else 1600,
            last_high_ns=1502 if i == 0 else 1602, clock_uncertainty_ns=2) for i in range(4)]
        good = s.overlap(intervals, configs())
        self.assertTrue(good['suitable'])
        self.assertEqual(good['cold'][0]['initial_margin_ns'], 98)
        self.assertEqual(good['cold'][0]['final_margin_ns'], 98)
        for index in (1, 2, 3):
            for key, value in [('first_high_ns', 1201), ('last_low_ns', 1501)]:
                bad = deepcopy(intervals)
                bad[index][key] = value
                self.assertFalse(s.overlap(bad, configs())['suitable'])
        bad = deepcopy(intervals)
        bad[1]['phase'] = 2
        with self.assertRaisesRegex(ValueError, 'mixed'):
            s.overlap(bad, configs())
        with self.assertRaisesRegex(ValueError, 'producer'):
            s.overlap([*intervals[:3], intervals[0]], configs())

    def test_raw_files_independently_bind_every_reported_endpoint_and_population(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence, reports = [], []
            for phase in (0, 1):
                rows = []
                for producer in range(4):
                    path = Path(temp) / f'{phase}-{producer}.bin'
                    # Two serial one-request bursts; second has the longer latency.
                    first = phase * 8
                    path.write_bytes(struct.pack('<8sIIQQ', b'HFBSTL02', phase, producer, first, 2)
                        + struct.pack('<QQQ', first, 10, 12 + producer)
                        + struct.pack('<QQQ', first + 4, 20, 30 + producer))
                    meta = dict(version=2, producer=producer, phase=phase, first_stream=first,
                                count=2, expected=2, bytes=80, end_ns=40)
                    evidence.append(latency.validate(path, meta, phase, first, 2, 1, producer))
                    rows.append(dict(phase=phase, latency=meta, phase_clock=dict(
                        first_sent_ns=10, last_complete_ns=30 + producer)))
                reports.append(rows)
            groups = s.finish(evidence, reports, configs())
            self.assertEqual(groups['hot']['count'], 2)
            self.assertEqual(groups['cold']['count'], 6)
            self.assertEqual([r['count'] for r in groups['producers']], [2] * 4)
            self.assertEqual(groups['cold']['max_ns'], 13)
            for phase in (0, 1):
                for key in ('first_sent_ns', 'last_complete_ns'):
                    bad = deepcopy(reports)
                    bad[phase][3]['phase_clock'][key] += 1
                    with self.assertRaisesRegex(ValueError, 'endpoints'):
                        s.finish(evidence, bad, configs())
            for bad in (evidence[:-1], [*evidence[:-1], evidence[0]]):
                with self.assertRaises(ValueError):
                    s.finish(bad, reports, configs())

    def test_comparisons_reject_changed_counts_delays_and_unsuitable_runs(self):
        row = dict(schedule=dict(config=configs(), suitable=True, initial_window=1024,
                   warmup_batches=2, cycles=2, barrier_lead_ns=50_000_000), cycles=[{}, {}],
                   producer_sha256='fixed-peer', client_cpus=[1, 2, 3, 4], gro=True, smoke=True,
                   udp_receive_buffer=dict(status='available', effective_bytes=8192, requested_bytes=4096),
                   measured_requests=8, completed=12,
                   latency=dict(version=2, interval=latency.INTERVAL, warmup=dict(count=4),
                                measured=dict(count=8, p50_ns=1, p99_ns=2, p99_9_ns=3)))
        s.compare(row, row)
        for key in ('batches', 'delay_ns'):
            bad = deepcopy(row)
            bad['schedule']['config'][1][key] += 1
            with self.assertRaisesRegex(ValueError, 'different'):
                s.compare(row, bad)
        bad = deepcopy(row)
        bad['schedule']['suitable'] = False
        with self.assertRaisesRegex(ValueError, 'unsuitable'):
            s.compare(row, bad)


if __name__ == '__main__':
    unittest.main()
