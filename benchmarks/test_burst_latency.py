"""Independent byte-level sample oracle and phase/controller failure checks."""
from copy import deepcopy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import burst_latency as l
import burst_workers as b
from test_burst_workers import fixture


class SampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'samples.bin'
        # Two bursts, deliberately out of stream order; sorted by exact duration.
        self.samples = [(4, 10, 12), (12, 20, 23), (0, 10, 14), (8, 20, 27)]
        self.meta = dict(version=2, producer=0, phase=1, first_stream=0, count=4, expected=4,
                         bytes=128, end_ns=30)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, samples=None, head=None):
        # Do not use the implementation's packer: this is the wire format oracle.
        self.path.write_bytes(struct.pack('<8sIIQQ', *(head or (b'HFBSTL02', 1, 0, 0, 4))) +
                              b''.join(struct.pack('<QQQ', *s) for s in
                                       (self.samples if samples is None else samples)))

    def validate(self):
        return l.validate(self.path, self.meta, 1, 0, 4, 2)

    def test_exact_per_request_quantiles_include_every_worker_and_preserve_warmup(self):
        self.write()
        one = self.validate()
        self.assertEqual(l.summarize([one, one]), dict(count=8, min_ns=2, p50_ns=3,
                         p99_ns=7, p99_9_ns=7, max_ns=7, sum_ns=32, mean_ns=4))
        warm_path = self.path.with_name('warmup.bin')
        warm_path.write_bytes(struct.pack('<8sIIQQQQQ', b'HFBSTL02', 0, 0, 0, 1, 0, 1, 101))
        warm_meta = dict(version=2, producer=0, phase=0, first_stream=0, count=1, expected=1, bytes=56, end_ns=101)
        warm = l.validate(warm_path, warm_meta, 0, 0, 1, 1)
        evidence = [one, warm]
        for producer in range(1, 4):
            path = self.path.with_name(f'producer-{producer}.bin')
            raw = bytearray(self.path.read_bytes())
            struct.pack_into('<I', raw, 12, producer)
            path.write_bytes(raw)
            meta = dict(self.meta, producer=producer)
            evidence.append(l.validate(path, meta, 1, 0, 4, 2, producer=producer))
        result = l.finish(evidence)
        self.assertEqual(result['measured']['count'], 16)
        self.assertEqual(result['measured']['p99_9_ns'], 7)
        self.assertEqual(result['warmup']['count'], 1)
        self.assertEqual(result['warmup']['min_ns'], 100)
        with self.assertRaisesRegex(ValueError, 'repeated producer'):
            l.finish([*evidence, one])

    def test_zero_reversed_and_outside_phase_times_fail(self):
        for sample in [(4, 10, 10), (4, 10, 9), (4, 10, 31), (4, 0, 0)]:
            with self.subTest(sample=sample), self.assertRaisesRegex(ValueError, 'timestamp'):
                self.write([sample, *self.samples[1:]])
                self.validate()

    def test_duplicate_missing_wrong_alignment_and_wrong_stream_fail(self):
        for sample in [(0, 10, 12), (16, 10, 12), (5, 10, 12)]:
            with self.subTest(sample=sample), self.assertRaisesRegex(ValueError, 'duplicate|stream'):
                self.write([sample, *self.samples[1:]])
                self.validate()

    def test_phase_count_first_and_magic_in_header_are_independently_checked(self):
        for header in [(b'HFBSTL03', 1, 0, 0, 4), (b'HFBSTL02', 0, 0, 0, 4),
                       (b'HFBSTL02', 1, 0, 4, 4), (b'HFBSTL02', 1, 0, 0, 3),
                       (b'HFBSTL02', 1, 1, 0, 4)]:
            with self.subTest(header=header), self.assertRaisesRegex(ValueError, 'header'):
                self.write(head=header)
                self.validate()

    def test_truncated_oversized_and_partial_records_fail_before_allocating(self):
        for delta in (-128, -120, -1, 1, 24):
            self.write()
            raw = self.path.read_bytes()
            self.path.write_bytes(raw[:len(raw) + delta] if delta < 0 else raw + b'x' * delta)
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, 'sample file'):
                self.validate()

    def test_symlink_and_fifo_do_not_block_the_reader(self):
        target = self.path.with_name('target')
        target.write_bytes(b'x' * 128)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            self.validate()
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaisesRegex(ValueError, 'nonregular'):
            self.validate()

    def test_burst_timestamps_must_match_and_serial_bursts_cannot_overlap(self):
        for samples in [[(4, 11, 13), *self.samples[1:]],
                        [(4, 10, 12), (12, 13, 16), (0, 10, 14), (8, 13, 20)]]:
            self.write(samples)
            with self.assertRaisesRegex(ValueError, 'timestamps differ|overlapping'):
                self.validate()

    def test_sorted_export_and_unchanged_bytes_are_required_for_exact_merge(self):
        self.write(self.samples[::-1])
        with self.assertRaisesRegex(ValueError, 'unsorted'):
            self.validate()
        self.write()
        evidence = self.validate()
        self.write([(4, 9, 11), *self.samples[1:]])
        with self.assertRaisesRegex(ValueError, 'changed'):
            l.summarize([evidence])

    def test_work_and_metadata_bounds_reject_invalid_types_and_limits(self):
        l.limits(32, 32, 4096, 64, 128)
        for args in [(32, 32, 4097, 1, 1), (32, 32, 1, 1, 4097), (1, 1, 1, 65, 1),
                     (1, 1, 0, 1, 1), (True, 1, 1, 1, 1), (1, 1, 1.0, 1, 1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                l.limits(*args)
        for field, value in [('count', 3), ('count', 5), ('count', True), ('version', 1),
                             ('phase', 0), ('producer', 1), ('first_stream', 4), ('bytes', 127),
                             ('end_ns', 0), ('end_ns', -1), ('end_ns', None),
                             ('end_ns', 1 << 64), ('end_ns', float('nan'))]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                l.metadata(dict(self.meta, **{field: value}), 1, 0, 4)

    def test_ready_report_cannot_claim_completed_samples(self):
        ready = dict(self.meta, count=0, bytes=32, end_ns=None)
        l.metadata(ready, 1, 0, 4, ready=True)
        with self.assertRaises(ValueError):
            l.metadata(self.meta, 1, 0, 4, ready=True)
        with self.assertRaises(ValueError):
            l.metadata(ready, 1, 0, 4)


class ControllerTests(unittest.TestCase):
    def test_prepare_export_and_sample_scans_are_outside_wall_and_cpu_intervals(self):
        warm = fixture()
        timed = fixture(warm, 1)
        for phase, row in enumerate((warm, timed)):
            row['latency'] = dict(version=2, producer=0, phase=phase, first_stream=phase * 2048,
                expected=512, count=512, bytes=32 + 512 * 24, end_ns=100)
        ready = dict(phase=1, latency_ready=dict(timed['latency'], count=0, bytes=32, end_ns=None))
        events = []
        process = Mock(pid=123)
        process.stdin.write.side_effect = lambda s: events.append(s.decode().strip())
        process.wait.side_effect = lambda **_: events.append('reaped') or 0
        counters = dict(InDatagrams=100, OutDatagrams=100, **{k: 0 for k in b.ERROR_COUNTERS})

        def collect(*_):
            return [next(reports)]

        def cpu(_):
            events.append('cpu')
            return dict(user=0, system=0)

        def clock():
            events.append('clock')
            return len(events)

        def export(*_):
            events.append('export')
            return []

        def validate(_):
            self.assertIn('reaped', events)
            events.append('scan')
            return []

        reports = iter([warm, ready, timed])
        summary = dict(version=2, interval=l.INTERVAL, measured=dict(count=512, p50_ns=2,
                       p99_ns=3, p99_9_ns=4), warmup=dict(count=512))
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(b.subprocess, 'Popen', return_value=process), \
                patch.object(b.os, 'set_blocking'), patch.object(b.os, 'read', return_value=b''), \
                patch.object(b, 'udp', return_value=counters), \
                patch.object(b, 'settle', return_value=counters), \
                patch.object(b, 'collect', side_effect=collect), \
                patch.object(b, 'cpu', side_effect=cpu), \
                patch.object(b.time, 'perf_counter', side_effect=clock), \
                patch.object(b, 'validate_delivery'), patch.object(b.failure, 'observe'), \
                patch.object(b.failure, 'cleanup', return_value=[]), \
                patch.object(b, 'export_latency', side_effect=export), \
                patch.object(l, 'validate_exports', side_effect=validate), \
                patch.object(l, 'finish', return_value=summary):
            result = b.coordinate(Path('/unused'), 234, 9999, Path(temp), [1],
                                  32, 8, 2, 1, 2, True, latency=True)
        self.assertEqual(events, ['export', 'PREPARE 1 2', 'cpu', 'cpu', 'clock',
            'RUN 1 2', 'clock', 'cpu', 'cpu', 'export', 'STOP', 'reaped', 'scan'])
        self.assertEqual(result['measured_requests'], 512)

    def test_mode_and_every_request_count_are_part_of_the_protocol_gate(self):
        row = fixture()
        with self.assertRaisesRegex(RuntimeError, 'sampling mode'):
            b.validate_report(row, None, 0, 2, 32, 8, True)
        row['latency'] = dict(version=2, producer=0, phase=0, first_stream=0, expected=512,
                              count=512, bytes=32 + 512 * 24, end_ns=100)
        b.validate_report(row, None, 0, 2, 32, 8, True)
        with self.assertRaisesRegex(RuntimeError, 'sampling mode'):
            b.validate_report(row, None, 0, 2, 32, 8)
        for field, value in [('count', 511), ('phase', 1), ('producer', 1), ('first_stream', 2048)]:
            wrong = deepcopy(row)
            wrong['latency'][field] = value
            with self.assertRaises(ValueError):
                b.validate_report(wrong, None, 0, 2, 32, 8, True)
        wrong = deepcopy(row)
        wrong['quiet']['completed'] = 1
        with self.assertRaisesRegex(RuntimeError, 'quiet'):
            b.validate_report(wrong, None, 0, 2, 32, 8, True)

    def test_comparison_rejects_mixed_missing_or_incomplete_latency(self):
        default = dict(measured_requests=4, completed=6)
        data = dict(version=2, interval=l.INTERVAL, measured=dict(count=4, p50_ns=2,
                    p99_ns=3, p99_9_ns=4), warmup=dict(count=2))
        sampled = dict(default, latency=data)
        self.assertEqual(l.compare(default, default, False), {})
        self.assertEqual(l.compare(sampled, sampled, True), dict(p50_percent=0, p99_percent=0,
                                                               p99_9_percent=0))
        for a, c, mode in [(default, sampled, False), (sampled, default, True),
                           (default, default, True)]:
            with self.assertRaises(ValueError):
                l.compare(a, c, mode)
        for section in ('measured', 'warmup'):
            broken = deepcopy(sampled)
            broken['latency'][section]['count'] -= 1
            with self.assertRaises(ValueError):
                l.compare(sampled, broken, True)

    def test_export_failure_propagates_original_producer_error(self):
        class Input:
            def write(self, _):
                pass
        class Process:
            stdin = Input()
        error = RuntimeError('worker 3 exited in phase 1; see worker stderr')
        with patch.object(b, 'collect', side_effect=error), self.assertRaises(RuntimeError) as caught:
            b.export_latency([dict(process=Process())], [], Path('.'), 1, 4, .1)
        self.assertIs(caught.exception, error)

    def test_export_metadata_cannot_swap_a_phase_or_omit_a_request(self):
        class Input:
            def write(self, command):
                self.command = command
        class Process:
            stdin = Input()
        worker = dict(process=Process())
        report = dict(latency=dict(phase=1, count=4))
        with patch.object(b, 'collect', return_value=[dict(phase=1, latency_export=dict(phase=0, count=4))]), \
                self.assertRaisesRegex(RuntimeError, 'export metadata'):
            b.export_latency([worker], [report], Path('.'), 1, 4, .1)
        self.assertEqual(worker['process'].stdin.command, b'EXPORT 1\n')


if __name__ == '__main__':
    unittest.main()
