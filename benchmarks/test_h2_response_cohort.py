"""Reject incomplete/corrupt native evidence before it can establish a gain."""
from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest

import h2_response_cohort as cohort


class CohortOracle(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.meta = dict(client='/tmp/frozen-client', url='http://127.0.0.1:30000/',
                         requests_per_child=2048, start_ns=1_000_000_000,
                         end_ns=21_000_000_000, server_alive=True, children=[])
        self.report = dict(requests=dict(total=2048, ok=2048, errors=0, connectErrors=0),
                           statusCodes={'200': 2048}, latencySamples=2048,
                           protocol='HTTP/2', connections=8, threads=1, url=self.meta['url'],
                           bytesSent=80000, bytesReceived=102800,
                           durationSeconds=18, requestsPerSec=2048 / 18,
                           latencySeconds=dict(min=.001, mean=.005, max=.01,
                             percentiles={p: (i + 1) / 1000 for i, p in enumerate(cohort.PERCENTILES)}))
        for i, cpu in enumerate(cohort.CLIENT_CPUS):
            self.meta['children'].append(dict(index=i, cpu=cpu, launch_ns=1_000_000_001 + i,
                complete_ns=21_000_000_000, exit_code=0,
                command=['/usr/bin/time', '-o', 'unused', '-f', '%U %S %e %M', '--',
                    *cohort.client_command(Path(self.meta['client']), self.meta['url'], cpu, 2048)]))
            (self.folder / f'child-{i}.json').write_text(json.dumps(self.report))
            (self.folder / f'child-{i}.cpu').write_text('4 3 19 2000\n')

    def result(self):
        return cohort.validate_cohort(self.folder, self.meta)

    def test_complete_common_interval(self):
        row = self.result()
        self.assertEqual(row['requests_per_sec'], 4096 / 20)
        self.assertNotEqual(row['requests_per_sec'], 2 * 2048 / 18)
        self.assertEqual(row['latency_samples'], 4096)
        self.assertEqual(row['producer_cores'], [.35, .35])

    def test_missing_duplicate_or_failed_child(self):
        good = deepcopy(self.meta)
        for children in [good['children'][:1], [good['children'][0]] * 2]:
            self.meta = dict(good, children=children)
            with self.assertRaises(ValueError):
                self.result()
        self.meta = deepcopy(good)
        self.meta['children'][1]['exit_code'] = 17
        with self.assertRaises(ValueError):
            self.result()

    def test_missing_or_partial_reports(self):
        path = self.folder / 'child-1.json'
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.result()
        for data in ['', '{', '{}']:
            path.write_text(data)
            with self.subTest(data=data), self.assertRaises((ValueError, KeyError)):
                self.result()

    def test_counts_samples_errors_and_settings(self):
        cases = [('requests', dict(total=2048, ok=2047, errors=1, connectErrors=0)),
                 ('requests', dict(total=2047, ok=2047, errors=0, connectErrors=0)),
                 ('statusCodes', {'200': 2047, '503': 1}), ('latencySamples', 2047),
                 ('threads', 2), ('connections', 7), ('protocol', 'HTTP/1.1'),
                 ('url', 'http://wrong/'), ('bytesReceived', 102399), ('bytesSent', -1),
                 ('durationSeconds', 0), ('durationSeconds', 21),
                 ('requestsPerSec', float('nan'))]
        for key, value in cases:
            (self.folder / 'child-1.json').write_text(json.dumps(dict(self.report, **{key: value})))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()

    def test_changed_command_or_cpu(self):
        good = deepcopy(self.meta)
        for key, value in [('cpu', 7), ('command', good['children'][1]['command'][:-1])]:
            self.meta = deepcopy(good)
            self.meta['children'][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
        self.meta = deepcopy(good)
        command = self.meta['children'][1]['command']
        command[command.index('-p') + 1] = '64'
        with self.assertRaises(ValueError):
            self.result()

    def test_invalid_or_partial_latency(self):
        for key, value in [('min', -.1), ('mean', float('nan')), ('mean', .02), ('max', .002)]:
            report = deepcopy(self.report)
            report['latencySeconds'][key] = value
            (self.folder / 'child-1.json').write_text(json.dumps(report))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
        for key in ['p50', 'p99.99']:
            report = deepcopy(self.report)
            del report['latencySeconds']['percentiles'][key]
            (self.folder / 'child-1.json').write_text(json.dumps(report))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()

    def test_clock_and_server_failures(self):
        good = deepcopy(self.meta)
        for key, value in [('start_ns', 0), ('end_ns', 20_000_000_000),
                           ('end_ns', 22_000_000_000), ('server_alive', False)]:
            self.meta = dict(good, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.result()
        self.meta = deepcopy(good)
        self.meta['children'][1]['launch_ns'] = 999_999_999
        with self.assertRaises(ValueError):
            self.result()

    def test_missing_or_invalid_cpu(self):
        path = self.folder / 'child-1.cpu'
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.result()
        for raw in ['', '1 2 3', 'nan 1 19 1000', '-1 1 19 1000']:
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.result()

    def test_pair_byte_mismatch(self):
        row = self.result()
        row['server_cpu_ns_per_request'] = 100
        self.assertEqual(cohort.validate_pair(row, row)['rps_percent'], 0)
        other = deepcopy(row)
        other['bytes']['bytesSent'] += 1
        with self.assertRaises(ValueError):
            cohort.validate_pair(row, other)
        other = deepcopy(row)
        other['rows'][0]['report']['bytesReceived'] -= 1
        other['rows'][1]['report']['bytesReceived'] += 1
        with self.assertRaises(ValueError):
            cohort.validate_pair(row, other)

    def test_active_worker_interval_excludes_reporting_tail(self):
        def process(pid, seconds, workers, core):
            return dict(pid=pid, timestamp_ns=int((1 + seconds) * 1e9), tids=[dict(
                tid=pid + i, start_ticks=10, affinity=[core], user=seconds / workers,
                system=0, runtime=seconds / workers, runqueue=0, timeslices=seconds)
                for i in range(workers)])
        samples = [dict(timestamp_ns=int((1 + s) * 1e9), server=process(100, s, 1, 1),
                        clients=[process(200, s, 2, 8), process(300, s, 2, 9)])
                   for s in range(20)]
        # Child 0 finished requests, while child 1 is still sending requests.
        samples[-1]['clients'][0]['tids'].pop()
        active = cohort.active_cpu(samples)
        self.assertEqual(active['seconds'], 18)
        self.assertEqual(active['server_cores'], 1)
        self.assertEqual(active['end_ns'], 19_000_000_000)
        bad = deepcopy(samples)
        bad[10]['clients'][0]['tids'].pop()
        with self.assertRaises(ValueError):
            cohort.active_cpu(bad)
        bad = deepcopy(samples)
        bad[18]['clients'][0]['tids'][1]['start_ticks'] += 1
        with self.assertRaises(ValueError):
            cohort.active_cpu(bad)

    def test_qualification_requires_server_saturation_and_headroom(self):
        row = dict(wall=20, server_cores=.95, producer_cores=[.5, .6],
                   active_cpu=dict(seconds=18, server_cores=.96, producer_cores=[.6, .7]))
        self.assertTrue(cohort.qualification(row)['passed'])
        for section, key, value in [(None, 'server_cores', .84), (None, 'wall', 9),
                ('active_cpu', 'server_cores', .84), ('active_cpu', 'seconds', 9),
                ('active_cpu', 'producer_cores', [.5, .90])]:
            bad = deepcopy(row)
            (bad if section is None else bad[section])[key] = value
            with self.subTest(key=key):
                self.assertFalse(cohort.qualification(bad)['passed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
