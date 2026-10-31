"""Reject incomplete/corrupt native evidence before it can establish a gain."""
from copy import deepcopy
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import tcp_churn_cohort as cohort


class CohortOracle(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.meta = dict(client='/tmp/frozen-client', port=30000,
                         requests_per_child=2048, start_ns=1_000_000_000,
                         end_ns=21_000_000_000, server_alive=True, children=[])
        self.report = dict(requests=dict(total=2048, ok=2048, errors=0, connectErrors=0),
                           statusCodes={'200': 2048}, latencySamples=2048,
                           protocol='HTTP/1.1', connections=64, threads=1, url=cohort.child_url(0, 30000),
                           bytesSent=2048 * 60, bytesReceived=2048 * 78,
                           durationSeconds=18, requestsPerSec=2048 / 18,
                           latencySeconds=dict(min=.001, mean=.005, max=.01,
                             percentiles={p: (i + 1) / 1000 for i, p in enumerate(cohort.PERCENTILES)}))
        for i, cpu in enumerate(cohort.CLIENT_CPUS):
            url = cohort.child_url(i, 30000)
            command = cohort.timed_command(Path(self.meta['client']), 30000, i, 2048)
            self.meta['children'].append(dict(index=i, cpu=cpu, launch_ns=1_000_000_001 + i,
                complete_ns=21_000_000_000, exit_code=0, url=url,
                destination=[f'127.0.0.{i + 1}', 30000],
                command=command, actual_command=command.copy()))
            (self.folder / f'child-{i}.json').write_text(json.dumps(dict(self.report, url=url)))
            (self.folder / f'child-{i}.cpu').write_text('4 3 19 2000\n')
        self.report['url'] = cohort.child_url(1, 30000)

    def result(self):
        return cohort.validate_cohort(self.folder, self.meta)

    def test_complete_common_interval(self):
        row = self.result()
        self.assertEqual(row['requests_per_sec'], 16384 / 20)
        self.assertNotEqual(row['requests_per_sec'], 8 * 2048 / 18)
        self.assertEqual(row['latency_samples'], 16384)
        self.assertEqual(row['producer_cores'], [.35] * 8)

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
                 ('threads', 2), ('connections', 7), ('protocol', 'HTTP/2'),
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
        command[command.index('--batch-size') + 1] = '64'
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

    def samples(self):
        def process(pid, seconds, workers, core, index=None):
            result = dict(pid=pid, timestamp_ns=int((1 + seconds) * 1e9) + core + 1,
                tids=[dict(tid=pid + i, start_ticks=10, affinity=[core],
                    user=seconds / workers, system=0, runtime=seconds / workers,
                    runqueue=0, timeslices=seconds) for i in range(workers)])
            if index is not None:
                result['index'] = index
            return result
        return [dict(timestamp_ns=int((1 + s) * 1e9), complete_ns=int((1 + s) * 1e9) + 100,
            server=process(100, s, 1, 1),
            clients=[process(200 + i * 100, s, 2, cpu, i)
                     for i, cpu in enumerate(cohort.CLIENT_CPUS)]) for s in range(20)]

    def test_active_worker_interval_excludes_reporting_tail(self):
        samples = self.samples()
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
        row = dict(wall=20, server_cores=.95, producer_cores=[.5] * 8,
                   active_cpu=dict(seconds=18, server_cores=.96, producer_cores=[.6] * 8))
        self.assertTrue(cohort.qualification(row)['passed'])
        for section, key, value in [(None, 'server_cores', .84), (None, 'wall', 9),
                ('active_cpu', 'server_cores', .84), ('active_cpu', 'seconds', 9),
                ('active_cpu', 'producer_cores', [.5] * 7 + [.90])]:
            bad = deepcopy(row)
            (bad if section is None else bad[section])[key] = value
            with self.subTest(key=key):
                self.assertFalse(cohort.qualification(bad)['passed'])


    def test_destination_assignment_and_port_width(self):
        self.assertEqual([cohort.child_url(i, 32123) for i in range(8)],
                         [f'http://127.0.0.{i}:32123/' for i in range(1, 9)])
        for index, port in [(8, 32123), (-1, 32123), (True, 32123), (0, 9999), (0, 65536)]:
            with self.subTest(index=index, port=port), self.assertRaises(ValueError):
                cohort.child_url(index, port)

    def test_wrong_or_duplicate_destination_is_rejected_for_every_child(self):
        good = deepcopy(self.meta)
        for i in range(8):
            for field, value in [('url', cohort.child_url((i + 1) % 8, 30000)),
                                 ('destination', ['127.0.0.1', 30001]),
                                 ('actual_command', ['/bin/true'])]:
                self.meta = deepcopy(good)
                self.meta['children'][i][field] = value
                with self.subTest(i=i, field=field), self.assertRaises(ValueError):
                    self.result()

    def test_shared_destination_cannot_be_hidden_by_consistent_commands(self):
        child = self.meta['children'][7]
        child['url'] = cohort.child_url(0, 30000)
        child['destination'] = ['127.0.0.1', 30000]
        child['command'][-1] = child['url']
        child['actual_command'] = child['command'].copy()
        (self.folder / 'child-7.json').write_text(json.dumps(dict(self.report, url=child['url'])))
        with self.assertRaises(ValueError):
            self.result()

    def test_each_child_must_supply_every_count(self):
        for i in range(8):
            path = self.folder / f'child-{i}.json'
            original = path.read_text()
            for field in ['latencySamples', 'bytesSent', 'bytesReceived']:
                report = json.loads(original)
                report[field] -= 1
                path.write_text(json.dumps(report))
                with self.subTest(i=i, field=field), self.assertRaises(ValueError):
                    self.result()
            path.write_text(original)

    def test_cpu_intervals_and_counters_cannot_be_forged(self):
        cases = [lambda s: s[10]['clients'][0].update(index=1),
                 lambda s: s[10].update(timestamp_ns=s[9]['timestamp_ns']),
                 lambda s: s[10]['server'].update(timestamp_ns=s[9]['timestamp_ns']),
                 lambda s: s[10]['server']['tids'][0].update(runtime=-1),
                 lambda s: s[10]['server']['tids'][0].update(runtime=float('nan')),
                 lambda s: s[10]['server']['tids'][0].update(runtime=1),
                 lambda s: s[10]['server']['tids'][0].update(start_ticks=11),
                 lambda s: s[10]['clients'][7]['tids'][1].update(affinity=[8]),
                 lambda s: s[10]['clients'][7]['tids'].append(s[10]['clients'][7]['tids'][0]),
                 lambda s: s[10]['clients'][7].update(pid=9000),
                 lambda s: s[10].update(complete_ns=s[11]['timestamp_ns'])]
        for i, mutate in enumerate(cases):
            samples = self.samples()
            mutate(samples)
            with self.subTest(i=i), self.assertRaises(ValueError):
                cohort.active_cpu(samples)

    def test_impossible_cpu_wall_time_is_rejected(self):
        path = self.folder / 'child-7.cpu'
        for text in ['4 3 17 2000', '4 3 21 2000', '18 3 19 2000']:
            path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.result()

    def test_nonfinite_or_missing_rates_cannot_qualify(self):
        row = dict(wall=20, server_cores=.95, producer_cores=[.5] * 8,
                   active_cpu=dict(seconds=18, server_cores=.96, producer_cores=[.6] * 8))
        for key, value in [('server_cores', float('nan')), ('producer_cores', [.5] * 7)]:
            bad = deepcopy(row)
            bad['active_cpu'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                cohort.qualification(bad)

    def test_disappeared_client_cannot_create_a_hole_in_the_active_interval(self):
        samples = self.samples()
        samples[-1]['clients'].pop()
        active = cohort.active_cpu(samples)
        self.assertEqual(active['seconds'], 18)
        self.assertEqual(active['end_ns'], 19_000_000_000)
        samples[10]['clients'].pop()
        with self.assertRaisesRegex(ValueError, 'discontinuous shared worker interval'):
            cohort.active_cpu(samples)


@unittest.skipUnless(sys.platform == 'linux', 'Linux process snapshots')
class SnapshotOracle(unittest.TestCase):
    def child(self):
        process = subprocess.Popen(['/bin/sleep', '20'], start_new_session=True)
        self.addCleanup(cohort.stop, [process])
        core = min(os.sched_getaffinity(0))
        os.sched_setaffinity(process.pid, {core})
        return process, core

    def exit_after_task_listing(self, process):
        iterdir = Path.iterdir

        def listed(path):
            entries = list(iterdir(path))
            if path == Path(f'/proc/{process.pid}/task'):
                self.assertTrue(entries)
                process.terminate()
                process.wait(timeout=2)
            return iter(entries)

        return patch.object(Path, 'iterdir', listed)

    def test_exit_between_task_listing_and_read_is_process_disappearance(self):
        process, _ = self.child()
        with self.exit_after_task_listing(process), self.assertRaises(ProcessLookupError):
            cohort.process_snapshot(process.pid)

    def test_finished_client_is_omitted_from_cpu_sample(self):
        process, core = self.child()
        with patch.object(cohort, 'child_pid', return_value=process.pid), \
             patch.object(cohort, 'CLIENT_CPUS', (core,)), \
             self.exit_after_task_listing(process):
            self.assertIsNone(cohort.sample_client(None, Path('/bin/sleep').resolve(), 0))

    def test_live_client_wrong_affinity_is_still_fatal_and_identified(self):
        process, core = self.child()
        with patch.object(cohort, 'child_pid', return_value=process.pid), \
             patch.object(cohort, 'CLIENT_CPUS', (core + 1,)), \
             self.assertRaisesRegex(ValueError, f'unexpected task affinity.*{process.pid}') as error:
            cohort.sample_client(None, Path('/bin/sleep').resolve(), 0)
        self.assertIn(f'expected [{core + 1}]', str(error.exception))
        self.assertIn(str([core]), str(error.exception))
        self.assertIsNone(process.poll())

    def test_live_client_and_non_disappearance_errors(self):
        process, core = self.child()
        with patch.object(cohort, 'child_pid', return_value=process.pid), \
             patch.object(cohort, 'CLIENT_CPUS', (core,)):
            snapshot = cohort.sample_client(None, Path('/bin/sleep').resolve(), 0)
            self.assertEqual(snapshot['pid'], process.pid)
            self.assertEqual(snapshot['index'], 0)
            self.assertEqual([t['affinity'] for t in snapshot['tids']], [[core]])
            cohort.validate_snapshot(snapshot)
            for error in (PermissionError('denied'), ValueError('invalid counter')):
                with patch.object(cohort, 'process_snapshot', side_effect=error), \
                     self.assertRaises(type(error)):
                    cohort.sample_client(None, Path('/bin/sleep').resolve(), 0)
        with self.assertRaises(ValueError):
            cohort.assert_affinity(dict(pid=process.pid, tids=[]), core)

    def test_server_disappearance_still_invalidates_the_cohort(self):
        process, _ = self.child()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'cohort'
            with self.exit_after_task_listing(process), self.assertRaises(ProcessLookupError):
                cohort.run_clients(Path('/bin/sleep'), process, 30000, folder, 1)
            failure = json.loads((folder / 'failure.json').read_text())
            self.assertIn('ProcessLookupError', failure['error'])
            self.assertFalse((folder / 'summary.json').exists())
            self.assertEqual(json.loads((folder / 'cleanup.json').read_text())['owned_groups'], [])


@unittest.skipUnless(sys.platform == 'linux', 'Linux process group cleanup')
class CleanupOracle(unittest.TestCase):
    def test_failed_or_stalled_child_cleans_every_owned_wrapper(self):
        server = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, inject, timeout, error in [('failed', True, 3, 'exited 17'),
                                                ('stalled', None, .05, 'cohort timeout')]:
                folder = root / name
                with patch.object(cohort, 'client_command', return_value=['/bin/sleep', '20']), \
                     patch.object(cohort, 'assert_affinity'), \
                     self.assertRaisesRegex(ValueError, error):
                    cohort.run_clients(Path('/bin/sleep'), server, 30000, folder, 1,
                                       timeout=timeout, inject_failure=inject)
                cleanup = json.loads((folder / 'cleanup.json').read_text())
                self.assertEqual(len(cleanup['owned_groups']), 8)
                self.assertTrue(all(code is not None for code in cleanup['exit_codes']))
                self.assertTrue((folder / 'failure.json').is_file())
                for pid in cleanup['owned_groups']:
                    self.assertFalse(Path(f'/proc/{pid}').exists())

    def test_exited_wrapper_does_not_hide_surviving_descendant(self):
        # Linux subreaper keeps this test's orphan local so the test can reap it.
        # Run in a helper to avoid changing the unittest process's child ownership.
        helper = r'''
import ctypes, os, signal, subprocess, sys
from pathlib import Path
import tcp_churn_cohort as cohort
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
wrapper = subprocess.Popen([sys.executable, '-c',
    'import os,time,signal; pid=os.fork(); '
    'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
    'print(pid,flush=True) if pid else time.sleep(20)'],
    stdout=subprocess.PIPE, text=True, start_new_session=True)
child = int(wrapper.stdout.readline())
try:
    assert wrapper.wait(timeout=3) == 0
    cohort.stop([wrapper])
    pid, status = os.waitpid(child, 0)
    assert pid == child and os.WIFSIGNALED(status)
finally:
    try: os.killpg(wrapper.pid, signal.SIGKILL)
    except ProcessLookupError: pass
'''
        result = subprocess.run([sys.executable, '-c', helper],
                                cwd=Path(cohort.__file__).parent, timeout=10,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
