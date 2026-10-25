"""Independent clocks, worker failures and live one-producer overflow oracles."""
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

import concurrent_uploads as c
import udp_accounting as udp


def reports():
    ready, rows = [], []
    for i, (lo, hi) in enumerate(((100, 300), (150, 400))):
        before = dict(status='available', inode=i + 1, rcvbuf=8192, drops=0)
        evidence = dict(status='available', drops=0, before=before, after=before)
        ready.append(dict(phase='ready', tls_ready=True, port=1234 + i, streams=1,
                          body_bytes_per_stream=1000, mode='ordinary', sent_data=0,
                          sent_packets=0, udp=copy.deepcopy(evidence)))
        rows.append(dict(phase='done', error=None, mode='ordinary', body_bytes_per_stream=1000,
            completed=1, latencies_ns=[100 + i], control_acked=True, port=1234 + i,
            streams=[dict(id=0, sent=1024, end=1024, body_acked=1000, acked_ranges=[[0, 1023]],
                          fin_sent=True, fin_acked=True, response_fin=True, response_ranges=[[0, 24]],
                          latency_ns=100 + i)], sent_data=1029, max_data=2048, max_flights=64,
            received_ranges=[[0, 10]], acked_packet_ranges=[[0, 10]], suppressed_ack_only_ranges=[],
            udp=evidence, elapsed_ns=hi - lo, interval=dict(start_monotonic_ns=lo,
            end_monotonic_ns=hi, elapsed_ns=hi - lo, cpu_elapsed_ns=50),
            total_sent_datagrams=10, total_received_datagrams=15))
    return ready, rows


class Accounting(unittest.TestCase):
    def aggregate(self, rows, ready):
        return c.aggregate(rows, ready, 1, 1000, 'ordinary', 50, 500)

    def test_overlapping_intervals_use_union_and_keep_every_sample(self):
        ready, rows = reports()
        result = self.aggregate(rows, ready)
        self.assertEqual(result['elapsed_ns'], 300)
        self.assertEqual(result['overlap_ns'], 150)
        self.assertEqual(result['start_skew_ns'], 50)
        self.assertEqual(result['completed'], 2)
        self.assertEqual(result['body_bytes'], 2000)
        self.assertEqual(result['latencies_ns'], [100, 101])
        self.assertAlmostEqual(result['requests_per_second'], 2e9 / 300)

    def test_one_missing_failed_or_incomplete_worker_invalidates_all(self):
        ready, rows = reports()
        with self.assertRaises(ValueError):
            self.aggregate(rows[:1], ready)
        for i in range(2):
            for key, value in [('phase', 'failed'), ('completed', 0), ('latencies_ns', []),
                               ('body_bytes_per_stream', 999), ('mode', 'sparse'), ('port', 1)]:
                bad = copy.deepcopy(rows)
                bad[i][key] = value
                with self.subTest(i=i, key=key), self.assertRaises((AssertionError, ValueError)):
                    self.aggregate(bad, ready)
        self.assertEqual(rows[0]['latencies_ns'], [100])

    def test_bad_barrier_and_socket_identity_are_rejected(self):
        ready, rows = reports()
        for key, value in [('tls_ready', False), ('sent_data', 1), ('sent_packets', 1),
                           ('port', ready[0]['port']), ('streams', 2)]:
            bad = copy.deepcopy(ready)
            bad[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.aggregate(rows, bad)
        bad = copy.deepcopy(ready)
        bad[1]['udp']['after']['inode'] = bad[0]['udp']['after']['inode']
        with self.assertRaises(ValueError):
            self.aggregate(rows, bad)

    def test_clock_skew_reset_and_invalid_duration_are_rejected(self):
        ready, rows = reports()
        for key, value in [('start_monotonic_ns', 49), ('end_monotonic_ns', 501),
                           ('end_monotonic_ns', 90), ('elapsed_ns', 201),
                           ('cpu_elapsed_ns', 0), ('cpu_elapsed_ns', float('nan'))]:
            bad = copy.deepcopy(rows)
            bad[0]['interval'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.aggregate(bad, ready)
        bad = copy.deepcopy(rows)
        bad[0]['latencies_ns'] = [201]
        bad[0]['streams'][0]['latency_ns'] = 201
        with self.assertRaises(ValueError):
            self.aggregate(bad, ready)
        bad = copy.deepcopy(rows)
        bad[1]['interval'].update(start_monotonic_ns=300, end_monotonic_ns=500,
                                  elapsed_ns=200)
        bad[1]['elapsed_ns'] = 200
        with self.assertRaisesRegex(ValueError, 'did not overlap'):
            self.aggregate(bad, ready)

    def test_kernel_overflow_in_either_producer_invalidates_group(self):
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
        for sock in sockets:
            self.addCleanup(sock.close)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            sock.bind(('127.0.0.1', 0))
        peers, sender = sockets[:2], sockets[2]
        before = [udp.process_snapshot(os.getpid(), p.getsockname()[1], 1) for p in peers]
        for target in range(2):
            for _ in range(1024):
                sender.sendto(b'x' * 512, peers[target].getsockname())
            after = [udp.process_snapshot(os.getpid(), p.getsockname()[1], 1) for p in peers]
            deltas = [udp.process_delta(a, b) for a, b in zip(before, after)]
            self.assertGreater(deltas[target]['drops'], 0)
            self.assertEqual(deltas[1 - target]['drops'], 0)
            with self.assertRaisesRegex(ValueError, 'peer UDP loss'):
                udp.require_clean_group(deltas, dict(status='available', drops=0),
                                        dict(status='available', counters={}))
            before = after
        self.assertNotEqual(before[0]['sockets'][0]['cookie'], before[1]['sockets'][0]['cookie'])

    def test_single_shared_namespace_ledger_is_not_doubled(self):
        ready, rows = reports()
        snapshots = []
        for r in rows:
            native = r['udp']['after']
            snapshots.append(dict(status='available', sockets=[native]))
        evidence = dict(peer_before=snapshots, peer_after=snapshots,
                        peer_deltas=[dict(status='available', drops=0)] * 2,
                        server_delta=dict(status='available', drops=0),
                        namespace_delta=dict(status='available', counters=dict(InDatagrams=50, OutDatagrams=50)))
        c.validate_udp(rows, evidence)
        # GSO send accounting can be smaller than the delivered datagram count.
        evidence['namespace_delta']['counters']['OutDatagrams'] = 7
        c.validate_udp(rows, evidence)
        for amount in [25, 49, 51, 100]:
            bad = copy.deepcopy(evidence)
            bad['namespace_delta']['counters']['InDatagrams'] = amount
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                c.validate_udp(rows, bad)
        for who in ['server_delta', 'namespace_delta']:
            bad = copy.deepcopy(evidence)
            bad[who]['status'] = 'unavailable'
            with self.assertRaises(ValueError):
                c.validate_udp(rows, bad)
        for who in ['peer_before', 'peer_after', 'peer_deltas']:
            bad = copy.deepcopy(evidence)
            bad[who] = []
            with self.assertRaisesRegex(ValueError, 'missing live producer'):
                c.validate_udp(rows, bad)

    def test_real_complete_reports_reject_sample_and_clock_omissions(self):
        path = os.environ.get('CONCURRENT_UPLOAD_VALID_RESULT')
        if not path:
            self.skipTest('set CONCURRENT_UPLOAD_VALID_RESULT after the native smoke')
        result = json.loads(Path(path).read_text())
        def validate(result):
            return c.aggregate(result['workers'], result['ready'], result['streams_per_producer'],
                               result['body_bytes_per_stream'], result['mode'],
                               result['controller_start_ns'], result['controller_end_ns'])
        validate(result)
        for index in range(2):
            bad = copy.deepcopy(result)
            bad['workers'][index]['udp']['drops'] = 1
            with self.assertRaises(ValueError):
                validate(bad)
            self.assertEqual(bad['workers'][index]['latencies_ns'], result['workers'][index]['latencies_ns'])


class Collection(unittest.TestCase):
    def collect(self, codes, phase='ready', maximum=1024, timeout=1):
        workers = []
        for code in codes:
            process = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE,
                                       stdin=subprocess.PIPE)
            workers.append(dict(process=process, log=io.BytesIO(), buffer=b''))
        try:
            return c.collect(workers, phase, timeout, maximum)
        finally:
            self.raw = [w['log'].getvalue() for w in workers]
            for worker in workers:
                worker['process'].kill()
                worker['process'].communicate(timeout=2)

    def test_two_ready_required_and_either_stall_exit_or_malformed_fails(self):
        valid = 'import sys; print(\'{"phase":"ready"}\',flush=True); sys.stdin.read()'
        self.assertEqual(self.collect([valid, valid]), [dict(phase='ready')] * 2)
        for bad in ['pass', 'import time; time.sleep(5)', 'print("{bad}",flush=True)',
                    'print(\'{"phase":"done"}\',flush=True)', 'print("x"*2048,flush=True)']:
            for index in range(2):
                codes = [valid, valid]
                codes[index] = bad
                with self.subTest(index=index, bad=bad), self.assertRaises(ValueError):
                    self.collect(codes, timeout=.2)

    def test_failed_terminal_is_retained_with_successful_sibling(self):
        codes = ['import sys; print(\'{"phase":"%s"}\',flush=True); sys.stdin.read()' % p
                 for p in ['done', 'failed']]
        self.assertEqual(self.collect(codes, phase='done'), [dict(phase='done'), dict(phase='failed')])
        self.assertIn(b'failed', self.raw[1])

    def test_duplicate_and_truncated_reports_are_not_success(self):
        for code in ['import os; os.write(1,b\'{"phase":"ready"}\\n{"phase":"ready"}\\n\')',
                     'print(\'{"phase":"ready"}\',end="",flush=True)']:
            with self.assertRaises(ValueError):
                self.collect([code])


if __name__ == '__main__':
    unittest.main()
