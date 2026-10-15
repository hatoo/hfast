#!/usr/bin/env python3
"""Negative accounting oracles and bounded controller/process failure tests."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import burst_workers as b


def fixture(previous=None, phase=0, batches=2):
    batch, datagrams = 32, 8
    first = previous['active']['completed'] if previous else 0
    count = batches * batch * datagrams
    work = dict(batches=batches, requests=count, first_completed=first, completed=first + count,
                request_datagrams=batches * datagrams, fences=batches,
                sent_datagrams=batches * (datagrams + 1), sent_messages=batches * 2,
                received_datagrams=batches * 8, burst_seconds=.1)
    row = dict(phase=phase, work=work, quiet_pings=phase + 1,
               pending_requests=0, pending_fences=0, errors=0)
    for index, name in enumerate(('active', 'quiet')):
        completed = first + count if name == 'active' else 0
        old = previous[name] if previous else dict(sent_datagrams=10, sent_messages=10,
                    received_datagrams=10, last_sent=10, last_received=10, packet_count=10)
        sent = work['sent_datagrams'] + 1 if name == 'active' else 2
        messages = work['sent_messages'] + 1 if name == 'active' else 2
        received = work['received_datagrams'] if name == 'active' else 1
        row[name] = dict(port=10000 + index, completed=completed, next_stream=4 * completed,
                         initial_limit=512, stream_limit=512 + completed,
                         initial_max_data=1 << 20, max_data=(1 << 20) + completed * 18,
                         sent_data=5 + 18 * completed,
                         sent_datagrams=old['sent_datagrams'] + sent,
                         sent_messages=old['sent_messages'] + messages,
                         received_datagrams=old['received_datagrams'] + received,
                         last_sent=old['last_sent'] + sent,
                         acked_through=old['last_sent'] + sent - 1,
                         last_received=old['last_received'] + received,
                         packet_count=old['packet_count'] + received)
    return row


class AccountingTests(unittest.TestCase):
    def test_warmup_and_timed_work_have_disjoint_exact_ledgers(self):
        ready = fixture()
        timed = fixture(ready, 1, 3)
        b.validate_report(ready, None, 0, 2, 32, 8)
        b.validate_report(timed, ready, 1, 3, 32, 8)
        self.assertEqual(timed['work']['requests'], 768)
        self.assertEqual(timed['active']['completed'], 1280)
        delta = {k: b.totals([timed])[k] - b.totals([ready])[k] for k in b.COUNTERS}
        self.assertEqual(delta, dict(sent_datagrams=30, sent_messages=9, received_datagrams=25))

    def test_missing_duplicate_credit_fence_and_pending_work_fail(self):
        ready = fixture()
        good = fixture(ready, 1, 3)
        corruptions = [
            ('active', 'completed', -1), ('active', 'completed', 1),
            ('active', 'next_stream', 4), ('active', 'stream_limit', -1),
            ('active', 'sent_data', 1), ('active', 'max_data', 1 << 21),
            ('active', 'acked_through', -1), ('active', 'received_datagrams', -1),
            ('active', 'sent_messages', 1), ('active', 'last_received', 1),
            ('quiet', 'completed', 1), ('quiet', 'stream_limit', 1),
            ('quiet', 'acked_through', -1), ('quiet', 'port', 2),
            ('work', 'first_completed', -256), ('work', 'fences', -1),
            ('work', 'requests', -1), ('work', 'received_datagrams', 1),
        ]
        for section, key, delta in corruptions:
            with self.subTest(section=section, key=key, delta=delta):
                row = deepcopy(good)
                row[section][key] += delta
                with self.assertRaises(RuntimeError):
                    b.validate_report(row, ready, 1, 3, 32, 8)
        for key in ('phase', 'quiet_pings', 'pending_requests', 'pending_fences', 'errors'):
            row = deepcopy(good)
            row[key] += 1
            with self.assertRaises(RuntimeError):
                b.validate_report(row, ready, 1, 3, 32, 8)

    def test_one_peers_extra_response_cannot_hide_another_peers_missing_response(self):
        rows = [fixture() for _ in range(4)]
        rows[0]['active']['completed'] -= 1
        rows[1]['active']['completed'] += 1
        self.assertEqual(sum(r['active']['completed'] for r in rows), 2048)
        for row in rows[:2]:
            with self.assertRaises(RuntimeError):
                b.validate_report(row, None, 0, 2, 32, 8)

    def test_global_counters_are_checked_once_against_all_peers(self):
        rows = [fixture() for _ in range(4)]
        ledger = b.totals(rows)
        before = {k: 0 for k in (*b.ERROR_COUNTERS, 'InDatagrams', 'OutDatagrams')}
        for gro in (False, True):
            after = dict(before)
            after['InDatagrams'] = ledger['sent_messages' if gro else 'sent_datagrams'] + ledger['received_datagrams']
            after['OutDatagrams'] = ledger['sent_messages'] + ledger['received_datagrams']
            b.validate_delivery(before, after, ledger, gro)
            for omitted in (rows[:3], rows + rows[:1]):
                with self.assertRaises(RuntimeError):
                    b.validate_delivery(before, after, b.totals(omitted), gro)
            for key in after:
                corrupt = dict(after)
                corrupt[key] += 1
                with self.assertRaises(RuntimeError):
                    b.validate_delivery(before, corrupt, ledger, gro)
            after['InDatagrams'] -= 1  # includes a final ACK left unread
            with self.assertRaises(RuntimeError):
                b.validate_delivery(before, after, ledger, gro)


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workers = []

    def tearDown(self):
        for worker in self.workers:
            process = worker['process']
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            process.stdin.close()
            process.stdout.close()
            worker['stdout'].close()
        self.temp.cleanup()

    def spawn(self, code):
        process = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, bufsize=0)
        os.set_blocking(process.stdout.fileno(), False)
        worker = dict(process=process, buffer=b'', stdout=(Path(self.temp.name) /
                      f'{len(self.workers)}.log').open('xb'))
        self.workers.append(worker)

    def test_independent_interleavings_and_phase_boundaries(self):
        for delay in (.03, .01, .04, .02):
            self.spawn(f'''import json, time, sys
time.sleep({delay})
print(json.dumps(dict(phase=0, identity={delay})), flush=True)
input()
time.sleep({.05 - delay})
print(json.dumps(dict(phase=1, identity={delay})), flush=True)
input()
''')
        first = b.collect(self.workers, 0, 2)
        for worker in self.workers:
            worker['process'].stdin.write(b'RUN\n')
        second = b.collect(self.workers, 1, 2)
        self.assertEqual([r['identity'] for r in first], [r['identity'] for r in second])

    def test_worker_failure_propagates(self):
        self.spawn('import sys; sys.exit(7)')
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            b.collect(self.workers, 0, 2)

    def test_partial_report_is_bounded(self):
        self.spawn('import sys; sys.stdout.write("partial"); sys.stdout.flush(); input()')
        with self.assertRaisesRegex(RuntimeError, 'timeout'):
            b.collect(self.workers, 0, .2)

    def test_duplicate_report_is_rejected(self):
        self.spawn('import sys; sys.stdout.write(\'{"phase":0}\\n{"phase":0}\\n\'); sys.stdout.flush(); input()')
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            b.collect(self.workers, 0, 2)

    def test_wrong_phase_is_rejected(self):
        self.spawn('print(\'{"phase":1}\', flush=True); input()')
        with self.assertRaisesRegex(RuntimeError, 'phase'):
            b.collect(self.workers, 0, 2)

    def test_mid_phase_failure_cancels_all_other_workers(self):
        created = []
        popen = subprocess.Popen

        def spawn(_command, **kwargs):
            index = len(created)
            code = (f'import sys\nprint({json.dumps(fixture())!r}, flush=True)\n'
                    f'input()\n' + ('sys.exit(7)\n' if index == 1 else 'input()\n'))
            process = popen([sys.executable, '-c', code], **kwargs)
            created.append(process)
            return process

        counters = {k: 0 for k in (*b.ERROR_COUNTERS, 'InDatagrams', 'OutDatagrams')}
        with patch.object(b.subprocess, 'Popen', side_effect=spawn), \
                patch.object(b, 'udp', return_value=counters), \
                patch.object(b, 'settle', return_value=counters):
            with self.assertRaisesRegex(RuntimeError, 'exited'):
                b.coordinate(Path('/unused'), os.getpid(), 1234, Path(self.temp.name),
                             [0, 1, 2, 3], 32, 8, 3, 1, 2, True, timeout=2)
        self.assertEqual(len(created), 4)
        self.assertTrue(all(process.poll() is not None for process in created))
        self.assertIn('phase 1', (Path(self.temp.name) / 'failure.txt').read_text())

    def test_report_after_final_phase_cannot_escape_validation(self):
        popen = subprocess.Popen
        ready = fixture()
        done = fixture(ready, 1, 3)

        def spawn(_command, **kwargs):
            code = (f'print({json.dumps(ready)!r}, flush=True)\ninput()\n'
                    f'print({json.dumps(done)!r}, flush=True)\ninput()\n'
                    f'print({json.dumps(done)!r}, flush=True)\n')
            return popen([sys.executable, '-c', code], **kwargs)

        counters = {k: 0 for k in (*b.ERROR_COUNTERS, 'InDatagrams', 'OutDatagrams')}
        with patch.object(b.subprocess, 'Popen', side_effect=spawn), \
                patch.object(b, 'udp', return_value=counters), \
                patch.object(b, 'settle', return_value=counters), \
                patch.object(b, 'validate_delivery'):
            with self.assertRaisesRegex(RuntimeError, 'after STOP'):
                b.coordinate(Path('/unused'), os.getpid(), 1234, Path(self.temp.name),
                             [0], 32, 8, 3, 1, 2, True, timeout=2)


if __name__ == '__main__':
    unittest.main()
