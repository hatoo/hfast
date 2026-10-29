#!/usr/bin/env python3
"""Negative accounting oracles and bounded controller/process failure tests."""
from copy import deepcopy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_cleanup_io_error_cannot_skip_sibling_processes(self):
        for _ in range(4):
            self.spawn('input()')
        real = self.workers[0]['stdout']
        broken = Mock(wraps=real)
        broken.flush.side_effect = OSError('failed stdout flush')
        self.workers[0]['stdout'] = broken
        errors = b.failure.cleanup(self.workers)
        self.assertTrue(any('failed stdout flush' in error for error in errors))
        self.assertTrue(all(w['process'].poll() is not None for w in self.workers))
        self.assertTrue(all(w['process'].stdout.closed for w in self.workers))

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
        evidence = json.loads((Path(self.temp.name) / 'failure.json').read_text())
        self.assertEqual(evidence['phase'], 1)
        self.assertEqual(evidence['last_success']['phase'], 0)
        self.assertEqual(evidence['last_success']['reports'], [fixture()] * 4)
        self.assertEqual(len(evidence['workers']), 4)
        self.assertFalse(evidence['timing_evidence'])

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


class FailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name)
        self.created = []

    def tearDown(self):
        # Assert that the controller, not the test, reaped every process.
        try:
            for process in self.created:
                self.assertIsNotNone(process.poll())
                self.assertTrue(process.stdin.closed and process.stdout.closed)
        finally:
            for process in self.created:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
            self.temp.cleanup()

    def coordinate(self, codes, timeout=.4, patches=()):
        popen = subprocess.Popen

        def spawn(_command, **kwargs):
            code = codes[len(self.created)]
            process = popen([sys.executable, '-c', code], **kwargs)
            self.created.append(process)
            return process

        counters = {k: 0 for k in (*b.ERROR_COUNTERS, 'InDatagrams', 'OutDatagrams')}
        with ExitStack() as stack:
            stack.enter_context(patch.object(b.subprocess, 'Popen', side_effect=spawn))
            stack.enter_context(patch.object(b, 'udp', return_value=counters))
            stack.enter_context(patch.object(b, 'settle', return_value=counters))
            stack.enter_context(patch.object(b, 'validate_delivery'))
            for p in patches:
                stack.enter_context(p)
            b.coordinate(Path('/unused'), os.getpid(), 1234, self.output,
                         [0] * len(codes), 32, 8, 3, 1, 2, True, timeout=timeout)

    def evidence(self):
        return json.loads((self.output / 'failure.json').read_text())

    def test_warmup_timeout_preserves_partial_line_and_live_socket_before_cleanup(self):
        code = ('import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n'
                's.bind(("127.0.0.1",0))\nsys.stdout.buffer.write(b"partial\\xff")\n'
                'sys.stdout.flush()\ninput()\n')
        with self.assertRaisesRegex(RuntimeError, 'phase 0 timeout'):
            self.coordinate([code])
        row = self.evidence()
        self.assertEqual(row['stage'], 'warmup')
        self.assertIsNone(row['last_success'])
        self.assertIsNone(row['namespace_since_last_success']['counters'])
        peer = row['workers'][0]
        self.assertIsNone(peer['exit_code'])
        self.assertIsNone(peer['report'])
        self.assertEqual(bytes.fromhex(peer['partial_stdout_hex']), b'partial\xff')
        self.assertEqual((self.output / peer['stdout']).read_bytes(), b'partial\xff')
        self.assertEqual(peer['sockets']['status'], 'available')
        socket = peer['sockets']['sockets'][0]
        self.assertGreater(socket['inode'], 0)
        self.assertEqual(socket['rx_queue'], 0)
        self.assertEqual(socket['drops'], 0)
        self.assertEqual(len(socket['cookie']), 2)
        self.assertIsNone(peer['socket_delta']['drops'])  # No baseline before warmup.

    def test_bad_json_preserves_original_decode_error_and_exact_raw_bytes(self):
        with self.assertRaises(json.JSONDecodeError) as caught:
            self.coordinate(['print("{bad json}",flush=True); input()'])
        row = self.evidence()
        self.assertEqual(row['original_error']['type'], type(caught.exception).__name__)
        self.assertEqual(bytes.fromhex(row['workers'][0]['report_line_hex']), b'{bad json}')
        self.assertEqual((self.output / 'worker-0.jsonl').read_bytes(), b'{bad json}\n')

    def test_completed_sibling_report_survives_partial_report_timeout(self):
        self.coordinate_failure_with_sibling('import sys; sys.stdout.write("truncated"); '
                                            'sys.stdout.flush(); input()', 'timeout')

    def test_exit_after_report_keeps_report_and_exit_status(self):
        code = f'print({json.dumps(fixture())!r},flush=True)'
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            self.coordinate([code, 'input()'])
        peer = self.evidence()['workers'][0]
        self.assertEqual(peer['report'], fixture())
        self.assertEqual(peer['exit_code'], 0)
        self.assertEqual(peer['sockets']['status'], 'unavailable')
        self.assertIsNone(peer['socket_delta']['drops'])

    def test_stdout_eof_before_waitable_exit_preserves_natural_status(self):
        # Hold the child alive after EOF until capture explicitly waits. This
        # reproduces the CI race without relying on scheduler timing or sleeps.
        code = 'import os,sys; os.close(1); input(); sys.exit(7)'
        wait = subprocess.Popen.wait

        def release(process, *args, **kwargs):
            if process.poll() is None:
                process.stdin.write(b'exit\n')
            return wait(process, *args, **kwargs)

        with patch.object(subprocess.Popen, 'wait', release):
            with self.assertRaisesRegex(RuntimeError, 'exited'):
                self.coordinate([code], timeout=2)
        peer = self.evidence()['workers'][0]
        self.assertTrue(peer['stdout_eof'])
        self.assertEqual(peer['exit_code'], 7)
        self.assertEqual(peer['sockets']['status'], 'unavailable')
        self.assertIsNone(peer['socket_delta']['drops'])
        self.assertEqual(self.created[0].returncode, 7)

    def test_stdout_eof_with_live_socket_keeps_evidence_and_bounds_wait(self):
        code = ('import os,socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n'
                's.bind(("127.0.0.1",0))\nos.close(1)\ninput()\n')
        wait = subprocess.Popen.wait
        waits = []

        def short_wait(process, *args, **kwargs):
            if not waits:
                waits.append(kwargs['timeout'])
                # Exercise a real timeout while keeping the regression fast.
                return wait(process, timeout=.02)
            return wait(process, *args, **kwargs)

        with patch.object(subprocess.Popen, 'wait', short_wait):
            with self.assertRaisesRegex(RuntimeError, 'exited'):
                self.coordinate([code], timeout=2)
        peer = self.evidence()['workers'][0]
        self.assertTrue(peer['stdout_eof'])
        self.assertIsNone(peer['exit_code'])
        self.assertEqual(peer['sockets']['status'], 'available')
        self.assertEqual(len(peer['sockets']['sockets']), 1)
        self.assertIsNone(peer['socket_delta']['drops'])
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0)
        self.assertLessEqual(waits[0], 5)
        self.assertEqual(self.created[0].returncode, -9)

    def coordinate_failure_with_sibling(self, faulty, message):
        code = f'print({json.dumps(fixture())!r},flush=True); input()'
        with self.assertRaisesRegex(RuntimeError, message):
            self.coordinate([code, faulty])
        peers = self.evidence()['workers']
        self.assertEqual(peers[0]['report'], fixture())
        self.assertIsNone(peers[1]['report'])
        self.assertIsNone(self.evidence()['last_success'])

    def test_diagnostic_capture_exception_does_not_replace_primary_or_skip_cleanup(self):
        original = RuntimeError('original collect failure')
        with self.assertRaises(RuntimeError) as caught:
            self.coordinate(['input()'] * 4, patches=[
                patch.object(b, 'collect', side_effect=original),
                patch.object(b.failure, 'capture', side_effect=OSError('unavailable proc'))])
        self.assertIs(caught.exception, original)
        self.assertEqual(self.evidence()['status'], 'unavailable')
        self.assertIn('unavailable proc', self.evidence()['error'])
        self.assertIn('original collect failure', (self.output / 'failure.txt').read_text())

    def test_diagnostic_write_failure_preserves_exception_and_reaps_all_children(self):
        original = RuntimeError('original collect failure')
        path_open = Path.open

        def fail(path, *args, **kwargs):
            if path.name in ('failure.json', 'failure.txt'):
                raise OSError('diagnostic disk full')
            return path_open(path, *args, **kwargs)

        with self.assertRaises(RuntimeError) as caught:
            self.coordinate(['input()'] * 4, patches=[
                patch.object(b, 'collect', side_effect=original),
                patch.object(Path, 'open', fail)])
        self.assertIs(caught.exception, original)
        self.assertIn('diagnostic disk full', '; '.join(original.__notes__))

    def test_raw_log_close_failure_cannot_mask_the_original_or_leave_siblings(self):
        original = RuntimeError('original collect failure')
        path_open = Path.open

        class BrokenClose:
            def __init__(self, file):
                self.file = file

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.file.close()
                raise OSError('raw evidence close failed')

            def write(self, data):
                return self.file.write(data)

            def flush(self):
                return self.file.flush()

        def open_log(path, *args, **kwargs):
            file = path_open(path, *args, **kwargs)
            return BrokenClose(file) if path.name == 'worker-0.jsonl' else file

        with self.assertRaises(RuntimeError) as caught:
            self.coordinate(['input()'] * 4, patches=[
                patch.object(b, 'collect', side_effect=original),
                patch.object(Path, 'open', open_log)])
        self.assertIs(caught.exception, original)
        self.assertIn('raw evidence close failed', '; '.join(original.__notes__))

    def test_unavailable_proc_is_never_zero_loss(self):
        with patch.object(b.failure, 'process_identity', side_effect=PermissionError('no proc')):
            result = b.failure.process_snapshot(os.getpid())
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['sockets'], [])
        self.assertIn('no proc', result['error'])
        delta = b.failure.process_delta(result, result)
        self.assertIsNone(delta['drops'])

    def test_expired_diagnostic_budget_is_unavailable_without_more_socket_reads(self):
        with patch.object(b.failure, 'socket_diagnostics') as diagnostics:
            row = b.failure.process_snapshot(os.getpid(), deadline=0)
        diagnostics.assert_not_called()
        self.assertEqual(row['status'], 'unavailable')
        self.assertIn('deadline expired', row['error'])

    def repeated_table(self, repetitions, *, conflict=False):
        """Replay the identical foreign row seen in post-merge CI40800271894."""
        raw = ('8059: 0100007F:A19C 0100007F:94CE 01 00000000:00000000 '
               '00:00000000 00000000 0 0 135952 2 ffff8c6b2853ee40 0\n')
        duplicate = raw.replace('00000000:00000000', '00000000:00000001') if conflict else raw
        read_text = Path.read_text
        reads = []
        target = Path(f'/proc/{os.getpid()}/net/udp')

        def read(path, *args, **kwargs):
            text = read_text(path, *args, **kwargs)
            if path == target:
                reads.append(text)
                if len(reads) <= repetitions:
                    return text + raw + duplicate
            return text

        return patch.object(Path, 'read_text', read), reads, raw + duplicate

    def test_identical_foreign_row_retries_a_complete_snapshot_and_retains_evidence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            before = b.failure.process_snapshot(os.getpid())
            injection, reads, repeated = self.repeated_table(1)
            with injection:
                after = b.failure.process_snapshot(os.getpid())
        self.assertEqual(after['status'], 'available', after)
        self.assertEqual(len(reads), 2)
        self.assertEqual(b.failure.process_delta(before, after)['drops'], 0)
        rejected = after['rejected_snapshots']
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]['status'], 'unavailable')
        self.assertTrue(rejected[0]['tables']['udp'].endswith(repeated))
        self.assertIn('duplicate UDP inode', rejected[0]['error'])

    def test_persistent_duplicate_rows_remain_unavailable_after_three_attempts(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            injection, reads, _ = self.repeated_table(100)
            with injection:
                row = b.failure.process_snapshot(os.getpid())
        self.assertEqual(len(reads), 3)
        self.assertEqual(row['status'], 'unavailable')
        self.assertEqual(len(row['rejected_snapshots']), 2)
        self.assertIsNone(b.failure.process_delta(row, row)['drops'])

    def test_conflicting_duplicate_rows_are_not_retried(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            injection, reads, _ = self.repeated_table(1, conflict=True)
            with injection:
                row = b.failure.process_snapshot(os.getpid())
        self.assertEqual(len(reads), 1)
        self.assertEqual(row['status'], 'unavailable')
        self.assertIn('conflicting', row['error'])
        self.assertNotIn('rejected_snapshots', row)

    def test_duplicate_retry_uses_the_original_diagnostic_deadline(self):
        injection, reads, _ = self.repeated_table(100)
        with injection, patch.object(b.failure.time, 'monotonic', side_effect=[10, 10, 13]):
            row = b.failure.process_snapshot(os.getpid())
        self.assertEqual(len(reads), 1)
        self.assertEqual(row['status'], 'unavailable')
        self.assertIn('deadline expired', row['error'])
        self.assertEqual(len(row['rejected_snapshots']), 1)

    def test_a_retry_cannot_hide_changed_process_or_socket_ownership(self):
        first = dict(status='unavailable', error='RepeatedUdpRow: duplicate UDP inode',
                     error_kind='RepeatedUdpRow', pid=123, start_ticks=456,
                     netns='net:1', owned_inodes={789: [3]}, sockets=[])
        for key, value in [('pid', 124), ('start_ticks', 457), ('netns', 'net:2'),
                           ('owned_inodes', {790: [3]}), ('owned_inodes', {789: [4]})]:
            good = {k: v for k, v in first.items() if k not in ('error', 'error_kind')}
            good.update(status='available', error=None)
            good[key] = value
            with self.subTest(key=key, value=value), \
                    patch.object(b.failure, '_process_snapshot', side_effect=[deepcopy(first), good]):
                result = b.failure.process_snapshot(123)
            self.assertEqual(result['status'], 'unavailable')
            self.assertIn('identity changed', result['error'])
            self.assertIsNone(b.failure.process_delta(result, result)['drops'])

    def test_other_snapshot_failures_are_not_retried(self):
        for error in ['socket diagnostic deadline expired', 'socket ownership changed',
                      'UDP socket changed during snapshot', 'permission denied']:
            failed = dict(status='unavailable', error=error, error_kind='ValueError')
            with patch.object(b.failure, '_process_snapshot', return_value=failed) as capture:
                result = b.failure.process_snapshot(123)
            self.assertEqual(capture.call_count, 1)
            self.assertIs(result, failed)

    def test_reused_or_missing_socket_identity_has_no_delta(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            before = b.failure.process_snapshot(os.getpid())
            self.assertEqual(before['status'], 'available')
            for field in ('inode', 'cookie', 'fds'):
                after = deepcopy(before)
                after['sockets'][0][field] = ([] if field != 'inode' else 123456789)
                self.assertIsNone(b.failure.process_delta(before, after)['drops'])
            after = deepcopy(before)
            after['sockets'] = []
            self.assertIsNone(b.failure.process_delta(before, after)['drops'])

    def test_diagnostic_files_are_not_overwritten(self):
        (self.output / 'failure.json').write_text('prior evidence')
        original = ValueError('first error')
        b.failure.write_failure(self.output, 'failure', original, lambda: {})
        self.assertEqual((self.output / 'failure.json').read_text(), 'prior evidence')
        self.assertIn('first error', (self.output / 'failure.txt').read_text())

    def test_existing_queue_and_drop_gates_still_reject(self):
        header = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n'
        row = '1: 0100007F:1234 00000000:0000 07 {queue} 00:00000000 00000000 1000 0 12345 2 0000000000000000 {drops}\n'
        for queue, drops in [('00000000:00000000', 1), ('00000000:00000001', 0),
                             ('00000001:00000000', 0)]:
            with patch.object(Path, 'read_text', return_value=header + row.format(queue=queue, drops=drops)):
                with self.assertRaisesRegex(RuntimeError, 'queued/dropped'):
                    b.empty_sockets([0x1234])

    def test_serialization_failure_still_writes_primary_traceback(self):
        original = ValueError('primary')
        b.failure.write_failure(self.output, 'failure', original, lambda: dict(bad={1, 2}))
        self.assertEqual(self.evidence()['status'], 'unavailable')
        self.assertIn('primary', (self.output / 'failure.txt').read_text())

    def test_server_is_snapshotted_before_terminate_and_killed_if_term_is_ignored(self):
        popen = subprocess.Popen
        waits = []

        def spawn(_command, **kwargs):
            code = ('import signal,socket,time\n'
                    'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                    's=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n'
                    's.bind(("127.0.0.1",0))\ntime.sleep(30)\n')
            process = popen([sys.executable, '-c', code], **kwargs)
            wait = process.wait

            def short_wait(timeout):
                waits.append(timeout)
                return wait(timeout=.1)

            process.wait = short_wait
            return process

        original = RuntimeError('coordinator failure')
        with patch.object(b.subprocess, 'Popen', side_effect=spawn), \
                patch.object(b, 'coordinate', side_effect=original), \
                self.assertRaises(RuntimeError) as caught:
            b.run(Path(sys.executable), Path(sys.executable), self.output / 'server',
                  [min(os.sched_getaffinity(0))], allow_shared_cpus=True)
        self.assertIs(caught.exception, original)
        row = json.loads((self.output / 'server/run-failure.json').read_text())
        self.assertEqual(row['server']['status'], 'available')
        self.assertIsNone(row['exit_code'])
        self.assertFalse(Path(f"/proc/{row['server']['pid']}").exists())
        self.assertEqual(waits, [5, 5])  # Timeout, then kill and reap.
        self.assertFalse((self.output / 'server/result.json').exists())

    def test_namespace_read_failure_preserves_original_error_and_no_fake_baseline(self):
        original = PermissionError('SNMP unavailable')
        with self.assertRaises(PermissionError) as caught:
            self.coordinate([], patches=[patch.object(b, 'udp', side_effect=original)])
        self.assertIs(caught.exception, original)
        self.assertEqual(self.evidence()['namespace_delta']['status'], 'unavailable')
        self.assertIsNone(self.evidence()['namespace_delta']['counters'])

    def test_wrong_phase_retains_the_rejected_report(self):
        with self.assertRaisesRegex(RuntimeError, 'wrong worker'):
            self.coordinate(['print(\'{"phase":9}\',flush=True); input()'])
        self.assertEqual(self.evidence()['workers'][0]['report'], dict(phase=9))

    def test_diagnostic_key_failure_leaves_raw_observations_unavailable(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            with patch.object(b.failure, 'socket_diagnostics', return_value={}):
                row = b.failure.process_snapshot(os.getpid())
        self.assertEqual(row['status'], 'unavailable')
        self.assertTrue(row['sockets'])
        self.assertIn('udp', row['tables'])
        self.assertIsNone(b.failure.process_delta(row, row)['drops'])


class ExitCaptureTests(unittest.TestCase):
    def capture(self, workers):
        state = dict(phase=0, stage='warmup', namespace_before={}, last_success=None,
                     server_baseline={})
        return b.failure.capture(100, workers, state)

    def worker(self, pid, eof=False, exit_code=None):
        process = Mock(pid=pid)
        process.poll.return_value = exit_code
        return dict(process=process, command=['peer'], buffer=b'', stdout_eof=eof)

    def test_exit_waits_share_snapshot_budget_and_keep_all_peer_evidence(self):
        workers = [self.worker(101, True), self.worker(102, True)]
        events = []

        def snapshot(pid, deadline):
            events.append(('snapshot', pid, deadline))
            return dict(status='available', sockets=[dict(inode=pid)])

        def wait(timeout):
            events.append(('wait', timeout))
            raise subprocess.TimeoutExpired('peer', timeout)

        workers[0]['process'].wait.side_effect = wait
        # First worker consumes the two seconds left after all snapshots. The
        # next worker gets no new budget even though its stdout also hit EOF.
        with patch.object(b.failure.time, 'monotonic', side_effect=[10, 13, 15, 15]), \
                patch.object(b.failure, 'namespace_snapshot', return_value={}), \
                patch.object(b.failure, 'process_snapshot', side_effect=snapshot):
            result = self.capture(workers)
        self.assertEqual(events, [('snapshot', 100, 15), ('snapshot', 101, 15),
                                  ('snapshot', 102, 15), ('wait', 2)])
        workers[1]['process'].wait.assert_not_called()
        for index, row in enumerate(result['workers']):
            self.assertIsNone(row['exit_code'])
            self.assertEqual(row['sockets']['sockets'], [dict(inode=101 + index)])

    def test_open_stdout_and_already_exited_workers_are_not_waited_again(self):
        workers = [self.worker(101), self.worker(102, True, 7)]
        with patch.object(b.failure, 'namespace_snapshot', return_value={}), \
                patch.object(b.failure, 'process_snapshot', return_value={}):
            result = self.capture(workers)
        for worker in workers:
            worker['process'].wait.assert_not_called()
        self.assertEqual([row['exit_code'] for row in result['workers']], [None, 7])


if __name__ == '__main__':
    unittest.main()
