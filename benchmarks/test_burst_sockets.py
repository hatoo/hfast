"""Independent socket tables, identity mutations and actual SO_REUSEPORT lifetimes."""
from copy import deepcopy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import burst_buffer
import burst_sockets as s
import burst_workers as b


HEADER = ('sl local_address rem_address st tx_queue rx_queue tr tm->when '
          'retrnsmt uid timeout inode ref pointer drops\n')


def snapshot(ports=(9000, 9000), pid=123, first=100):
    rows = []
    for index, port in enumerate(ports):
        inode = first + index
        rows.append(dict(inode=inode, port=port, family=socket.AF_INET,
            local=f'0100007F:{port:04X}', remote='00000000:0000', fds=[3 + index],
            cookie=[inode + 30, 1], rcvbuf=8388608, drops=0, diag_drops=0,
            tx_queue=0, rx_queue=0))
    result = dict(status='available', error=None, pid=pid, start_ticks=456, port=None,
        netns='net:7', sockets=rows, owned_inodes={r['inode']: r['fds'] for r in rows})
    result['tables'] = tables(rows)
    return result


def tables(rows):
    # Independent /proc wire representation; do not serialize using the parser.
    return dict(udp=HEADER + ''.join(f"1: {r['local']} {r['remote']} 07 "
        f"{r['tx_queue']:08X}:{r['rx_queue']:08X} 00:00000000 00000000 1000 0 "
        f"{r['inode']} 2 0000000000000000 {r['drops']}\n" for r in rows), udp6=HEADER)


class SocketOracles(unittest.TestCase):
    def test_one_and_two_workers_and_independent_producer_sockets(self):
        for ports in ([9000], [9000, 9000], [9001, 9002]):
            row = snapshot(ports)
            delta = s.validate(row, ports)
            self.assertEqual(delta['drops'], 0)
            self.assertEqual(len(delta['sockets']), len(ports))

    def test_order_is_irrelevant_but_no_worker_can_be_omitted(self):
        before = snapshot()
        after = deepcopy(before)
        after['sockets'].reverse()
        self.assertEqual(s.validate(after, [9000, 9000], before)['drops'], 0)
        for rows in ([], after['sockets'][:1], after['sockets'] * 2):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                s.validate(dict(after, sockets=rows), [9000, 9000], before)

    def test_replaced_inode_cookie_fd_capacity_process_or_namespace_is_rejected(self):
        before = snapshot()
        for key, value in [('inode', 500), ('cookie', [3, 4]), ('fds', [5]),
                           ('rcvbuf', 425984), ('port', 9001),
                           ('local', '00000000:2328'), ('remote', '0100007F:7777')]:
            after = deepcopy(before)
            after['sockets'][0][key] = value
            after['tables'] = tables(after['sockets'])
            after['owned_inodes'] = {r['inode']: r['fds'] for r in after['sockets']}
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.validate(after, [9000, 9000], before)
        for key, value in [('pid', 321), ('start_ticks', 789), ('netns', 'net:8')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.validate(dict(before, **{key: value}), [9000, 9000], before)

    def test_extra_foreign_missing_duplicate_or_mismatched_table_socket_fails(self):
        before = snapshot()
        extras = snapshot(first=400)['sockets']
        for raw in (tables(before['sockets'] + extras[:1]), tables(before['sockets'][:1]),
                    tables(before['sockets'] * 2), tables(extras)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                s.validate(dict(before, tables=raw), [9000, 9000])
        for key in ('cookie', 'inode'):
            after = deepcopy(before)
            after['sockets'][1][key] = after['sockets'][0][key]
            with self.assertRaises(ValueError):
                s.validate(after, [9000, 9000])

    def test_socket_drop_queue_and_diagnostic_disagreement_fail(self):
        for key in ('drops', 'diag_drops', 'tx_queue', 'rx_queue'):
            for update_table in (False, True):
                after = snapshot()
                after['sockets'][1][key] = 1
                if update_table:
                    after['tables'] = tables(after['sockets'])
                with self.subTest(key=key, update_table=update_table), self.assertRaises(ValueError):
                    s.validate(after, [9000, 9000])

    def test_unavailable_partial_and_malformed_evidence_is_not_zero_loss(self):
        for after in (dict(snapshot(), status='unavailable', error='denied'),
                      dict(snapshot(), tables={}), dict(snapshot(), owned_inodes={})):
            with self.assertRaises((ValueError, KeyError)):
                s.validate(after, [9000, 9000])
        for key, value in [('rcvbuf', 0), ('rcvbuf', True), ('cookie', [0xffffffff] * 2)]:
            after = snapshot()
            after['sockets'][0][key] = value
            with self.assertRaises(ValueError):
                s.validate(after, [9000, 9000])

    def test_capacity_comparisons_never_mix_one_and_two_workers(self):
        observations = []
        for count in (1, 2):
            with patch.object(burst_buffer.failure, 'process_snapshot',
                              return_value=snapshot([9000] * count)):
                row = burst_buffer.observe(123, 9000, 4194304, workers=count)
                interval = burst_buffer.interval(row, row)
                self.assertEqual(interval['status'], 'available')
                self.assertEqual(interval['workers'], count)
                burst_buffer.require_equal(interval, interval)
                observations.append(interval)
        with self.assertRaisesRegex(ValueError, 'worker counts'):
            burst_buffer.require_equal(*observations)
        after = snapshot()
        after['sockets'][1]['rcvbuf'] //= 2
        with patch.object(burst_buffer.failure, 'process_snapshot', return_value=after):
            self.assertEqual(burst_buffer.observe(123, 9000, 0, workers=2)['status'], 'unavailable')

    def test_reference_settlement_checks_every_inode_and_still_rejects_foreign(self):
        raw = snapshot([9000, 9000, 9001, 9002])['tables']
        expected = {9000: {100, 101}, 9001: {102}, 9002: {103}}
        with patch.object(Path, 'read_text', side_effect=lambda *a, **k: raw['udp']):
            # The legacy guard must continue to reject shared server ports.
            with self.assertRaisesRegex(RuntimeError, 'shared UDP port'):
                b.empty_sockets([9000, 9001, 9002])
        with patch.object(Path, 'read_text', autospec=True,
                          side_effect=lambda path: raw[path.name]):
            b.empty_sockets([9000, 9001, 9002], expected)
            b.empty_sockets([9000, 9001, 9002], {9000: {100, 101}})  # First warmup.
            for corrupt in ({9000: {100}}, {**expected, 9001: {999}}):
                with self.assertRaises(ValueError):
                    b.empty_sockets([9000, 9001, 9002], corrupt)

    def test_socket_addition_during_observation_keeps_partial_evidence(self):
        snap = snapshot()
        with patch.object(s.failure, 'process_snapshot', return_value=snap), \
                patch.object(s.failure, 'owned_inodes', return_value={**snap['owned_inodes'], 500: [5]}):
            result = s.observe(123, [9000, 9000])
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['delta'])
        self.assertIn('ownership changed', result['error'])
        self.assertEqual(result['snapshot'], snap)
        self.assertIn(500, result['ownership_after'])

    def test_reference_cannot_omit_a_producer_or_share_its_ports(self):
        with self.assertRaisesRegex(ValueError, 'missing producer'):
            s.capture(123, 9000, 2, [object()], [])
        server = dict(status='available', error=None, ports=[9000, 9000])
        producer = dict(status='available', error=None, ports=[9001, 9002])
        s.require_clean(dict(server=server, producers=[producer]))
        for peers in ([producer, producer], [dict(producer, ports=[9001, 9001])],
                      [dict(producer, ports=[9000, 9001])]):
            with self.assertRaisesRegex(ValueError, 'shared'):
                s.require_clean(dict(server=server, producers=peers))

    def test_reference_arguments_and_affinity_fail_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'untouched'
            for count in (0, 3, -1, True, 1.5, '2'):
                with self.assertRaisesRegex(RuntimeError, 'one or two'):
                    b.run(Path('/unused'), Path('/unused'), output, [8], reference_workers=count)
            with patch.object(os, 'sched_getaffinity', return_value={0, 1, 2}):
                with self.assertRaisesRegex(RuntimeError, 'distinct client'):
                    b.run(Path('/unused'), Path('/unused'), output, [1], reference_workers=2)
            self.assertFalse(output.exists())


# Child owns all reference sockets; the test/controller cannot accidentally
# count its own UDP sockets as server workers. Commands alter real kernel state.
CHILD = '''import json,os,socket,sys
sockets=[]
port=0
def add():
    global port
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
    s.bind(('127.0.0.1',port))
    port=s.getsockname()[1]
    sockets.append(s)
add(); add()
print(port,flush=True)
for line in sys.stdin:
    command=line.strip()
    if command=='stop': break
    if command=='close': sockets.pop().close()
    if command=='replace': sockets.pop().close(); add()
    if command=='extra': add()
    if command=='capacity': sockets[0].setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
    print('done',flush=True)
'''


class LiveSockets(unittest.TestCase):
    def setUp(self):
        self.child = subprocess.Popen([sys.executable, '-c', CHILD], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True)
        self.assertTrue(select.select([self.child.stdout], [], [], 5)[0])
        self.port = int(self.child.stdout.readline())

    def tearDown(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.communicate(timeout=5)

    def command(self, text):
        self.child.stdin.write(text + '\n')
        self.child.stdin.flush()
        self.assertTrue(select.select([self.child.stdout], [], [], 5)[0])
        self.assertEqual(self.child.stdout.readline(), 'done\n')

    def observe(self, before=None):
        return s.observe(self.child.pid, [self.port] * 2, before)

    def test_two_live_owned_sockets_keep_identity_capacity_and_zero_drops(self):
        before = self.observe()
        self.assertEqual(before['status'], 'available', before)
        after = self.observe(before['snapshot'])
        self.assertEqual(after['status'], 'available', after)
        self.assertEqual(after['delta']['drops'], 0)
        s.empty([self.port], {self.port: {r['inode'] for r in after['snapshot']['sockets']}})
        # Corrupt only a cookie; a fresh real kernel observation must reject it.
        before['snapshot']['sockets'][1]['cookie'][0] += 1
        self.assertEqual(self.observe(before['snapshot'])['status'], 'unavailable')

    def test_closed_worker_socket_is_rejected(self):
        before = self.observe()
        self.command('close')
        after = self.observe(before['snapshot'])
        self.assertEqual(after['status'], 'unavailable', after)
        self.assertEqual(len(after['snapshot']['sockets']), 1)

    def test_replaced_worker_socket_is_rejected(self):
        before = self.observe()
        self.command('replace')
        after = self.observe(before['snapshot'])
        self.assertEqual(after['status'], 'unavailable', after)
        self.assertEqual(len(after['snapshot']['sockets']), 2)

    def test_extra_owned_worker_socket_is_rejected(self):
        before = self.observe()
        self.command('extra')
        after = self.observe(before['snapshot'])
        self.assertEqual(after['status'], 'unavailable', after)
        self.assertEqual(len(after['snapshot']['sockets']), 3)

    def test_changed_worker_capacity_is_rejected(self):
        before = self.observe()
        self.command('capacity')
        self.assertEqual(self.observe(before['snapshot'])['status'], 'unavailable')

    def test_foreign_reuseport_socket_cannot_masquerade_as_a_worker(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign:
            foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            foreign.bind(('127.0.0.1', self.port))
            after = self.observe()
            self.assertEqual(after['status'], 'unavailable', after)
            self.assertIn('foreign', after['error'])
            self.assertEqual(len(after['snapshot']['sockets']), 2)

    def test_live_queue_and_overflow_are_rejected_with_exact_socket_evidence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b'x', ('127.0.0.1', self.port))
            queued = self.observe()
            self.assertEqual(queued['status'], 'unavailable', queued)
            self.assertEqual(sum(r['drops'] for r in queued['snapshot']['sockets']), 0)
            self.assertGreater(sum(r['rx_queue'] for r in queued['snapshot']['sockets']), 0)
            for _ in range(2048):
                sender.sendto(b'x' * 1024, ('127.0.0.1', self.port))
            dropped = self.observe()
            self.assertEqual(dropped['status'], 'unavailable', dropped)
            self.assertGreater(sum(r['drops'] for r in dropped['snapshot']['sockets']), 0)

    def test_exited_process_and_unavailable_diagnostics_remain_unavailable(self):
        with patch.object(s.failure, 'socket_diagnostics', side_effect=PermissionError('denied')):
            after = self.observe()
            self.assertEqual(after['status'], 'unavailable', after)
            self.assertIsNone(after['delta'])
        self.child.stdin.write('stop\n')
        self.child.stdin.flush()
        self.child.wait(timeout=5)
        self.assertEqual(self.observe()['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
