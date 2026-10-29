"""Real kernel overflow, ownership, and independent malformed-evidence oracles."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

import udp_accounting as udp

HEADER = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n'
ROW = '1: 0100007F:1234 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345 2 0000000000000000 7\n'


def diag_payload(inode=12345, capacity=8192, drops=7, family=socket.AF_INET):
    # Construct Linux UAPI wire fields independently of the production parser.
    sockid = struct.pack('!HH', 0x1234, 0) + bytes(36) + struct.pack('=II', 77, 88)
    message = bytes([family, 7, 0, 0]) + sockid + struct.pack('=5I', 0, 0, 0, 1000, inode)
    return message + struct.pack('=HH9I', 40, 7, 0, capacity, 0, 8192, 0, 0, 0, 0, drops)


def nl_message(payload, kind=20, flags=2, seq=1):
    return struct.pack('=IHHII', 16 + len(payload), kind, flags, seq, 0) + payload


class Parsing(unittest.TestCase):
    def test_only_identical_duplicate_rows_are_retryable(self):
        with self.assertRaises(udp.RepeatedUdpRow):
            udp.parse_udp(HEADER + ROW + ROW, socket.AF_INET)
        for conflicting in [ROW.replace(' 7\n', ' 8\n'), ROW.replace(':1234', ':1235'),
                            ROW.replace('00000000:00000000', '00000000:00000001')]:
            with self.subTest(row=conflicting), self.assertRaises(ValueError) as caught:
                udp.parse_udp(HEADER + ROW + conflicting, socket.AF_INET)
            self.assertNotIsInstance(caught.exception, udp.RepeatedUdpRow)

    def test_proc_ipv4_ipv6_and_same_port_distinct_inodes(self):
        other = ROW.replace('12345', '54321').replace(' 7\n', ' 0\n')
        result = udp.parse_udp(HEADER + ROW + other, socket.AF_INET)
        self.assertEqual(set(result), {12345, 54321})
        self.assertEqual(result[12345]['drops'], 7)
        self.assertEqual(result[54321]['drops'], 0)
        table = (HEADER + ROW).replace('0100007F', '00000000000000000000000001000000')
        table = table.replace('00000000:0000', '00000000000000000000000000000000:0000')
        self.assertEqual(udp.parse_udp(table, socket.AF_INET6)[12345]['drops'], 7)
        self.assertEqual(udp.parse_udp(HEADER, socket.AF_INET), {})

    def test_bad_proc_rows_are_never_zero(self):
        for table in ['', ROW, HEADER + 'bad\n', HEADER + ROW + ROW,
                      (HEADER + ROW).replace(' 7\n', ' -1\n'),
                      (HEADER + ROW).replace(' 7\n', ' 4294967296\n'),
                      (HEADER + ROW).replace('12345', 'garbage'),
                      (HEADER + ROW).replace('0100007F', 'short')]:
            with self.subTest(table=table), self.assertRaises(ValueError):
                udp.parse_udp(table, socket.AF_INET)

    def test_diag_capacity_cookie_and_drops(self):
        for family in [socket.AF_INET, socket.AF_INET6]:
            row = udp.parse_diag(diag_payload(family=family))
            self.assertEqual(row, dict(inode=12345, family=family, port=0x1234,
                                      cookie=[77, 88], rcvbuf=8192, diag_drops=7))
        payload = diag_payload()
        for bad in [b'', payload[:71], payload[:72], payload[:-1],
                    payload[:72] + struct.pack('=HH', 3, 7),
                    payload + payload[72:], diag_payload(capacity=0),
                    payload[:44] + b'\xff' * 8 + payload[52:]]:
            with self.subTest(payload=bad), self.assertRaises(ValueError):
                udp.parse_diag(bad)

    def test_netlink_termination_errors_sequence_and_interrupt(self):
        message = nl_message(diag_payload())
        done = nl_message(struct.pack('=i', 0), kind=3)
        rows, finished = udp.diag_messages(message + done, 1)
        self.assertTrue(finished)
        self.assertEqual(len(rows), 1)
        self.assertFalse(udp.diag_messages(message, 1)[1])
        for bad in [message[:-1], message[:10], nl_message(diag_payload(), seq=2),
                    nl_message(diag_payload(), flags=0x12),
                    nl_message(struct.pack('=i', -13), kind=2),
                    nl_message(struct.pack('=i', -4), kind=3),
                    nl_message(b'', kind=3), nl_message(b'', kind=4), done + message]:
            with self.subTest(message=bad), self.assertRaises(ValueError):
                udp.diag_messages(bad, 1)

    def test_diagnostic_deadline_bounds_even_a_continuing_dump(self):
        # Zero-status acknowledgements are legal but do not terminate a dump.
        ack = nl_message(struct.pack('=i', 0), kind=2)
        with patch.object(udp.socket, 'socket') as create, \
                patch.object(udp.time, 'monotonic', side_effect=[1, 2, 3]):
            netlink = create.return_value.__enter__.return_value
            netlink.recvmsg.return_value = (ack, [], 0, (0, 0))
            with self.assertRaisesRegex(ValueError, 'deadline expired'):
                udp.socket_diagnostics({socket.AF_INET}, deadline=2.5)
        self.assertEqual(netlink.recvmsg.call_count, 2)
        self.assertEqual([call.args[0] for call in netlink.settimeout.call_args_list], [2, 1.5, .5])


class LiveSockets(unittest.TestCase):
    def socket(self, family=socket.AF_INET, port=0, small=False):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if small:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        sock.bind(('127.0.0.1' if family == socket.AF_INET else '::1', port))
        sock.settimeout(2)
        return sock

    def snapshot(self, sock, workers=1):
        result = udp.process_snapshot(os.getpid(), sock.getsockname()[1], workers)
        self.assertEqual(result['status'], 'available', result)
        return result

    def test_clean_socket_and_actual_receive_capacity(self):
        for family in [socket.AF_INET, socket.AF_INET6]:
            with self.subTest(family=family):
                receiver, sender = self.socket(family), self.socket(family)
                before = self.snapshot(receiver)
                self.assertEqual(before['sockets'][0]['rcvbuf'],
                                 receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
                for i in range(8):
                    payload = bytes([i]) * 512
                    sender.sendto(payload, receiver.getsockname())
                    self.assertEqual(receiver.recv(1024), payload)
                delta = udp.process_delta(before, self.snapshot(receiver))
                self.assertEqual(delta['status'], 'available', delta)
                self.assertEqual(delta['drops'], 0)

    def test_overflow_attributed_to_exact_inode_with_two_workers(self):
        receiver = self.socket(small=True)
        worker = self.socket(port=receiver.getsockname()[1], small=True)
        sender = self.socket()
        before = self.snapshot(receiver, 2)
        payload = b'complete datagram' * 32
        sent = 1024
        for _ in range(sent):
            self.assertEqual(sender.sendto(payload, receiver.getsockname()), len(payload))
        received = {}
        for sock in [receiver, worker]:
            inode = os.fstat(sock.fileno()).st_ino
            received[inode] = 0
            sock.setblocking(False)
            while True:
                try:
                    self.assertEqual(sock.recv(1024), payload)
                    received[inode] += 1
                except BlockingIOError:
                    break
        delta = udp.process_delta(before, self.snapshot(receiver, 2))
        self.assertEqual(delta['status'], 'available', delta)
        self.assertGreater(delta['drops'], 0)
        self.assertEqual(sum(received.values()) + delta['drops'], sent)
        # The stable UDP flow maps to one reuseport socket; both are accounted.
        active = [s for s in delta['sockets'] if s['drops'] > 0]
        self.assertEqual(len(active), 1, delta)
        self.assertEqual(active[0]['drops'] + received[active[0]['inode']], sent)
        self.assertEqual(self.snapshot(sender)['sockets'][0]['drops'], 0)
        with self.assertRaisesRegex(ValueError, 'server UDP loss'):
            udp.require_clean_run(dict(status='available', drops=0), delta,
                                  dict(status='available', counters={}))

    def test_other_process_same_port_is_excluded(self):
        receiver = self.socket()
        child = subprocess.Popen([sys.executable, '-c',
            'import socket,sys,os; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
            's.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1); '
            's.bind(("127.0.0.1",int(sys.argv[1]))); '
            'print(os.fstat(s.fileno()).st_ino,flush=True); sys.stdin.read()',
            str(receiver.getsockname()[1])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'child did not bind')
            foreign_inode = int(child.stdout.readline())
            row = self.snapshot(receiver)
            self.assertNotEqual(row['sockets'][0]['inode'], foreign_inode)
            foreign = udp.process_snapshot(child.pid, receiver.getsockname()[1], 1)
            self.assertEqual(foreign['status'], 'available', foreign)
            self.assertEqual(foreign['sockets'][0]['inode'], foreign_inode)
        finally:
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)

    def test_disappearance_permissions_wrong_count_and_namespace(self):
        receiver = self.socket()
        port = receiver.getsockname()[1]
        wrong_count = udp.process_snapshot(os.getpid(), port, 2)
        self.assertEqual(wrong_count['status'], 'unavailable')
        for function, error in [('owned_inodes', PermissionError('denied')),
                                ('socket_diagnostics', OSError('not supported'))]:
            with patch.object(udp, function, side_effect=error):
                report = udp.process_snapshot(os.getpid(), port, 1)
            self.assertEqual(report['status'], 'unavailable')
            self.assertIn(str(error), report['error'])
        with patch.object(udp, 'socket_diagnostics', return_value={}):
            self.assertEqual(udp.process_snapshot(os.getpid(), port, 1)['status'], 'unavailable')
        with patch.object(udp, 'process_identity', return_value=dict(start_ticks=1, netns='foreign')):
            self.assertEqual(udp.process_snapshot(os.getpid(), port, 1)['status'], 'unavailable')
        before = self.snapshot(receiver)
        receiver.close()
        after = udp.process_snapshot(os.getpid(), port, 1)
        self.assertEqual(after['status'], 'unavailable')
        self.assertIsNone(udp.process_delta(before, after)['drops'])

    def test_recycled_inode_reset_and_missing_evidence_rejected(self):
        before = self.snapshot(self.socket())
        for key, value in [('cookie', [999, 999]), ('fds', [999]), ('rcvbuf', 1),
                           ('family', 99), ('local', 'changed'), ('inode', 999)]:
            after = copy.deepcopy(before)
            after['sockets'][0][key] = value
            delta = udp.process_delta(before, after)
            self.assertEqual(delta['status'], 'unavailable', key)
            self.assertIsNone(delta['drops'])
        for key, value in [('start_ticks', 999999), ('pid', -1), ('netns', 'other'),
                           ('status', 'unavailable'), ('sockets', [])]:
            after = copy.deepcopy(before)
            after[key] = value
            self.assertIsNone(udp.process_delta(before, after)['drops'])
        after = copy.deepcopy(before)
        before['sockets'][0]['drops'] = 0xffffffff
        self.assertIsNone(udp.process_delta(before, after)['drops'])
        after['sockets'] *= 2
        self.assertIsNone(udp.process_delta(after, after)['drops'])


class Validation(unittest.TestCase):
    def test_namespace_and_peer_fail_closed(self):
        before = udp.namespace_snapshot()
        self.assertEqual(before['status'], 'available', before)
        clean = udp.namespace_delta(before, before)
        udp.require_clean_run(dict(status='available', drops=0),
                              dict(status='available', drops=0), clean)
        for who in ['peer', 'server', 'namespace']:
            peer = dict(status='available', drops=0)
            server = dict(status='available', drops=0)
            net = copy.deepcopy(clean)
            if who == 'peer': peer['drops'] = 1
            if who == 'server': server['drops'] = 1
            if who == 'namespace': net['counters']['RcvbufErrors'] = 1
            with self.subTest(who=who), self.assertRaises(ValueError):
                udp.require_clean_run(peer, server, net)
        for invalid in [dict(status='unavailable', drops=None), dict(status='available', drops=3)]:
            with self.assertRaises(ValueError):
                udp.require_clean_peer(invalid)
        after = copy.deepcopy(before)
        after['counters']['InErrors'] = -1
        self.assertIsNone(udp.namespace_delta(before, after)['counters'])
        with patch.object(Path, 'read_text', side_effect=PermissionError('denied')):
            missing = udp.namespace_snapshot()
        self.assertEqual(missing['status'], 'unavailable')
        self.assertIsNone(udp.namespace_delta(before, missing)['counters'])
        text = Path('/proc/net/snmp').read_text()
        for invalid in [text.replace('Udp: InDatagrams', 'Udp: InErrors'),
                        'Udp: InErrors RcvbufErrors\nUdp: -1 0\n']:
            with patch.object(Path, 'read_text', return_value=invalid):
                self.assertEqual(udp.namespace_snapshot()['status'], 'unavailable')

    def test_real_success_ledger_rejects_injected_loss_without_losing_samples(self):
        # Optional artifact check runs after native positive/negative wire cases.
        # It tests validate(), not just the helper that it is meant to call.
        path = os.environ.get('STREAM_CREDIT_VALID_ROW')
        if not path:
            self.skipTest('set STREAM_CREDIT_VALID_ROW to a real successful peer stdout')
        spec = importlib.util.spec_from_file_location('credit_check', Path(__file__).with_name('stream-credit-peer-check.py'))
        check = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check)
        row = json.loads(Path(path).read_text())
        count, size = row['completed'], row['body_bytes_per_stream']
        check.validate(row, count, size)
        for evidence in [dict(status='available', drops=1), dict(status='unavailable', drops=None)]:
            mutant = copy.deepcopy(row)
            mutant['udp'] = evidence
            with self.assertRaisesRegex(ValueError, 'peer UDP loss'):
                check.validate(mutant, count, size)
            self.assertEqual(mutant['completed'], count)
            self.assertEqual(mutant['latencies_ns'], row['latencies_ns'])


if __name__ == '__main__':
    unittest.main()
