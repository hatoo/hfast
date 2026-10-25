"""Receive-buffer command, live-capacity and comparison exclusion regressions."""
import argparse
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import burst_buffer as capacity
import burst_workers as workers

spec = importlib.util.spec_from_file_location('compare_bursts',
                                             Path(__file__).with_name('compare-bursts.py'))
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def snapshot(effective=8388608):
    return dict(status='available', error=None, pid=123, start_ticks=456, netns='net:7',
                port=None, sockets=[dict(inode=8, port=9999, rcvbuf=effective, cookie=[9, 0],
                    fds=[3], family=2, local='00000000:270F', remote='00000000:0000', drops=0)])


def observation(effective=8388608, requested=4194304):
    with patch.object(capacity.failure, 'process_snapshot', return_value=snapshot(effective)):
        return capacity.observe(123, 9999, requested)


class CapacityTests(unittest.TestCase):
    def test_request_bounds_and_default_flags(self):
        self.assertEqual(capacity.flags(0), [])
        for value in (1, 212992, 4194304):
            self.assertEqual(capacity.argument(str(value)), value)
            self.assertEqual(capacity.flags(value), ['--udp-receive-buffer', str(value)])
        for value in (-1, 4194305, 1 << 64, True, 1.5, '0', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity.flags(value)

    def test_both_clis_reject_invalid_requests_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'untouched'
            for script, positional in [('burst_workers.py', ['unused', 'unused']),
                                       ('compare-bursts.py', ['unused'] * 3)]:
                for value in ('-1', '4194305', '18446744073709551616', 'invalid', '1.5', None):
                    with self.subTest(script=script, value=value):
                        command = [sys.executable, str(Path(__file__).with_name(script)),
                                   *positional, str(output), '--udp-receive-buffer']
                        run = subprocess.run(command + ([] if value is None else [value]),
                                             capture_output=True, text=True, timeout=5)
                        self.assertEqual(run.returncode, 2, run.stderr)
                        self.assertIn('--udp-receive-buffer', run.stderr)
                        self.assertFalse(output.exists())

    def test_caps_and_default_are_observed_not_inferred_from_request(self):
        for actual in (212992, 425984, 8388608, 16777216):
            row = observation(actual)
            self.assertEqual(row['effective_bytes'], actual)
            self.assertEqual(row['below_doubled_request'], actual < 8388608)
            pair = capacity.interval(row, row)
            capacity.require_equal(pair, pair)
        default = observation(212992, 0)
        self.assertEqual(default['effective_bytes'], 212992)
        self.assertIsNone(default['below_doubled_request'])

    def test_missing_partial_wrong_port_and_multiple_sockets_stay_unavailable(self):
        rows = [dict(status='unavailable', error='denied', sockets=snapshot()['sockets']),
                dict(snapshot(), sockets=[]),
                dict(snapshot(), sockets=snapshot()['sockets'] * 2)]
        for field, value in [('port', 1234), ('rcvbuf', 0), ('rcvbuf', None)]:
            row = snapshot()
            row['sockets'][0][field] = value
            rows.append(row)
        for snap in rows:
            with patch.object(capacity.failure, 'process_snapshot', return_value=snap):
                row = capacity.observe(123, 9999, 4194304)
            self.assertEqual(row['status'], 'unavailable')
            self.assertIsNone(row['effective_bytes'])
            self.assertIsNone(row['below_doubled_request'])
        with patch.object(capacity.failure, 'process_snapshot', side_effect=PermissionError('denied')):
            self.assertEqual(capacity.observe(123, 9999, 0)['status'], 'unavailable')

    def test_identity_capacity_and_missing_observations_exclude_comparison(self):
        before = observation()
        good = capacity.interval(before, before)
        for field, value in [('inode', 88), ('cookie', [10, 0]), ('fds', [4]),
                             ('rcvbuf', 425984)]:
            after = deepcopy(before)
            after['snapshot']['sockets'][0][field] = value
            bad = capacity.interval(before, after)
            self.assertEqual(bad['status'], 'unavailable')
            self.assertIsNone(bad['effective_bytes'])
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                capacity.require_equal(good, bad)
        for field, value in [('status', 'unavailable'), ('effective_bytes', None),
                             ('requested_bytes', 0), ('effective_bytes', 425984)]:
            other = dict(good, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                capacity.require_equal(good, other)

    def test_live_socket_snapshot_matches_getsockopt_before_and_after(self):
        # An independent child owns exactly one UDP socket; no server/peer workload.
        code = ('import json,socket,sys\n'
                's=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n'
                's.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4194304)\n'
                's.bind(("127.0.0.1",0))\n'
                'print(json.dumps([s.getsockname()[1],s.getsockopt(socket.SOL_SOCKET,'
                'socket.SO_RCVBUF)]),flush=True)\nsys.stdin.readline()\n')
        with subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True) as child:
            try:
                port, actual = json.loads(child.stdout.readline())
                before = capacity.observe(child.pid, port, 4194304)
                after = capacity.observe(child.pid, port, 4194304)
                row = capacity.interval(before, after)
                self.assertEqual(row['status'], 'available', row)
                self.assertEqual(row['effective_bytes'], actual)
                self.assertEqual(row['socket_delta']['drops'], 0)
            finally:
                child.stdin.write('stop\n')
                child.stdin.flush()
                child.wait(timeout=5)


class CommandTests(unittest.TestCase):
    def test_comparator_excludes_unavailable_unequal_and_between_pair_changes(self):
        before = observation()
        good = capacity.interval(before, before)
        unavailable = dict(good, status='unavailable', effective_bytes=None)
        capped = capacity.interval(observation(425984), observation(425984))
        for capacities in ([good, unavailable], [good, capped], [good, good, capped, capped]):
            with self.subTest(capacities=[c['effective_bytes'] for c in capacities]), \
                    tempfile.TemporaryDirectory() as temp:
                args = self.comparison_args(temp, len(capacities) // 2)
                rows = [self.result(c) for c in capacities]
                with patch.object(compare, 'run', side_effect=rows), \
                        patch('builtins.print'), self.assertRaises(ValueError):
                    compare.main(args)
                self.assertTrue((args.output / 'manifest.json').exists())
                self.assertFalse((args.output / 'summary.json').exists())

    def test_equal_capped_comparisons_record_actual_capacity_and_alternate(self):
        capped = capacity.interval(observation(425984), observation(425984))
        with tempfile.TemporaryDirectory() as temp:
            args = self.comparison_args(temp, 2)
            with patch.object(compare, 'run', side_effect=[self.result(capped) for _ in range(4)]) as run, \
                    patch('builtins.print'):
                compare.main(args)
            self.assertEqual([(c.args[1], c.args[2]) for c in run.call_args_list],
                             [('baseline', 0), ('candidate', 0), ('candidate', 1), ('baseline', 1)])
            summary = json.loads((args.output / 'summary.json').read_text())
            self.assertEqual(summary['udp_receive_buffer_requested'], 4194304)
            self.assertEqual(summary['receive_buffer_capacities'], [425984] * 4)

    @staticmethod
    def comparison_args(temp, pairs):
        return argparse.Namespace(output=Path(temp) / 'comparison',
            baseline=Path(sys.executable), candidate=Path(sys.executable), peer=Path(sys.executable),
            producer_cpus=[1], pairs=pairs, reverse=False, batch=32, datagrams=8,
            batches=16, cycles=2, warmup=8, udp_receive_buffer=4194304)

    @staticmethod
    def result(capacity):
        return dict(pair=0, variant='synthetic', requests_per_second=1, cpu_ns_per_request=1,
                    server_cores=1, measured_requests=1, sent_datagrams=1, received_datagrams=1,
                    completed=1, sent_messages=1, udp_receive_buffer=capacity)

    def test_coordinator_flags_manifest_and_result_in_both_delivery_modes(self):
        for requested in (0, 4194304):
            for gro in (True, False):
                with self.subTest(requested=requested, gro=gro), tempfile.TemporaryDirectory() as temp:
                    output = Path(temp) / 'run'
                    process = Mock(pid=123)
                    process.poll.return_value = None
                    with patch.object(workers.subprocess, 'Popen', return_value=process) as spawn, \
                            patch.object(workers.time, 'sleep'), \
                            patch.object(workers, 'coordinate', return_value=dict(completed=1)), \
                            patch.object(capacity, 'observe', return_value=observation(425984, requested)):
                        row = workers.run(Path(sys.executable), Path(sys.executable), output,
                                          [min(os.sched_getaffinity(0))], gro=gro,
                                          udp_receive_buffer=requested, allow_shared_cpus=True)
                    command = spawn.call_args.args[0]
                    self.assertEqual(command.count('--udp-receive-buffer'), int(requested > 0))
                    if requested:
                        self.assertEqual(command[-2:], ['--udp-receive-buffer', str(requested)])
                    self.assertEqual(Path(command[0]).name,
                                     Path(sys.executable).name if gro else 'without-udp-gro.py')
                    manifest = json.loads((output / 'manifest.json').read_text())
                    self.assertEqual(manifest['server_command'], command)
                    self.assertEqual(manifest['udp_receive_buffer_requested'], requested)
                    evidence = json.loads((output / 'receive-buffer.json').read_text())
                    self.assertEqual(evidence['effective_bytes'], 425984)
                    self.assertEqual(row['udp_receive_buffer']['effective_bytes'], 425984)
                    process.terminate.assert_called_once()

    def test_comparator_passes_one_request_to_both_variants_and_delivery_modes(self):
        for requested in (0, 4194304):
            for denied in (True, False):
                args = argparse.Namespace(output=Path('/unused'), baseline=Path('/baseline'),
                    candidate=Path('/candidate'), peer=Path('/peer'), producer_cpus=[1, 2, 3, 4],
                    baseline_without_gro=denied, candidate_without_gro=denied,
                    batch=32, datagrams=8, batches=16, cycles=2, warmup=8,
                    udp_receive_buffer=requested)
                with patch.object(workers, 'run', side_effect=[{}, {}]) as run:
                    compare.run(args, 'baseline', 0)
                    compare.run(args, 'candidate', 0)
                calls = run.call_args_list
                self.assertEqual(calls[0].kwargs, calls[1].kwargs)
                self.assertEqual(calls[0].kwargs['udp_receive_buffer'], requested)
                self.assertEqual(calls[0].kwargs['gro'], not denied)

    def test_legacy_server_receives_same_flags_even_if_peer_fails(self):
        for requested in (0, 4194304):
            with tempfile.TemporaryDirectory() as temp:
                args = argparse.Namespace(output=Path(temp), baseline=Path('/baseline'),
                    candidate=Path('/candidate'), peer=Path('/peer'), producer_cpus=None,
                    candidate_without_gro=False, batch=32, datagrams=8, batches=16,
                    cycles=2, warmup=8, client_cpu=1, udp_receive_buffer=requested)
                commands = []
                for variant in ('baseline', 'candidate'):
                    process = Mock(pid=123)
                    process.poll.return_value = None
                    with patch.object(compare.subprocess, 'Popen', return_value=process) as spawn, \
                            patch.object(compare.subprocess, 'run', return_value=Mock(
                                returncode=1, stdout='', stderr='deliberate peer failure')), \
                            patch.object(compare.time, 'sleep'), \
                            patch.object(capacity, 'observe', return_value=observation(425984, requested)), \
                            self.assertRaisesRegex(AssertionError, 'deliberate peer failure'):
                        compare.run(args, variant, 0)
                    commands.append(spawn.call_args.args[0])
                    evidence = json.loads((args.output / f'0-{variant}.receive-buffer.json').read_text())
                    self.assertEqual(evidence['requested_bytes'], requested)
                    self.assertEqual(evidence['effective_bytes'], 425984)
                    process.terminate.assert_called_once()
                # Ignore the server executable and the independently reserved UDP port.
                for command in commands:
                    command[0] = 'server'
                    command[command.index('--quic') + 1] = 'port'
                self.assertEqual(commands[0], commands[1])
                self.assertEqual(commands[0].count('--udp-receive-buffer'), int(requested > 0))


if __name__ == '__main__':
    unittest.main()
