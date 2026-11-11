"""Real child exits, deadline cleanup and preflight workload rejection."""
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'sustained_controller', Path(__file__).with_name('response-credit-sustained-check.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Controller(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SUSTAINED_PEER'), 'requires the built native fixture')
    def test_native_rejects_invalid_inputs_before_transport(self):
        peer = os.environ['SUSTAINED_PEER']
        for count, window, schedule, reason in (
                (4097,4097,'full','invalid workload'),
                (512,513,'full','invalid workload'),
                (8193,4096,'byte','trace workload exceeds event budget'),
                (32,8,'two-fragment','unsupported connection increment')):
            result = subprocess.run([peer, '9', str(count), str(window), schedule, 'each', '1',
                                     '--connection-credit', '--controlled', '--trace'],
                                    capture_output=True, text=True, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(result.stdout)
            self.assertIn(reason, result.stderr)

    def test_invalid_workloads_fail_before_starting_children(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(runner.subprocess, 'Popen') as popen:
            for count, window, schedule in ((4097,4097,'full'), (8193,4096,'byte'),
                                             (512,513,'full'), (32,8,'two-fragment')):
                output = Path(directory) / f'{count}-{window}'
                with self.assertRaises(ValueError):
                    runner.run(Path('/missing-server'), Path('/missing-peer'), output,
                               count, window, schedule, 'each', 0, 1, True, True)
                self.assertFalse(output.exists())
            popen.assert_not_called()

    def test_peer_exit_and_deadline_reap_both_children(self):
        cpu = min(os.sched_getaffinity(0))
        for scenario in ('exit', 'deadline'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for role in ('server', 'peer'):
                    script = root / role
                    body = ("import os, pathlib, signal, time\n"
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                            f"pathlib.Path({str(root / (role + '.pid'))!r}).write_text(str(os.getpid()))\n")
                    body += 'raise SystemExit(17)\n' if role == 'peer' and scenario == 'exit' else 'time.sleep(60)\n'
                    script.write_text('#!/usr/bin/env python3\n' + body)
                    script.chmod(0o755)

                original_collect = runner.collect

                def collect(workers, phase, timeout):
                    if scenario == 'exit': return original_collect(workers, phase, timeout)
                    deadline = time.monotonic() + 2
                    while not (root / 'peer.pid').exists() and time.monotonic() < deadline:
                        time.sleep(.005)
                    self.assertTrue((root / 'peer.pid').exists())
                    raise ValueError('injected ready deadline')

                with patch.object(runner, 'process_snapshot', return_value={}), \
                     patch.object(runner, 'namespace_snapshot', return_value={}), \
                     patch.object(runner, 'collect', side_effect=collect):
                    started = time.monotonic()
                    with self.assertRaises((ValueError, RuntimeError)):
                        runner.run(root / 'server', root / 'peer', root / 'output',
                                   513, 513, 'full', 'each', cpu, 1, True, True)
                    self.assertLess(time.monotonic() - started, 8)
                self.assertTrue((root / 'output/failure.txt').is_file())
                for role in ('server', 'peer'):
                    pid = int((root / (role + '.pid')).read_text())
                    with self.assertRaises(ProcessLookupError): os.kill(pid, 0)


if __name__ == '__main__': unittest.main()
