#!/usr/bin/env python3
"""Run independent QUIC fixtures with native/denied GRO and optional GSO sends."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main(args):
    args.output.mkdir(parents=True)
    here = Path(__file__).resolve().parent
    env = dict(os.environ, HFAST_GRO_BINARY=str(args.binary), PYTHONDONTWRITEBYTECODE='1')
    cases = {name: [] for name in [
        'interoperability', 'crypto-recovery-check', 'control-recovery-check',
        'stream-recovery-check', 'credit-recovery-check', 'stream-credit-check',
        'sparse-stream-credit-check', 'response-credit-check', 'response-recovery-check',
        'uni-accounting-check', 'reset-accounting-check', 'key-update-check',
    ]}
    if not args.gso:
        cases.update({
            'stream-table-bench': ['--slots', '4096', '--requests', '2048', '--warmup', '128'],
            'ack-ledger-bench': ['--window', '1024', '--requests', '256', '--warmup', '64'],
            'sparse-ack-bench': ['--window', '1024', '--ranges', '64', '--cycles', '1'],
            'quic-loss-check': [],
        })
    binary = here / 'without-udp-gro.py' if args.without_gro else args.binary
    rows = []
    for name, options in cases.items():
        command = [sys.executable]
        if args.gso:
            command.append(str(here / 'gso-fixture.py'))
        command += [str(here / (name + '.py')), str(binary), *options]
        start = time.monotonic()
        with (args.output / (name + '.log')).open('x') as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=240)
        row = dict(fixture=name, command=command, returncode=result.returncode,
                   seconds=time.monotonic() - start)
        rows.append(row)
        print(json.dumps(row), flush=True)
        assert result.returncode == 0, row
    (args.output / 'results.json').open('x').write(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary', type=lambda s: Path(s).resolve())
    p.add_argument('output', type=lambda s: Path(s).resolve())
    p.add_argument('--without-gro', action='store_true')
    p.add_argument('--gso', action='store_true')
    main(p.parse_args())
