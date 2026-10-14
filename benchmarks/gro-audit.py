#!/usr/bin/env python3
"""Untimed receive counts using immutable binaries and a libc interposer."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


def main(args):
    args.output.mkdir(parents=True)
    here = Path(__file__).resolve().parent
    library = args.output / 'audit.so'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                    str(here / 'gro-audit.c'), '-ldl', '-o', str(library)], check=True)
    rows = []
    for variant in ('baseline', 'candidate', 'fallback'):
        binary = args.baseline if variant == 'baseline' else args.candidate
        if variant == 'fallback':
            binary = here / 'without-udp-gro.py'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        counters = args.output / (variant + '.bin')
        env = dict(os.environ, LD_PRELOAD=str(library), GRO_AUDIT_COUNTERS=str(counters),
                   HFAST_GRO_BINARY=str(args.candidate))
        command = [str(binary), '--threads', '1', '--tcp', '0', '--quic', str(port),
                   '--max-streams', str(args.batch * args.datagrams * 2)]
        # For the Python seccomp wrapper, preload only when it execs hfast:
        # re-running the constructor would otherwise collide with the counters.
        if variant == 'fallback':
            env.pop('LD_PRELOAD')
            env['HFAST_GRO_PRELOAD'] = str(library)
        with (args.output / (variant + '.server.log')).open('x') as log:
            server = subprocess.Popen(command, stdout=log, stderr=log, env=env)
            try:
                time.sleep(.2)
                assert server.poll() is None
                peer = ['taskset', '-c', str(args.client_cpu), str(args.peer), str(port),
                        str(server.pid), str(args.batch), str(args.datagrams), '64', '1', '8',
                        str(int(variant == 'candidate'))]
                result = subprocess.run(peer, capture_output=True, text=True, timeout=60)
                (args.output / (variant + '.stdout')).open('x').write(result.stdout)
                (args.output / (variant + '.stderr')).open('x').write(result.stderr)
                assert result.returncode == 0, result.stderr
                report = json.loads(result.stdout)
            finally:
                server.terminate()
                server.wait(timeout=5)
        values = struct.unpack('=22Q', counters.read_bytes())
        audit = dict(calls=values[:5], successes=values[5:10], errors=values[10:15],
                     rx_messages=values[15], rx_datagrams=values[16], rx_bytes=values[17],
                     tx_messages=values[18], tx_datagrams=values[19], tx_bytes=values[20],
                     gro_messages=values[21])
        assert audit['rx_datagrams'] == report['sent_datagrams']
        assert audit['tx_datagrams'] == report['received_datagrams']
        expected_messages = report['sent_messages'] if variant == 'candidate' else report['sent_datagrams']
        assert audit['rx_messages'] == expected_messages
        assert audit['gro_messages'] == (72 if variant == 'candidate' and args.datagrams > 1 else 0)
        rows.append(dict(variant=variant, audit=audit, report=report))
        print(json.dumps(dict(variant=variant, audit=audit)), flush=True)
    assert len({r['report']['completed'] for r in rows}) == 1
    assert len({r['audit']['rx_datagrams'] for r in rows}) == 1
    (args.output / 'results.json').open('x').write(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'peer', 'output'):
        p.add_argument(name, type=lambda s: Path(s).resolve())
    p.add_argument('--batch', type=int, default=32)
    p.add_argument('--datagrams', type=int, default=8)
    p.add_argument('--client-cpu', type=int, default=8)
    main(p.parse_args())
