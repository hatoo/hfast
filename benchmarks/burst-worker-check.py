#!/usr/bin/env python3
"""Bounded native/GRO-denied single- and four-producer correctness smoke.

Run in an isolated network namespace. CPUs may be shared on small CI machines;
the reported smoke timings are not performance evidence.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import burst_workers as b


def main(args):
    args.output.mkdir(parents=True)
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    results = []
    for producers in (1, 4):
        for datagrams in (1, 8):
            for gro in (True, False):
                result = b.run(args.server, args.peer,
                               args.output / f'p{producers}-d{datagrams}-gro{int(gro)}',
                               cpus[:producers], batch=32, datagrams=datagrams,
                               batches=16, cycles=2, warmup=8, gro=gro,
                               timeout=30, allow_shared_cpus=True)
                results.append(result)
    # The original eight-positional-argument peer mode stays independently usable.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    with (args.output / 'legacy-server.log').open('x') as log:
        server = subprocess.Popen([str(args.server), '--threads', '1', '--tcp', '0',
                                   '--quic', str(port), '--max-streams', '512'],
                                  stdout=log, stderr=log)
        try:
            time.sleep(.2)
            command = ['taskset', '-c', str(cpus[0]), str(args.peer), str(port),
                       str(server.pid), '32', '8', '16', '2', '8', '1']
            peer = subprocess.run(command, capture_output=True, text=True, timeout=30)
            (args.output / 'legacy.stdout').open('x').write(peer.stdout)
            (args.output / 'legacy.stderr').open('x').write(peer.stderr)
            b.require(peer.returncode == 0, peer.stderr)
            legacy = json.loads(peer.stdout)
            b.require(legacy['completed'] == 10240 and legacy['errors'] == 0
                      and legacy['quiet_completed'] == 0 and legacy['quiet_pings'] == 4,
                      'legacy response/lifecycle mismatch')
            b.require(server.poll() is None, 'server failed during legacy smoke')
        finally:
            server.terminate()
            server.wait(timeout=5)
    summary = dict(cases=len(results) + 1, completed=sum(r['completed'] for r in results)
                   + legacy['completed'], errors=0, client_cpus=cpus, smoke=True)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    main(parser.parse_args())
