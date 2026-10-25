#!/usr/bin/env python3
"""Untimed two-producer full-upload, credit/recovery and UDP accounting checks."""
import argparse
import json
import os
from pathlib import Path

from concurrent_uploads import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server', type=lambda s: Path(s).resolve())
    parser.add_argument('peer', type=lambda s: Path(s).resolve())
    parser.add_argument('output', type=lambda s: Path(s).resolve())
    parser.add_argument('--streams', type=int, nargs='+', default=[1, 8, 32])
    parser.add_argument('--modes', nargs='+', default=['ordinary', 'loss', 'reorder', 'sparse', 'pto'])
    parser.add_argument('--bytes', type=int, default=(1 << 24) + 65543)
    parser.add_argument('--threads', type=int, default=1)
    parser.add_argument('--without-gro', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    available = sorted(os.sched_getaffinity(0))
    clients = [c for c in available if c != 0] or available
    cpus = [clients[i % len(clients)] for i in range(2)]
    rows = []
    for mode in args.modes:
        for count in args.streams:
            name = f'{mode}-s{count}'
            print(json.dumps(dict(case=name, event='start')), flush=True)
            try:
                result = run(args.server, args.peer, args.output / name, cpus, count=count,
                             size=args.bytes, mode=mode, threads=args.threads,
                             gro=not args.without_gro, smoke=True)
                rows.append(dict(case=name, passed=True, completed=result['completed'],
                                 samples=len(result['latencies_ns']), body_bytes=result['body_bytes']))
            except Exception as error:
                rows.append(dict(case=name, passed=False, error=f'{type(error).__name__}: {error}'))
                # Preserve completed work even when strict loss/timing validation
                # rejects the run; never convert recovered loss into a clean run.
                ledger = args.output / name / 'reports.json'
                if ledger.exists():
                    terminal = json.loads(ledger.read_text())['terminal'] or []
                    rows[-1].update(reported_completed=sum(r['completed'] for r in terminal),
                                    retained_samples=sum(len(r['latencies_ns']) for r in terminal))
            (args.output / 'summary.json').write_text(json.dumps(dict(cases=rows, timing=False), indent=2) + '\n')
            print(json.dumps(rows[-1]), flush=True)
    assert all(r['passed'] for r in rows), rows


if __name__ == '__main__':
    main()
