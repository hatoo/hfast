#!/usr/bin/env python3
"""Bounded persistent-peer correctness smoke; its rates are not timing evidence."""
import argparse
import json
import os
from pathlib import Path

import persistent_peers as p


def main(args):
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    rows = []
    configurations = [(1, 1), (4, 4)] + ([(4, 128)] if args.full else [])
    for producers, count in configurations:
        for window in (1, 8):
            for gro in (True, False):
                result = p.run(args.server, args.peer,
                               args.output / f'p{producers}-c{count}-w{window}-gro{int(gro)}',
                               cpus[:producers], count=count, rounds=4, window=window,
                               receive_buffer=4194304 if count == 128 else 0,
                               gro=gro, timeout=120, smoke=True)
                rows.append({key: result[key] for key in ('connections', 'requests', 'errors', 'window', 'gro', 'receive_buffer')})
    summary = dict(cases=rows, connections=sum(r['connections'] for r in rows),
                   requests=sum(r['requests'] for r in rows), errors=0, smoke=True)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    parser.add_argument('--full', action='store_true', help='also exercise 512 live peers with 4 MiB receive request')
    main(parser.parse_args())
