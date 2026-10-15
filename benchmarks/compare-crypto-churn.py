#!/usr/bin/env python3
"""Alternate immutable servers under exactly the same bounded TLS/HTTP workload.

Run in an isolated network namespace. Opposite-order confirmation uses a new
output directory and --candidate-first. This script reports evidence, not an
automatic performance acceptance decision.
"""
import argparse
import json
import statistics
from pathlib import Path

import crypto_churn as c


def main(args):
    args.output.mkdir(parents=True)
    rows = []
    order = ['candidate', 'baseline'] if args.candidate_first else ['baseline', 'candidate']
    for pair in range(args.pairs):
        paired = {}
        for variant in (order if pair % 2 == 0 else order[::-1]):
            row = c.run(getattr(args, variant), args.peer,
                        args.output / f'pair-{pair}-{variant}', args.client_cpus,
                        mode=args.mode, count=args.connections, warmup=args.warmup,
                        timeout=args.timeout)
            paired[variant] = dict(connections_per_second=row['connections_per_second'],
                                   cpu_ns=row['server_cpu_ns_per_connection'],
                                   server_cores=row['server_cpu']['cores'],
                                   peer_cores=[p['cores'] for p in row['peer_cpu']],
                                   completed=row['completed'], errors=row['errors'])
        paired['throughput_change_pct'] = 100 * (
            paired['candidate']['connections_per_second'] / paired['baseline']['connections_per_second'] - 1)
        paired['cpu_change_pct'] = 100 * (paired['candidate']['cpu_ns'] / paired['baseline']['cpu_ns'] - 1)
        rows.append(paired)
        print(json.dumps(dict(pair=pair, **paired)), flush=True)
    result = dict(mode=args.mode, client_cpus=args.client_cpus, connections=args.connections,
                  warmup=args.warmup, pairs=rows,
                  median_throughput_change_pct=statistics.median(r['throughput_change_pct'] for r in rows),
                  median_cpu_change_pct=statistics.median(r['cpu_change_pct'] for r in rows))
    (args.output / 'summary.json').open('x').write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    parser.add_argument('--mode', choices=['normal', 'reverse', 'overlap-duplicates'], required=True)
    parser.add_argument('--connections', type=int, default=12000, help='per producer')
    parser.add_argument('--warmup', type=int, default=32)
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--client-cpus', type=int, nargs='+', default=[2, 4, 6, 8])
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--candidate-first', action='store_true')
    args = parser.parse_args()
    c.require(1 <= args.pairs <= 20, 'unbounded comparison')
    main(args)
