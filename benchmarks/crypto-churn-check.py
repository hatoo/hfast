#!/usr/bin/env python3
"""Bounded correctness smoke; reported smoke rates are not performance evidence."""
import argparse
import json
import os
from pathlib import Path

import crypto_churn as c


def main(args):
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    rows = []
    for producers in (1, 4):
        for mode in ('normal', 'reverse', 'overlap-duplicates'):
            for gro in (True, False):
                result = c.run(args.server, args.peer,
                               args.output / f'p{producers}-{mode}-gro{int(gro)}',
                               cpus[:producers], mode=mode, count=8, warmup=2,
                               gro=gro, timeout=30, smoke=True)
                rows.append(dict(mode=mode, producers=producers, gro=gro,
                                 completed=result['completed'], errors=0))
    summary = dict(cases=rows, completed=sum(r['completed'] for r in rows),
                   errors=0, smoke=True)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    main(parser.parse_args())
