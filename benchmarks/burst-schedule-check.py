#!/usr/bin/env python3
"""Untimed native asymmetric schedules, full overlap and failure evidence checks.

Run in a private network namespace. These short smoke schedules verify the
fixture; they do not establish producer headroom or a server performance gain.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

import burst_schedule
import burst_workers as b


def schedule(cold=8192, delay=20_000_000):
    # Four busy producers may share one CI CPU. Allow several scheduler turns
    # before hot work, and retain enough fixed cold work to cover that lead.
    return [dict(role='hot' if i == 0 else 'cold', batch=32 if i == 0 else 1,
                 datagrams=32 if i == 0 else 1, batches=4 if i == 0 else cold,
                 delay_ns=delay if i == 0 else 0) for i in range(4)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    options = dict(cycles=2, warmup=2, udp_receive_buffer=4194304,
                   latency=True, allow_shared_cpus=True)
    cases = []
    for gro in (True, False):
        path = args.output / f'gro-{int(gro)}'
        result = b.run(args.server, args.peer, path, cpus, gro=gro,
                       schedule=schedule(), **options)
        burst_schedule.compare(result, result)
        b.require(result['measured_requests'] == 2 * (4096 + 3 * 8192), 'wrong fixed count')
        b.require(result['schedule']['latency']['hot']['count'] == 8192
                  and result['schedule']['latency']['cold']['count'] == 49152,
                  'wrong latency population')
        b.require(len(result['latency']['files']) == 12, 'missing warmup/measured exports')
        cases.append(dict(case=path.name, completed=result['completed'],
                          measured=result['measured_requests'], suitable=True))

    # All cold work finishes before the delayed hot producer. Reject the timing
    # interpretation only AFTER preserving every complete response and sample.
    path = args.output / 'early-cold-exit'
    try:
        b.run(args.server, args.peer, path, cpus,
              schedule=schedule(cold=1, delay=100_000_000), **options)
    except RuntimeError as error:
        b.require('do not cover' in str(error), f'unexpected overlap failure: {error}')
    else:
        raise AssertionError('early cold exit accepted')
    observed = json.loads((path / 'schedule-evidence.json').read_text())
    b.require(not observed['schedule']['suitable'] and not (path / 'result.json').exists(),
              'unsuitable timing accepted')
    b.require(observed['latency']['measured']['count'] == 2 * (4096 + 3)
              and len(observed['latency']['files']) == 12, 'unsuitable run discarded samples')
    failed = json.loads((path / 'failure.json').read_text())
    b.require(failed['stage'] == 'schedule-validation', 'wrong early-exit failure stage')
    cases.append(dict(case=path.name, expected_failure=True,
                      retained_samples=observed['completed']))

    # Independent proxy corrupts exports after native completion; it does not
    # change the validator. Reuse the established bounded/reaped child wrapper.
    spec = importlib.util.spec_from_file_location('latency_checks',
        Path(__file__).with_name('burst-latency-check.py'))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    for fault in ('truncated', 'duplicate', 'exit'):
        proxy = checks.fault_proxy(args, fault)
        path = args.output / fault
        try:
            b.run(args.server, proxy, path, cpus, schedule=schedule(), **options)
        except (RuntimeError, ValueError) as error:
            message = str(error)
        else:
            raise AssertionError(f'{fault} accepted')
        expected = {'truncated': 'truncated', 'duplicate': 'duplicate sample', 'exit': 'exited'}[fault]
        b.require(expected in message, f'unrelated {fault} failure: {message}')
        failed = json.loads((path / 'failure.json').read_text())
        b.require(not (path / 'result.json').exists(), 'failed export accepted')
        b.require(all((path / f'latency-{i}/phase-0.bin').exists() for i in range(4)),
                  'prior samples discarded')
        pids = [worker['pid'] for worker in failed['workers']]
        pids.append(int((path / 'fault-child.pid').read_text()))
        b.require(all(not Path(f'/proc/{pid}').exists() for pid in pids), 'orphan producer')
        cases.append(dict(case=fault, expected_failure=message))
    summary = dict(timing_evidence=False, cases=cases)
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
