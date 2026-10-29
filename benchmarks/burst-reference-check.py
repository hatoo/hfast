#!/usr/bin/env python3
"""Native owned-socket reference oracles; run in a private network namespace.

Timings are smoke evidence only. Faults terminate actual server/producer
processes while their siblings and raw evidence are still available.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import time
from unittest.mock import patch

import burst_schedule
import burst_sockets
import burst_workers as b


def inspect(output, result, count):
    b.require(result['reference_workers'] == count, 'wrong reference worker count')
    b.require(result['udp_receive_buffer']['workers'] == count, 'missing worker capacities')
    audits = [json.loads(line) for line in (output / 'socket-audit.jsonl').read_text().splitlines()]
    b.require(len(audits) == 1 + 2 * len(result['cycles']), 'missing socket boundary')
    b.require([a['stage'] for a in audits] == ['warmup'] +
              [f'{side}-{i + 1}' for i in range(len(result['cycles']))
               for side in ('before', 'after')], 'wrong socket boundary order')
    initial = json.loads((output / 'reference-start.json').read_text())
    final = json.loads((output / 'reference-end.json').read_text())
    server_inodes = {s['inode'] for s in initial['server']['snapshot']['sockets']}
    producer_inodes = [{s['inode'] for s in p['snapshot']['sockets']}
                       for p in audits[0]['producers']]
    for audit in [initial, *audits, final]:
        burst_sockets.require_clean(audit)
        b.require(len(audit['server']['snapshot']['sockets']) == count
                  and {s['inode'] for s in audit['server']['snapshot']['sockets']} == server_inodes,
                  'server socket set changed')
    for audit in audits:
        b.require(len(audit['producers']) == 4, 'producer omitted')
        for index, producer in enumerate(audit['producers']):
            rows = producer['snapshot']['sockets']
            b.require(len(rows) == 2 and {s['inode'] for s in rows} == producer_inodes[index],
                      'producer socket set changed')
    b.require(result['completed'] == result['latency']['measured']['count']
              + result['latency']['warmup']['count'], 'samples lost')


def disappearance(args, cpus, target, gro):
    output = args.output / f'{target}-exit-gro{int(gro)}'
    capture = burst_sockets.capture
    calls = 0

    def terminate(server_pid, port, count, workers, reports, before=None):
        nonlocal calls
        calls += 1
        if calls == 3:  # startup, settled warmup, then prepared phase 1
            pid = server_pid if target == 'server' else workers[-1]['process'].pid
            os.kill(pid, signal.SIGKILL)
            deadline = time.monotonic() + 2
            while Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0] != 'Z':
                b.require(time.monotonic() < deadline, 'fault process did not exit')
                time.sleep(.001)
        return capture(server_pid, port, count, workers, reports, before=before)

    start = time.monotonic()
    try:
        with patch.object(burst_sockets, 'capture', side_effect=terminate):
            b.run(args.server, args.peer, output, cpus, reference_workers=2, gro=gro,
                  batch=4, datagrams=1, batches=4, warmup=2, cycles=1,
                  latency=True, allow_shared_cpus=True, timeout=5)
    except ValueError as error:
        message = str(error)
    else:
        raise AssertionError('disappeared process accepted')
    b.require(time.monotonic() - start < 15, 'unbounded failure cleanup')
    failed = json.loads((output / 'failure.json').read_text())
    run = json.loads((output / 'run-failure.json').read_text())
    b.require(failed['stage'] == 'before-sockets' and failed['phase'] == 1,
              'failure outside the deliberate socket disappearance')
    b.require(failed['original_error']['message'] == message, 'original failure lost')
    b.require(not (output / 'result.json').exists(), 'failed run published a result')
    b.require(all((output / f'latency-{i}/phase-0.bin').exists() for i in range(4)),
              'warmup samples discarded')
    audits = [json.loads(line) for line in (output / 'socket-audit.jsonl').read_text().splitlines()]
    observed = audits[-1]['server'] if target == 'server' else audits[-1]['producers'][-1]
    b.require(observed['status'] == 'unavailable' and observed['delta'] is None,
              'disappeared sockets appeared lossless')
    pids = [run['server']['pid'], *[w['pid'] for w in failed['workers']]]
    b.require(all(not Path(f'/proc/{pid}').exists() for pid in pids), 'orphan process')
    return dict(case=output.name, expected_failure=message, retained_warmup_samples=32)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    available = sorted(os.sched_getaffinity(0) - {0, 1})
    available = available or sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    spec = importlib.util.spec_from_file_location('schedule_checks',
        Path(__file__).with_name('burst-schedule-check.py'))
    schedules = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schedules)
    cases = []
    for count in (1, 2):
        for gro in (True, False):
            for scheduled in (False, True):
                output = args.output / f'w{count}-gro{int(gro)}-schedule{int(scheduled)}'
                result = b.run(args.server, args.peer, output, cpus, reference_workers=count,
                    gro=gro, batch=32, datagrams=8, batches=8, cycles=1, warmup=2,
                    udp_receive_buffer=4194304, latency=True, allow_shared_cpus=True,
                    schedule=schedules.schedule() if scheduled else None)
                inspect(output, result, count)
                if scheduled:
                    burst_schedule.compare(result, result)
                cases.append(dict(case=output.name, completed=result['completed'],
                                  measured=result['measured_requests'], errors=0))
    for target in ('server', 'producer'):
        for gro in (True, False):
            cases.append(disappearance(args, cpus, target, gro))
    summary = dict(timing_evidence=False, cases=cases,
                   completed=sum(c.get('completed', 0) for c in cases))
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
