#!/usr/bin/env python3
"""Live failure evidence and cleanup oracles; run in a private network namespace.

Deliberate drops and failed workloads are never performance evidence. Production
server and native peer binaries remain unchanged throughout this check.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import burst_workers as b


def controller_fault(args, cpus, producers, gro, fault):
    case = args.output / f'{fault}-p{producers}-gro{int(gro)}'
    wrapper = args.output / f'{case.name}-peer'
    index = producers - 1
    code = ('#!/usr/bin/env python3\nimport json,os,socket,sys\nfrom pathlib import Path\n'
            f'Path({str(case)!r}, "pid-"+os.environ["BURST_PRODUCER_INDEX"]).write_text(str(os.getpid()))\n'
            f'if int(os.environ["BURST_PRODUCER_INDEX"]) != {index}:\n'
            f'    os.execv({str(args.peer)!r}, [{str(args.peer)!r}, *sys.argv[1:]])\n')
    code += dict(
        exit='sys.exit(7)\n',
        malformed='print("{injected malformed report}",flush=True)\ninput()\n',
        truncated='sys.stdout.write("injected partial report")\nsys.stdout.flush()\ninput()\n',
        overflow='''receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
receiver.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024)
receiver.bind(('127.0.0.1',0))
sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(1024):
    assert sender.sendto(b'x'*512,receiver.getsockname())==512
print(json.dumps(dict(kind='injected_overflow',port=receiver.getsockname()[1])),file=sys.stderr,flush=True)
sys.stdout.write('injected overflow; no phase report')
sys.stdout.flush()
input()
''')[fault]
    wrapper.write_text(code)
    wrapper.chmod(0o755)
    started = time.monotonic()
    try:
        b.run(args.server, wrapper, case, cpus[:producers], batch=4, datagrams=1,
              warmup=2, batches=2, cycles=1, gro=gro, timeout=2, allow_shared_cpus=True)
    except (RuntimeError, ValueError) as error:
        original = str(error)
    else:
        raise AssertionError('faulty producer accepted')
    b.require(time.monotonic() - started < 12, 'unbounded failure cleanup')
    evidence = json.loads((case / 'failure.json').read_text())
    run = json.loads((case / 'run-failure.json').read_text())
    b.require(evidence['original_error']['message'] == original, 'original exception lost')
    b.require(not (case / 'result.json').exists(), 'failed run reported as successful')
    b.require(evidence['phase'] == 0 and evidence['last_success'] is None, 'wrong failure phase')
    b.require(evidence['namespace_delta']['status'] == 'available', 'missing namespace counters')
    b.require(evidence['server_delta']['status'] == 'available'
              and evidence['server_delta']['drops'] == 0, 'missing/dirty server identity')
    b.require(run['server']['status'] == 'available', 'server destroyed before run evidence')
    for worker in evidence['workers']:
        b.require(not Path(f"/proc/{worker['pid']}").exists(), 'orphan producer')
        b.require((case / worker['stdout']).exists() and (case / worker['stderr']).exists(),
                  'missing raw worker output')
    b.require(not Path(f"/proc/{run['server']['pid']}").exists(), 'orphan server')
    broken = evidence['workers'][index]
    delta = evidence['namespace_delta']['counters']
    if fault == 'overflow':
        marker = json.loads((case / broken['stderr']).read_text())
        b.require(broken['sockets']['status'] == 'available', 'overflowing socket unavailable')
        overflowing = [s for s in broken['sockets']['sockets'] if s['port'] == marker['port']]
        b.require(len(overflowing) == 1, 'ambiguous overflow socket')
        sock = overflowing[0]
        b.require(sock['rx_queue'] > 0 and sock['rcvbuf'] > 0 and sock['inode'] > 0
                  and len(sock['cookie']) == 2, 'missing queue/capacity/identity')
        b.require(0 < sock['drops'] == delta['RcvbufErrors'] == delta['InErrors'] < 1024,
                  'socket and namespace drops disagree')
        b.require(broken['exit_code'] is None, 'overflow evidence captured after exit')
        if producers == 4:
            b.require(all(w['report'] and w['report']['phase'] == 0
                          for w in evidence['workers'][:index]), 'lost healthy sibling reports')
    elif fault == 'exit':
        b.require(broken['exit_code'] == 7 and broken['sockets']['status'] == 'unavailable'
                  and broken['socket_delta']['drops'] is None, 'exited peer appeared lossless')
    return dict(case=case.name, expected_failure=original, udp_delta=delta, timing_evidence=False)


def native_failure(args, core, gro):
    """The real native worker must report still-owned sockets before exiting."""
    case = args.output / f'native-command-gro{int(gro)}'
    case.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    binary = args.server if gro else Path(__file__).with_name('without-udp-gro.py')
    with (case / 'server.log').open('x') as log, (case / 'peer.stderr').open('xb') as err, \
            (case / 'peer.jsonl').open('xb') as out:
        server = subprocess.Popen([str(binary), '--tcp', '0', '--threads', '1', '--quic', str(port),
                                   '--max-streams', '8'],
                                  stdout=log, stderr=log,
                                  env=dict(os.environ, HFAST_GRO_BINARY=str(args.server)))
        workers = []
        try:
            time.sleep(.2)
            peer = subprocess.Popen(['taskset', '-c', str(core), str(args.peer), '--worker',
                                     str(port), '4', '1', '2'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=err, bufsize=0)
            os.set_blocking(peer.stdout.fileno(), False)
            workers.append(dict(process=peer, stdout=out, buffer=b''))
            ready = b.collect(workers, 0, 5)[0]
            b.validate_report(ready, None, 0, 2, 4, 1)
            peer.stdin.write(b'RUN 2 2\n')  # Must expect phase 1.
            b.require(peer.wait(timeout=5) != 0, 'native worker accepted wrong phase')
        finally:
            try:
                b.require(not b.failure.cleanup(workers), 'native pipe cleanup failed')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
    records = [json.loads(line) for line in (case / 'peer.stderr').read_text().splitlines()
               if line.startswith('{')]
    b.require(len(records) == 1 and records[0]['kind'] == 'burst_failure', 'native record missing')
    row = records[0]
    b.require(row['phase'] == 1 and 'wrong worker phase' in row['error'], 'wrong native failure')
    b.require(row['udp_table']['status'] == 'available', 'missing native socket queues')
    for name in ('active', 'quiet'):
        item = row[name]
        b.require(item['ledger']['status'] == item['socket']['status'] == 'available',
                  'native ledgers disappeared before exit')
        b.require(item['ledger']['value'] == ready[name], 'failure changed native ledger')
        b.require(item['socket']['drops'] == 0 and item['socket']['rcvbuf'] > 0, 'dirty native socket')
        b.require(str(item['socket']['inode']) in row['udp_table']['value'], 'native inode missing')
    return dict(case=case.name, expected_failure=row['error'], timing_evidence=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    results = []
    for gro in (True, False):
        for producers in (1, 4):
            for fault in ('exit', 'malformed', 'truncated', 'overflow'):
                results.append(controller_fault(args, cpus, producers, gro, fault))
        results.append(native_failure(args, cpus[0], gro))
    summary = dict(expected_failures=len(results), cases=results, timing_evidence=False)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(dict(expected_failures=len(results), all_rejected=True)), flush=True)


if __name__ == '__main__':
    main()
