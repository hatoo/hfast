#!/usr/bin/env python3
"""Exact native latency smoke and corrupted-export oracles in a private netns.

Timings here are correctness checks, never performance evidence. Uses immutable
servers and native peers; the fault proxy changes only untimed sample exports.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import burst_latency as latency
import burst_workers as b


def smoke(args, cpus):
    rows = []
    for buffer in (0, 4194304):
        widths = [(1, 1), (18, 2), (32, 2)]
        if buffer:
            widths.append((32, 32))
        for batch, datagrams in widths:
            for producers in (1, 4):
                for gro in (True, False):
                    label = f'b{buffer}-n{batch * datagrams}-p{producers}-gro{int(gro)}'
                    row = b.run(args.server, args.peer, args.output / label, cpus[:producers],
                                batch=batch, datagrams=datagrams, batches=4, cycles=2,
                                warmup=2, gro=gro, allow_shared_cpus=True,
                                udp_receive_buffer=buffer, latency=True)
                    latency.compare(row, row, True)
                    b.require(row['udp_receive_buffer']['status'] == 'available',
                              'missing observed receive capacity')
                    rows.append(dict(case=label, completed=row['completed'],
                                     measured=row['latency']['measured']['count'],
                                     warmup=row['latency']['warmup']['count'],
                                     effective_buffer=row['udp_receive_buffer']['effective_bytes']))
    return rows


def fault_proxy(args, fault):
    path = args.output / f'proxy-{fault}'
    # This proxy is independent of the controller's validator. Three siblings
    # use the native peer directly; only producer 3 corrupts phase-1 exports.
    source = '''#!/usr/bin/env python3
import json,os,signal,struct,subprocess,sys
from pathlib import Path
PEER = @PEER@
FAULT = @FAULT@
if os.environ['BURST_PRODUCER_INDEX'] != '3':
    os.execv(PEER, [PEER, *sys.argv[1:]])
child=subprocess.Popen([PEER, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       text=True, bufsize=1)
directory=Path(sys.argv[sys.argv.index('--latency-dir')+1])
(directory.parent/'fault-child.pid').write_text(str(child.pid))
def terminate(*_):
    raise SystemExit(143)
signal.signal(signal.SIGTERM, terminate)
try:
    for line in child.stdout:
        row=json.loads(line)
        if 'latency_export' in row and row['phase']==1:
            file=directory/'phase-1.bin'
            raw=bytearray(file.read_bytes())
            if FAULT=='exit':
                sys.exit(7)
            elif FAULT=='truncated': raw=raw[:-1]
            elif FAULT=='oversized': raw+=b'x'
            elif FAULT=='wrong-phase': struct.pack_into('<Q',raw,8,0)
            elif FAULT=='duplicate': raw[32+24:32+32]=raw[32:40]
            elif FAULT=='zero-duration': raw[48:56]=raw[40:48]
            file.write_bytes(raw)
        print(line, end='', flush=True)
        command=sys.stdin.readline()
        if not command: break
        child.stdin.write(command);child.stdin.flush()
        if command=='STOP\\n':
            sys.exit(child.wait(timeout=5))
    sys.exit(child.wait(timeout=5))
finally:
    if child.poll() is None: child.kill()
    child.wait(timeout=5)
'''.replace('@PEER@', repr(str(args.peer))).replace('@FAULT@', repr(fault))
    path.write_text(source)
    path.chmod(0o755)
    return path


def faults(args, cpus):
    results = []
    for fault in ('truncated', 'oversized', 'wrong-phase', 'duplicate', 'zero-duration', 'exit'):
        path = args.output / f'fault-{fault}'
        proxy = fault_proxy(args, fault)
        start = time.monotonic()
        try:
            b.run(args.server, proxy, path, cpus, batch=4, datagrams=1, batches=2,
                  cycles=2, warmup=2, timeout=3, allow_shared_cpus=True, latency=True)
        except (ValueError, RuntimeError) as error:
            original = str(error)
        else:
            raise AssertionError('corrupt export accepted: ' + fault)
        b.require(time.monotonic() - start < 15, 'unbounded sample failure cleanup')
        evidence = json.loads((path / 'failure.json').read_text())
        b.require(evidence['original_error']['message'] == original, 'primary failure lost')
        late = fault in ('duplicate', 'zero-duration')
        b.require(evidence['phase'] == (2 if late else 1)
                  and evidence['stage'] == ('sample-validation' if late else 'sample-export'),
                  'failure outside sample export/validation')
        b.require(evidence['last_success']['phase'] == (2 if late else 0), 'lost phase boundary')
        b.require(not (path / 'result.json').exists(), 'failed sample run accepted')
        b.require(all((path / f'latency-{i}/phase-0.bin').exists() for i in range(4)),
                  'failure discarded previous samples')
        pids = [w['pid'] for w in evidence['workers']]
        pids += [int((path / 'fault-child.pid').read_text())]
        b.require(all(not Path(f'/proc/{pid}').exists() for pid in pids), 'orphan producer')
        results.append(dict(case=fault, expected_failure=original, timing_evidence=False))
    return results


def native_failure(args, core):
    """An invalid export command retains exact samples and the primary error."""
    output = args.output / 'native-export-failure'
    output.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    with (output / 'server.log').open('x') as log, (output / 'peer.stderr').open('xb') as err, \
            (output / 'peer.jsonl').open('xb') as out:
        server = subprocess.Popen([str(args.server), '--threads', '1', '--tcp', '0',
            '--quic', str(port), '--max-streams', '8'], stdout=log, stderr=log)
        workers = []
        try:
            time.sleep(.2)
            peer = subprocess.Popen(['taskset', '-c', str(core), str(args.peer), '--worker',
                str(port), '4', '1', '2', '--latency-dir', str(output / 'samples')],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, bufsize=0)
            os.set_blocking(peer.stdout.fileno(), False)
            workers.append(dict(process=peer, stdout=out, buffer=b''))
            report = b.collect(workers, 0, 5)[0]
            b.validate_report(report, None, 0, 2, 4, 1, True)
            b.require(not list((output / 'samples').iterdir()), 'export occurred before controller permission')
            peer.stdin.write(b'EXPORT 1\n')  # Wrong phase, while every sample is still live.
            b.require(peer.wait(timeout=5) != 0, 'invalid export command accepted')
        finally:
            try:
                b.require(not b.failure.cleanup(workers), 'native failure cleanup')
            finally:
                server.terminate()
                server.wait(timeout=5)
    records = [json.loads(line) for line in (output / 'peer.stderr').read_text().splitlines()
               if line.startswith('{')]
    samples, failed = records
    b.require(samples['kind'] == 'burst_latency_failure'
              and samples['latency']['status'] == 'available', 'native failure lost samples')
    b.require(failed['kind'] == 'burst_failure' and 'expected latency EXPORT phase 0' in failed['error'],
              'native failure lost original error')
    b.require(all(failed[p]['socket']['status'] == 'available' for p in ('active', 'quiet')),
              'native failure lost owned socket evidence')
    evidence = latency.validate(output / 'samples/failure-0.bin', report['latency'], 0, 0, 8, 4)
    b.require(latency.summarize([evidence])['count'] == 8, 'native failure omitted samples')
    return dict(case='native-export-command', retained_samples=8, expected_failure=failed['error'],
                timing_evidence=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    available = sorted(os.sched_getaffinity(0) - {0}) or sorted(os.sched_getaffinity(0))
    cpus = [available[i % len(available)] for i in range(4)]
    rows = smoke(args, cpus)
    failures = faults(args, cpus)
    failures.append(native_failure(args, cpus[0]))
    summary = dict(smoke=True, timing_evidence=False, cases=rows, failure_oracles=failures,
                   completed=sum(row['completed'] for row in rows),
                   measured_samples=sum(row['measured'] for row in rows),
                   warmup_samples=sum(row['warmup'] for row in rows), errors=0)
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
