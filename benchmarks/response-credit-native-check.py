#!/usr/bin/env python3
"""Bounded real-server response-credit coverage with live socket evidence; no RPS."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import traceback

from concurrent_uploads import collect, cpu_ticks
from response_credit_reports import validate
from udp_accounting import (namespace_delta, namespace_snapshot, process_delta,
                            process_snapshot, require, require_clean_run)


def run(server, peer, output, count, step, mode, cpu):
    output.mkdir(parents=True, exist_ok=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    worker = child = None
    with ExitStack() as files:
        try:
            server_log = files.enter_context((output / 'server.log').open('xb'))
            child = subprocess.Popen([str(server), '--threads', '1', '--tcp', '0', '--quic', str(port),
                                      '--udp-receive-buffer', '4194304'],
                                     stdout=server_log, stderr=subprocess.STDOUT)
            time.sleep(.15)
            require(child.poll() is None, 'server failed to start')
            before = process_snapshot(child.pid, port, 1)
            net_before = namespace_snapshot()
            command = ['taskset', '-c', str(cpu), str(peer), str(port), str(count), str(step), mode, '10', '--controlled']
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=files.enter_context((output / 'peer.stderr').open('xb')), bufsize=0)
            worker = dict(process=process, log=files.enter_context((output / 'peer.jsonl').open('xb')), buffer=b'')
            ready = collect([worker], 'ready', 12)[0]
            require(ready['bootstrap_acked'] and ready['control_bytes'] == 3 and ready['started_requests'] == 0, 'not bootstrapped before workload')
            peer_before = process_snapshot(process.pid, ready['port'], 1)
            cpu_before = cpu_ticks(child.pid)
            controller_start = time.monotonic_ns()
            process.stdin.write(b'start\n')
            row = collect([worker], 'done', 15)[0]
            controller_end = time.monotonic_ns()
            cpu_after = cpu_ticks(child.pid)
            expected_datagrams = row['sent_packets'] + row['received_packets'] + row['handshake_sent'] + row['handshake_received']
            deadline = time.monotonic() + 1
            while True:
                net = namespace_delta(net_before, namespace_snapshot())
                if (net['status'] != 'available' or net['counters']['InDatagrams'] >= expected_datagrams
                        or time.monotonic() >= deadline): break
                time.sleep(.001)
            after = process_snapshot(child.pid, port, 1)
            peer_after = process_snapshot(process.pid, ready['port'], 1)
            net_after = namespace_snapshot()
            evidence = dict(server_before=before, server_after=after, server_delta=process_delta(before, after),
                            peer_before=peer_before, peer_after=peer_after, peer_delta=process_delta(peer_before, peer_after),
                            namespace_delta=namespace_delta(net_before, net_after),
                            cpu_before_ticks=cpu_before, cpu_after_ticks=cpu_after, ticks_per_second=os.sysconf('SC_CLK_TCK'),
                            controller_start_ns=controller_start, controller_end_ns=controller_end)
            (output / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
            result = validate(row, count, step, mode)
            require_clean_run(row['udp'], evidence['server_delta'], evidence['namespace_delta'])
            require(evidence['namespace_delta']['counters']['InDatagrams'] == expected_datagrams, 'exact datagram ledger mismatch')
            delta = evidence['peer_delta']
            require(delta['status'] == 'available' and delta['drops'] == 0, 'peer socket loss/missing evidence')
            for snap in (peer_before, peer_after):
                require(snap['status'] == 'available' and len(snap['sockets']) == 1, 'missing peer identity')
                live = snap['sockets'][0]
                require((live['inode'], live['rcvbuf']) == (row['udp']['after']['inode'], row['udp']['after']['rcvbuf']), 'peer identity changed')
            require(controller_start <= row['interval']['start_monotonic_ns'] < row['interval']['end_monotonic_ns'] <= controller_end, 'measurement includes barrier')
            process.stdin.write(b'exit\n')
            require(process.wait(timeout=3) == 0, 'peer exit failure')
            require(not process.stdout.read(), 'extra terminal report')
            result['command'] = command
            (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
            return result
        except BaseException:
            (output / 'failure.txt').write_text(traceback.format_exc())
            raise
        finally:
            if worker is not None:
                process = worker['process']
                if process.poll() is None: process.kill()
                process.wait(timeout=3)
                worker['log'].write(process.stdout.read())
            if child is not None:
                child.terminate()
                child.wait(timeout=3)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('server', 'peer', 'output'): p.add_argument(key, type=lambda s: Path(s).resolve())
    p.add_argument('--cpu', type=int, default=min(os.sched_getaffinity(0)))
    p.add_argument('--quick', action='store_true')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    cases = [(1, 1, 'each')] if a.quick else (
        [(n, step, 'each') for n in (1, 8, 32, 512) for step in (1, 2, 25)] +
        [(8, 1, mode) for mode in ('withheld', 'sparse', 'loss', 'reorder')])
    rows = []
    for n, step, mode in cases:
        row = run(a.server, a.peer, a.output / f'{n}-{step}-{mode}', n, step, mode, a.cpu)
        rows.append(row)
        print(json.dumps(row), flush=True)
    (a.output / 'summary.json').write_text(json.dumps(dict(cases=rows,
        server_sha256=hashlib.sha256(a.server.read_bytes()).hexdigest(),
        peer_sha256=hashlib.sha256(a.peer.read_bytes()).hexdigest()), indent=2) + '\n')


if __name__ == '__main__': main()
