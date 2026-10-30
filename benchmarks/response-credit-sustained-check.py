#!/usr/bin/env python3
"""Sustained fixed-server workload qualification with exact samples and UDP evidence."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import selectors
import subprocess
import time
import traceback

from concurrent_uploads import collect, cpu_ticks
from response_credit_sustained_reports import validate
from udp_accounting import (namespace_delta, namespace_snapshot, process_delta,
                            process_snapshot, require, require_clean_run)


def collect_terminal(worker, timeout, maximum=512 << 20):
    """Append samples in linear space/time after the CPU stop barrier."""
    require(not worker['buffer'], 'unexpected buffered terminal data')
    data = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as poll:
        poll.register(worker['process'].stdout, selectors.EVENT_READ)
        while True:
            require(time.monotonic() < deadline, 'terminal report timeout')
            if not poll.select(.1): continue
            chunk = os.read(worker['process'].stdout.fileno(), 65536)
            worker['log'].write(chunk)
            worker['log'].flush()
            require(chunk, 'producer exited before report')
            data.extend(chunk)
            require(len(data) <= maximum, 'oversized terminal report')
            if b'\n' in chunk:
                require(data[-1:] == b'\n' and data.count(b'\n') == 1, 'extra terminal report')
                row = json.loads(data)
                require(row['phase'] in ('done','failed'), 'wrong terminal phase')
                return row


def run(server, peer, output, count, window, schedule, mode, cpu, timeout, trace):
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
            command = ['taskset', '-c', str(cpu), str(peer), str(port), str(count), str(window), schedule, mode, str(timeout), '--controlled', *(['--trace'] if trace else [])]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=files.enter_context((output / 'peer.stderr').open('xb')), bufsize=0)
            worker = dict(process=process, log=files.enter_context((output / 'peer.jsonl').open('xb')), buffer=b'')
            ready = collect([worker], 'ready', 12)[0]
            require(ready['bootstrap_acked'] and ready['control_bytes'] == 3 and ready['started_requests'] == 0, 'not bootstrapped before workload')
            peer_before = process_snapshot(process.pid, ready['port'], 1)
            cpu_before = cpu_ticks(child.pid)
            controller_start = time.monotonic_ns()
            process.stdin.write(b'start\n')
            stopped = collect([worker], 'stopped', timeout + 5)[0]
            controller_end = time.monotonic_ns()
            cpu_after = cpu_ticks(child.pid)
            expected_datagrams = sum(stopped[k] for k in ('sent_packets', 'received_packets', 'handshake_sent', 'handshake_received'))
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
                            controller_start_ns=controller_start, controller_end_ns=controller_end,
                            affinities={str(t.name): sorted(os.sched_getaffinity(int(t.name)))
                                        for t in Path(f'/proc/{child.pid}/task').iterdir()},
                            peer_affinity=sorted(os.sched_getaffinity(process.pid)))
            (output / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
            process.stdin.write(b'report\n')
            row = collect_terminal(worker, 30)
            result = validate(row, count, window, schedule, mode)
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
            result['server_cpu_seconds'] = (sum(cpu_after) - sum(cpu_before)) / os.sysconf('SC_CLK_TCK')
            result['server_cpu_cores'] = result['server_cpu_seconds'] / result['elapsed_seconds']
            result['server_cpu_resolution_seconds'] = 1 / os.sysconf('SC_CLK_TCK')
            result['exact_datagrams'] = expected_datagrams
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
    p.add_argument('--count', type=int, default=64)
    p.add_argument('--window', type=int, default=8)
    p.add_argument('--schedule', choices=('byte','two-byte','two-fragment','full'), default='byte')
    p.add_argument('--mode', choices=('each','withheld','sparse','loss','reorder'), default='each')
    p.add_argument('--timeout', type=int, default=60)
    p.add_argument('--trace', action='store_true')
    a = p.parse_args()
    result = run(a.server, a.peer, a.output, a.count, a.window, a.schedule, a.mode, a.cpu, a.timeout, a.trace)
    result['server_sha256'] = hashlib.sha256(a.server.read_bytes()).hexdigest()
    result['peer_sha256'] = hashlib.sha256(a.peer.read_bytes()).hexdigest()
    (a.output / 'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__': main()
