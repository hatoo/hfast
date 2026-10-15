#!/usr/bin/env python3
"""Strict controller for bounded native CRYPTO connection churn."""
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import socket
import subprocess
import time
import traceback

from burst_workers import cpu, cpu_delta, empty_sockets, require, udp, ERROR_COUNTERS


def schedule(mode, size):
    require(size >= 24, 'short TLS flight')
    chunk = min(96, size // 3)
    ranges = [[start, min(start + chunk, size)] for start in range(0, size, chunk)]
    if mode != 'normal':
        ranges.reverse()
    if mode == 'overlap-duplicates':
        ranges = [ranges[0]] * 8 + ranges[:-1] + [[chunk // 2, min(2 * chunk, size)]] + ranges[-1:]
    require(mode in ('normal', 'reverse', 'overlap-duplicates'), 'invalid schedule')
    return ranges


def validate_epochs(epochs, mode):
    require(len(epochs) == 2, 'missing/extra TLS epoch')
    for plan in epochs:
        expected = schedule(mode, plan['bytes'])
        require(plan['schedule'] == expected, 'wrong schedule')
        require(len(bytes.fromhex(plan['original_hex'])) == plan['bytes'], 'wrong TLS bytes')
        sent = plan['sent']
        require([[r['start'], r['stop']] for r in sent] == expected, 'wrong emitted ranges')
        pns = [r['packet'] for r in sent]
        require(pns == sorted(set(pns)), 'replayed/reordered encrypted packets')
    return (sum(len(p['sent']) for p in epochs),
            sum(r['stop'] - r['start'] for p in epochs for r in p['sent']))


def validate_done(row, mode, count):
    require(row['phase'] == 'done' and row['failed'] == 0, 'failed/incomplete producer')
    for key in ('offered', 'completed', 'requests', 'responses', 'tls_completed', 'close_sent'):
        require(row[key] == count, f'wrong {key}')
    require(len(row['latencies_ns']) == count
            and all(isinstance(n, int) and n > 0 for n in row['latencies_ns']),
            'missing/invalid latency samples')
    require(math.isfinite(row['seconds']) and row['seconds'] > 0, 'invalid elapsed time')
    packets, size = validate_epochs(row['epochs'], mode)
    require(row['crypto_packets'] == packets * count and row['crypto_bytes'] == size * count,
            'inhomogeneous TLS workload')


def collect(workers, phase, timeout, maximum):
    rows = [None] * len(workers)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as poll:
        for i, worker in enumerate(workers):
            poll.register(worker['process'].stdout, selectors.EVENT_READ, i)
        while any(row is None for row in rows):
            require(time.monotonic() < deadline, f'{phase} timeout')
            for key, _ in poll.select(.1):
                i = key.data
                w = workers[i]
                chunk = os.read(key.fileobj.fileno(), 65536)
                w['log'].write(chunk)
                w['log'].flush()
                require(chunk, f'producer {i} exited in {phase}')
                w['buffer'] += chunk
                require(len(w['buffer']) <= maximum, 'oversized report')
                if b'\n' in w['buffer']:
                    line, extra = w['buffer'].split(b'\n', 1)
                    require(not extra and rows[i] is None, 'duplicate report')
                    row = json.loads(line)
                    require(row['phase'] == phase, f'producer {i} failed/wrong phase: {row}')
                    rows[i] = row
                    w['buffer'] = b''
    return rows


def coordinate(peer, pid, port, output, cpus, mode, count, warmup, timeout):
    workers = []
    with ExitStack() as files:
        before_udp = udp()
        try:
            for i, core in enumerate(cpus):
                command = ['taskset', '-c', str(core), str(peer), str(port), mode,
                           str(count), str(warmup)]
                stderr = files.enter_context((output / f'peer-{i}.stderr').open('xb'))
                log = files.enter_context((output / f'peer-{i}.jsonl').open('xb'))
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=stderr, bufsize=0)
                workers.append(dict(process=process, log=log, buffer=b'', command=command))
            ready = collect(workers, 'ready', timeout, 8192)
            require(all(r['warmup'] == warmup for r in ready), 'wrong warmup')
            require(len({r['port'] for r in ready}) == len(workers), 'shared source address')
            server_before = cpu(pid)
            peers_before = [cpu(w['process'].pid) for w in workers]
            start = time.perf_counter()
            for w in workers:
                w['process'].stdin.write(b'start\n')
            done = collect(workers, 'done', timeout, count * 32 + 65536)
            seconds = time.perf_counter() - start
            server_cpu = cpu_delta(server_before, cpu(pid), seconds)
            peers_cpu = [cpu_delta(old, cpu(w['process'].pid), seconds)
                         for old, w in zip(peers_before, workers)]
            for row in done:
                validate_done(row, mode, count)
            for w in workers:
                w['process'].stdin.write(b'validate\n')
            final = collect(workers, 'validated', timeout, 8192)
            for old, row in zip(ready, final):
                require({k: v for k, v in row.items() if k != 'ledger'}
                        == dict(phase='validated', retirement_probes=1,
                                    replacements_verified=warmup + count,
                                    maximum_server_addresses=1, port=old['port'], failed=0),
                        'lifecycle mismatch')
            expected = before_udp['InDatagrams'] + sum(
                r['ledger']['sent_datagrams'] + r['ledger']['received_datagrams'] for r in final)
            deadline = time.monotonic() + 1
            while True:
                after_udp = udp()
                if after_udp['InDatagrams'] >= expected:
                    break
                require(time.monotonic() < deadline, 'final close not consumed')
                time.sleep(.001)
            # Clients emit individual datagrams, so GRO cannot aggregate their
            # input; clients themselves have GRO disabled. This counts receive
            # operations across both ends, including every final close.
            require(after_udp['InDatagrams'] == expected, 'UDP delivery ledger mismatch')
            for key in ERROR_COUNTERS:
                require(after_udp[key] == before_udp[key], f'UDP error {key}')
            empty_sockets([port] + [r['port'] for r in ready])
            for w in workers:
                w['process'].stdin.write(b'exit\n')
            for w in workers:
                require(w['process'].wait(timeout=5) == 0, 'producer exit failure')
                trailing = w['process'].stdout.read()
                w['log'].write(trailing)
                require(not trailing, 'unexpected final output')
            total = count * len(workers)
            return dict(mode=mode, producers=len(workers), client_cpus=cpus,
                        per_producer=count, warmup=warmup, completed=total, errors=0,
                        seconds=seconds, connections_per_second=total / seconds,
                        server_cpu=server_cpu, peer_cpu=peers_cpu,
                        server_cpu_ns_per_connection=sum(server_cpu[k] for k in ('user', 'system')) * 1e9 / total,
                        ready=ready, workers=done, final=final,
                        udp_before=before_udp, udp_after=after_udp,
                        commands=[w['command'] for w in workers])
        except BaseException:
            (output / 'failure.txt').open('x').write(traceback.format_exc())
            raise
        finally:
            for w in workers:
                process = w['process']
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdin.close()
                process.stdout.close()


def run(server, peer, output, cpus, *, mode, count=10000, warmup=32,
        gro=True, timeout=120, smoke=False):
    require(len(cpus) in (1, 4), 'one or four producers required')
    require(all(c in os.sched_getaffinity(0) for c in cpus), 'unavailable CPU')
    require(smoke or (0 in os.sched_getaffinity(0) and 0 not in cpus
                     and len(cpus) == len(set(cpus))), 'invalid timing affinity')
    require(1 <= count <= 1_000_000 and 1 <= warmup <= 100_000, 'invalid work bound')
    require(not any(k in os.environ for k in ('LD_PRELOAD', 'HFAST_GRO_PRELOAD')),
            'instrumented timing')
    output.mkdir(parents=True)
    inputs = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    binary = server if gro else Path(__file__).with_name('without-udp-gro.py')
    command = [str(binary), '--threads', '1', '--tcp', '0', '--quic', str(port)]
    with (output / 'server.log').open('x') as log:
        server_process = subprocess.Popen(command, stdout=log, stderr=log,
                                          env=dict(os.environ, HFAST_GRO_BINARY=str(server)))
        try:
            time.sleep(.2)
            require(server_process.poll() is None, 'server startup failure')
            result = coordinate(peer, server_process.pid, port, output, cpus,
                                mode, count, warmup, timeout)
            require(server_process.poll() is None, 'server exited during workload')
        finally:
            server_process.terminate()
            server_process.wait(timeout=5)
    require(inputs == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)},
            'input binary changed')
    result.update(inputs=inputs, server_command=command, smoke=smoke, gro=gro)
    (output / 'result.json').open('x').write(json.dumps(result, indent=2) + '\n')
    return result
