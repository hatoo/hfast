#!/usr/bin/env python3
"""Fixed per-peer native requests after all TLS handshakes and warmup complete."""
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import time
import traceback

from burst_workers import cpu, cpu_delta, empty_sockets, require, udp, ERROR_COUNTERS
from crypto_churn import collect


def validate_peers(row, phase, count, rounds, window, previous=None, samples=False):
    require(row['phase'] == phase and row['failed'] == 0, 'wrong/failed phase')
    peers = row['peers']
    require(len(peers) == count, 'missing/extra peer')
    require(len({p['port'] for p in peers}) == count, 'shared peer port')
    for i, p in enumerate(peers):
        require(p['tls_completed'] is True, f'peer {i} incomplete TLS')
        for key in ('requests', 'responses'):
            require(p[key] == rounds * window, f'peer {i} wrong {key}')
        require(p['fences'] == rounds and p['pending_acks'] == p['pending_responses'] == 0,
                f'peer {i} unfinished round')
        require(p['next_stream'] == rounds * window * 4, f'peer {i} wrong stream count')
        require(p['close_sent'] is (phase == 'closed'), f'peer {i} wrong close state')
        require(p['sent_datagrams'] > 0 and p['received_datagrams'] > 0, 'empty UDP ledger')
        if samples:
            require(len(p['latencies_ns']) == rounds * window
                    and all(type(n) is int and n > 0 for n in p['latencies_ns']),
                    f'peer {i} missing/invalid latency')
        if previous is not None:
            old = previous['peers'][i]
            require(p['port'] == old['port'], 'peer replaced during measurement')
            delta = rounds - old['fences']
            # One request datagram and one ACK/PING fence per round; a pure
            # final ACK ends measurement, or one close ends validation.
            require(p['sent_datagrams'] - old['sent_datagrams'] == 2 * delta + 1,
                    'changed request/fence datagram count')
            require(p['received_datagrams'] >= old['received_datagrams'], 'decreased receive count')
            if phase == 'closed':
                require(p['received_datagrams'] == old['received_datagrams'], 'traffic after report')


def validate_done(row, count, rounds, window):
    require(row['phase'] == 'done' and row['failed'] == 0, 'incomplete measured phase')
    require(row['peers'] == count and row['requests'] == row['responses'] == count * rounds * window,
            'wrong measured totals')
    require(math.isfinite(row['seconds']) and row['seconds'] > 0, 'invalid worker time')


def settle(before, rows, server_port):
    peers = [p for row in rows for p in row['peers']]
    ports = [server_port] + [p['port'] for p in peers]
    require(len(set(ports)) == len(ports), 'shared producer port')
    expected = before['InDatagrams'] + sum(p['sent_datagrams'] + p['received_datagrams'] for p in peers)
    deadline = time.monotonic() + 1
    while True:
        after = udp()
        if after['InDatagrams'] >= expected:
            break
        require(time.monotonic() < deadline, 'final ACK/close not consumed')
        time.sleep(.001)
    require(after['InDatagrams'] == expected, 'UDP delivery ledger mismatch')
    for key in ERROR_COUNTERS:
        require(after[key] == before[key], f'UDP error {key}')
    empty_sockets(ports)
    return after


def coordinate(peer, pid, port, output, cpus, count, rounds, window, warmup, timeout):
    workers = []
    maximum = count * (rounds + warmup) * window * 24 + count * 1024 + 8192
    with ExitStack() as files:
        before_udp = udp()
        try:
            for i, core in enumerate(cpus):
                command = ['taskset', '-c', str(core), str(peer), str(port), str(count),
                           str(rounds), str(window), str(warmup)]
                stderr = files.enter_context((output / f'peer-{i}.stderr').open('xb'))
                log = files.enter_context((output / f'peer-{i}.jsonl').open('xb'))
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=stderr, bufsize=0)
                workers.append(dict(process=process, log=log, buffer=b'', command=command))

            def command(text):
                for worker in workers:
                    worker['process'].stdin.write(text.encode() + b'\n')

            ready = collect(workers, 'ready', timeout, maximum)
            for row in ready:
                validate_peers(row, 'ready', count, warmup, window)
            ready_udp = settle(before_udp, ready, port)
            server_before = cpu(pid)
            peer_before = [cpu(w['process'].pid) for w in workers]
            wall_start_ns = time.time_ns()
            start = time.perf_counter()
            command('start')
            done = collect(workers, 'done', timeout, maximum)
            seconds = time.perf_counter() - start
            wall_end_ns = time.time_ns()
            server_cpu = cpu_delta(server_before, cpu(pid), seconds)
            peers_cpu = [cpu_delta(old, cpu(w['process'].pid), seconds)
                         for old, w in zip(peer_before, workers)]
            for row in done:
                validate_done(row, count, rounds, window)
                require(row['seconds'] <= seconds, 'worker exceeded controller interval')
            command('report')
            reported = collect(workers, 'reported', timeout, maximum)
            for old, row in zip(ready, reported):
                validate_peers(row, 'reported', count, warmup + rounds, window, old, samples=True)
            done_udp = settle(before_udp, reported, port)
            command('close')
            closed = collect(workers, 'closed', timeout, maximum)
            for old, row in zip(reported, closed):
                validate_peers(row, 'closed', count, warmup + rounds, window, old)
            final_udp = settle(before_udp, closed, port)
            command('exit')
            for w in workers:
                require(w['process'].wait(timeout=5) == 0, 'producer exit failure')
                trailing = w['process'].stdout.read()
                w['log'].write(trailing)
                require(not trailing, 'unexpected trailing report')
            total = count * rounds * window * len(workers)
            return dict(producers=len(workers), per_producer=count, rounds=rounds, window=window,
                        warmup=warmup, connections=count * len(workers), requests=total,
                        errors=0, seconds=seconds, requests_per_second=total / seconds,
                        measurement_start_unix_ns=wall_start_ns, measurement_end_unix_ns=wall_end_ns,
                        server_cpu=server_cpu, peer_cpu=peers_cpu,
                        server_cpu_ns_per_request=sum(server_cpu[k] for k in ('user', 'system')) * 1e9 / total,
                        ready=ready, done=done, reported=reported, closed=closed,
                        udp_before=before_udp, udp_ready=ready_udp, udp_done=done_udp, udp_final=final_udp,
                        commands=[w['command'] for w in workers])
        except BaseException:
            (output / 'failure-udp.json').open('x').write(json.dumps(
                dict(before=before_udp, after=udp()), indent=2) + '\n')
            (output / 'failure-sockets.txt').open('x').write(Path('/proc/net/udp').read_text())
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


def run(server, peer, output, cpus, *, count=128, rounds=128, window=1, warmup=2,
        receive_buffer=0, gro=True, timeout=120, smoke=False):
    require(len(cpus) in (1, 4) and all(c in os.sched_getaffinity(0) for c in cpus), 'invalid CPU set')
    require(smoke or (0 in os.sched_getaffinity(0) and 0 not in cpus
                     and len(set(cpus)) == len(cpus)), 'invalid timing affinity')
    require(1 <= count <= 128 and 1 <= rounds <= 100_000 and 1 <= window <= 32
            and 1 <= warmup <= 1000 and count * window * (rounds + warmup) <= 1_000_000,
            'unbounded workload')
    require(0 <= receive_buffer <= 4194304, 'invalid receive capacity')
    require(not any(k in os.environ for k in ('LD_PRELOAD', 'HFAST_GRO_PRELOAD')), 'instrumented timing')
    output.mkdir(parents=True)
    inputs = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    binary = server if gro else Path(__file__).with_name('without-udp-gro.py')
    command = [str(binary), '--threads', '1', '--tcp', '0', '--quic', str(port)]
    if receive_buffer:
        command += ['--udp-receive-buffer', str(receive_buffer)]
    with (output / 'server.log').open('x') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log,
                                   env=dict(os.environ, HFAST_GRO_BINARY=str(server)))
        try:
            time.sleep(.2)
            require(process.poll() is None, 'server startup failure')
            result = coordinate(peer, process.pid, port, output, cpus, count, rounds, window, warmup, timeout)
            require(process.poll() is None, 'server exited during workload')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    require(inputs == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)},
            'input binary changed')
    result.update(inputs=inputs, server_command=command, client_cpus=cpus,
                  receive_buffer=receive_buffer, gro=gro, smoke=smoke)
    (output / 'result.json').open('x').write(json.dumps(result, indent=2) + '\n')
    return result
