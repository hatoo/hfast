#!/usr/bin/env python3
"""Alternate immutable production servers with exact native distinct-burst accounting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import time
import burst_workers
import burst_buffer
import burst_latency


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, variant, pair):
    buffer_flags = burst_buffer.flags(args.udp_receive_buffer)
    stem = args.output / f'{pair}-{variant}'
    if args.producer_cpus:
        gro = not (args.baseline_without_gro if variant == 'baseline' else args.candidate_without_gro)
        result = burst_workers.run(getattr(args, variant), args.peer, stem, args.producer_cpus,
                                  batch=args.batch, datagrams=args.datagrams, batches=args.batches,
                                  cycles=args.cycles, warmup=args.warmup, gro=gro,
                                  udp_receive_buffer=args.udp_receive_buffer,
                                  latency=getattr(args, "latency", False))
        result.update(variant=variant, pair=pair)
        return result
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    server_command = [str(getattr(args, variant)), '--threads', '1', '--tcp', '0',
                      '--quic', str(port), '--max-streams', str(args.batch * args.datagrams * 2),
                      *buffer_flags]
    with stem.with_suffix('.server.log').open('x') as log:
        server = subprocess.Popen(server_command, stdout=log, stderr=log)
        try:
            time.sleep(.2)
            assert server.poll() is None
            capacity_before = burst_buffer.observe(server.pid, port, args.udp_receive_buffer)
            with stem.with_suffix('.receive-buffer.json').open('x') as evidence:
                evidence.write(json.dumps(capacity_before, indent=2) + '\n')
            command = ['/usr/bin/time', '-o', str(stem.with_suffix('.peer-cpu.txt')),
                       '-f', '%U %S %e %M', 'taskset', '-c', str(args.client_cpu),
                       str(args.peer), str(port), str(server.pid), str(args.batch),
                       str(args.datagrams), str(args.batches), str(args.cycles),
                       str(args.warmup), str(int(variant == 'candidate' and not args.candidate_without_gro))]
            p = subprocess.run(command, capture_output=True, text=True, timeout=300)
            for suffix, data in [('.stdout', p.stdout), ('.stderr', p.stderr)]:
                with stem.with_suffix(suffix).open('x') as file:
                    file.write(data)
            assert p.returncode == 0, (stem, p.stderr)
            result = json.loads(p.stdout)
            assert server.poll() is None
            result['udp_receive_buffer'] = burst_buffer.interval(
                capacity_before, burst_buffer.observe(server.pid, port, args.udp_receive_buffer))
        finally:
            server.terminate()
            server.wait(timeout=5)
    assert not result['queue_audit'], 'instrumented queue audit cannot be timed'
    assert result['gro'] == (variant == 'candidate' and not args.candidate_without_gro)
    assert result['connections'] == 2 and result['quiet_completed'] == 0
    assert result['quiet_stream_limit'] == 2 * args.batch * args.datagrams
    assert result['quiet_pings'] == args.cycles + 2
    assert result['sent_datagrams'] == result['active_sent'] + result['quiet_sent']
    assert result['received_datagrams'] == result['active_received'] + result['quiet_received']
    assert result['quiet_sent'] > 0 and result['quiet_received'] > 0
    assert result['errors'] == result['lost_packets'] == result['duplicate_responses'] == 0
    assert len(result['cycles']) == args.cycles
    assert result['completed'] == args.batch * args.datagrams * (args.warmup + args.cycles * args.batches)
    assert result['advertised_stream_limit'] == 2 * args.batch * args.datagrams + result['completed']
    for cycle, batches in [(result['warmup'], args.warmup), *[(c, args.batches) for c in result['cycles']]]:
        assert cycle['requests'] == batches * args.batch * args.datagrams
        assert cycle['request_datagrams'] == batches * args.datagrams
        assert cycle['sent_datagrams'] == batches * (args.datagrams + 1)
        assert cycle['sent_messages'] == batches * 2
        assert cycle['fences'] == batches
    total = sum(c['requests'] for c in result['cycles'])
    elapsed = sum(c['seconds'] for c in result['cycles'])
    cpu = sum(c['requests'] * c['server_cpu_ns_per_request'] for c in result['cycles']) / total
    peer_user, peer_system, peer_wall, peer_rss = map(float, stem.with_suffix('.peer-cpu.txt').read_text().split())
    result.update(variant=variant, pair=pair, requests_per_second=total / elapsed,
                  cpu_ns_per_request=cpu, measured_requests=total, seconds=elapsed,
                  server_cores=cpu * total / 1e9 / elapsed,
                  peer_cpu=dict(user=peer_user, system=peer_system, wall=peer_wall, rss_kb=peer_rss),
                  peer_cores=(peer_user + peer_system) / peer_wall,
                  command=command, server_command=server_command)
    with stem.with_suffix('.json').open('x') as file:
        file.write(json.dumps(result, indent=2) + '\n')
    return result


def main(args):
    burst_buffer.validate(args.udp_receive_buffer)
    latency = getattr(args, 'latency', False)
    if latency:
        burst_latency.require(args.producer_cpus, '--latency requires --producer-cpus (one or four)')
        burst_latency.limits(args.batch, args.datagrams, args.batches, args.cycles, args.warmup)
    assert not any(name in os.environ for name in (
        'LD_PRELOAD', 'GRO_AUDIT_COUNTERS', 'HFAST_GRO_PRELOAD', 'BURST_QUEUE_AUDIT'
    )), 'audit/instrumentation environment cannot be timed'
    args.output.mkdir(parents=True)
    inputs = {name: sha(getattr(args, name)) for name in ['baseline', 'candidate', 'peer']}
    with (args.output / 'manifest.json').open('x') as file:
        file.write(json.dumps(dict(
            inputs=inputs, udp_receive_buffer_requested=args.udp_receive_buffer,
            arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}),
            indent=2) + '\n')
    rows, paired = [], []
    for pair in range(args.pairs):
        order = ['baseline', 'candidate']
        if (pair + args.reverse) % 2:
            order.reverse()
        runs = {}
        for variant in order:
            result = run(args, variant, pair)
            rows.append(result)
            runs[variant] = result
            print(json.dumps({k: result[k] for k in ['pair', 'variant', 'requests_per_second',
                'cpu_ns_per_request', 'server_cores', 'measured_requests', 'sent_datagrams', 'received_datagrams']}), flush=True)
        b, c = runs['baseline'], runs['candidate']
        burst_buffer.require_equal(b['udp_receive_buffer'], c['udp_receive_buffer'])
        burst_buffer.require_equal(rows[0]['udp_receive_buffer'], c['udp_receive_buffer'])
        tails = burst_latency.compare(b, c, latency)
        assert b['completed'] == c['completed'] and b['sent_datagrams'] == c['sent_datagrams']
        assert b['sent_messages'] == c['sent_messages']
        paired.append(dict(pair=pair, rps_percent=(c['requests_per_second']/b['requests_per_second']-1)*100,
                           cpu_percent=((c['cpu_ns_per_request']/b['cpu_ns_per_request']-1)*100 if b['cpu_ns_per_request'] else None), **tails))
    assert inputs == {name: sha(getattr(args, name)) for name in inputs}
    summary = dict(inputs=inputs, batch=args.batch, datagrams=args.datagrams, batches=args.batches,
                   udp_receive_buffer_requested=args.udp_receive_buffer,
                   receive_buffer_capacities=[r['udp_receive_buffer']['effective_bytes'] for r in rows],
                   producer_cpus=args.producer_cpus, warmup=args.warmup,
                   cycles=args.cycles, pairs=paired, completed=sum(x['completed'] for x in rows),
                   sent_datagrams=sum(x['sent_datagrams'] for x in rows), errors=0, reverse=args.reverse,
                   median_rps_percent=statistics.median(x['rps_percent'] for x in paired),
                   median_cpu_percent=(statistics.median(x['cpu_percent'] for x in paired if x['cpu_percent'] is not None) if any(x['cpu_percent'] is not None for x in paired) else None))
    if latency:
        summary['latency_interval'] = burst_latency.INTERVAL
        summary['measured_samples'] = sum(r['latency']['measured']['count'] for r in rows)
        summary['warmup_samples'] = sum(r['latency']['warmup']['count'] for r in rows)
        for name in ('p50', 'p99', 'p99_9'):
            summary['median_' + name + '_percent'] = statistics.median(p[name + '_percent'] for p in paired)
    for name, data in [('results', rows), ('summary', summary)]:
        with (args.output / f'{name}.json').open('x') as file:
            file.write(json.dumps(data, indent=2) + '\n')
    print(json.dumps(summary),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'peer', 'output']:
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    parser.add_argument('--batch', type=int, default=32)
    parser.add_argument('--datagrams', type=int, default=8)
    parser.add_argument('--batches', type=int, default=4096)
    parser.add_argument('--cycles', type=int, default=16)
    parser.add_argument('--warmup', type=int, default=256)
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--client-cpu', type=int, default=8)
    parser.add_argument('--udp-receive-buffer', type=burst_buffer.argument, default=0,
                        help='identical server receive-buffer request in bytes for both variants')
    parser.add_argument('--latency', action='store_true', help='exact per-request samples in coordinated mode')
    parser.add_argument('--producer-cpus', type=lambda s: list(map(int, s.split(','))),
                        help='coordinated mode: one or four CPUs; both servers default to GRO')
    parser.add_argument('--baseline-without-gro', action='store_true',
                        help='deny baseline UDP_GRO in coordinated mode')
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--candidate-without-gro', action='store_true', help='require baseline delivery semantics for a forced-ENOPROTOOPT candidate')
    args = parser.parse_args()
    assert args.pairs > 0 and args.cycles > 0
    assert not args.baseline_without_gro or args.producer_cpus
    main(args)
