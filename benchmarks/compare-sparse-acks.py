#!/usr/bin/env python3
"""Alternating production sparse-ACK comparisons with an immutable native peer.

Use --reverse for a separate confirmation and a fresh output directory. Each run
warms up on a full cycle, then includes every request, PING gap and final response
fence in the reported cycle rate. ACK fence latency is a distinct metric.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, variant, pair):
    stem = args.output / f'{pair}-{variant}'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    server_command = [str(getattr(args, variant)), '--threads', '1', '--tcp', '0',
                      '--quic', str(port), '--max-streams', str(args.window * 2)]
    with stem.with_suffix('.server.log').open('x') as log:
        server = subprocess.Popen(server_command, stdout=log, stderr=log)
        try:
            time.sleep(0.2)
            assert server.poll() is None
            command = ['/usr/bin/time', '-o', str(stem.with_suffix('.peer-cpu.txt')),
                       '-f', '%U %S %e %M', 'taskset', '-c', str(args.client_cpu),
                       str(args.peer), str(port), str(server.pid), str(args.window),
                       str(args.ranges), str(args.batch), str(args.cycles)]
            p = subprocess.run(command, capture_output=True, text=True, timeout=180)
            stem.with_suffix('.stdout').open('x').write(p.stdout)
            stem.with_suffix('.stderr').open('x').write(p.stderr)
            assert p.returncode == 0, (stem, p.stderr)
            result = json.loads(p.stdout)
            assert server.poll() is None
        finally:
            server.terminate()
            server.wait(timeout=5)
    assert result['errors'] == result['lost_packets'] == result['duplicate_responses'] == 0
    assert len(result['cycles']) == args.cycles
    for cycle in [result['warmup'], *result['cycles']]:
        assert cycle['ack_ranges'] == args.ranges
        assert cycle['outstanding_responses'] == args.window
    assert result['advertised_stream_limit'] == args.window * 2 + result['completed'] - 1
    total = sum(c['completed'] for c in result['cycles'])
    elapsed = sum(c['seconds'] for c in result['cycles'])
    cpu = sum(c['completed'] * c['server_cpu_ns_per_request'] for c in result['cycles']) / total
    result.update(variant=variant, pair=pair, requests_per_second=total / elapsed,
                  cpu_ns_per_request=cpu, measured_requests=total, seconds=elapsed,
                  ack_response_seconds=statistics.median(c['ack_response_seconds'] for c in result['cycles']),
                  command=command, server_command=server_command)
    stem.with_suffix('.json').open('x').write(json.dumps(result, indent=2) + '\n')
    return result


def main(args):
    args.output.mkdir(parents=True)  # Refuse to overwrite any previous evidence.
    inputs = {name: sha(getattr(args, name)) for name in ['baseline', 'candidate', 'peer']}
    rows = []
    paired = []
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
                  'cpu_ns_per_request', 'ack_response_seconds', 'measured_requests']}), flush=True)
        b, c = runs['baseline'], runs['candidate']
        assert b['completed'] == c['completed']
        assert b['measured_requests'] == c['measured_requests']
        assert [x['received_packets'] for x in b['cycles']] == [x['received_packets'] for x in c['cycles']]
        paired.append(dict(pair=pair, rps_percent=(c['requests_per_second']/b['requests_per_second']-1)*100,
                           cpu_percent=((c['cpu_ns_per_request']/b['cpu_ns_per_request']-1)*100 if b['cpu_ns_per_request'] else None),
                           fence_percent=(c['ack_response_seconds']/b['ack_response_seconds']-1)*100))
    assert inputs == {name: sha(getattr(args, name)) for name in inputs}
    summary = dict(inputs=inputs, window=args.window, ranges=args.ranges, batch=args.batch,
                   cycles=args.cycles, pairs=paired, completed=sum(x['completed'] for x in rows),
                   errors=0, reverse=args.reverse,
                   median_rps_percent=statistics.median(x['rps_percent'] for x in paired),
                   median_cpu_percent=(statistics.median(x['cpu_percent'] for x in paired if x['cpu_percent'] is not None) if any(x['cpu_percent'] is not None for x in paired) else None),
                   median_fence_percent=statistics.median(x['fence_percent'] for x in paired))
    (args.output/'results.json').open('x').write(json.dumps(rows, indent=2)+'\n')
    (args.output/'summary.json').open('x').write(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'peer', 'output']:
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    parser.add_argument('--window', type=int, default=65536)
    parser.add_argument('--ranges', type=int, default=256)
    parser.add_argument('--batch', type=int, default=32)
    parser.add_argument('--cycles', type=int, default=32)
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--client-cpu', type=int, default=8)
    parser.add_argument('--reverse', action='store_true')
    args = parser.parse_args()
    assert args.pairs > 0 and args.cycles > 0
    main(args)
