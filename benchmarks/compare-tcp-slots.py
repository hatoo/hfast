#!/usr/bin/env python3
"""Fixed accepted shb; exact accounting and all latency quantiles retained."""
import argparse, hashlib, json, os, re, socket, subprocess, sys, time
from pathlib import Path

CASES = {'h1-c1': (False, 1, 1, 131072), 'h1-c128': (False, 128, 1, 2097152),
         'h2-c1-p128': (True, 1, 128, 4194304), 'h2-c128-p1': (True, 128, 1, 2097152)}


def proc(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().split(') ')[1].split()
    sched = list(map(int, Path(f'/proc/{pid}/schedstat').read_text().split()))
    return dict(user=int(fields[11])/os.sysconf('SC_CLK_TCK'),
                system=int(fields[12])/os.sysconf('SC_CLK_TCK'), runtime=sched[0]/1e9,
                runqueue=sched[1]/1e9, timeslices=sched[2])


def client(port, case, count, stem, trace=False):
    h2, connections, parallel, _ = CASES[case]
    cpu_path = O/(stem+'-peer-cpu.txt')
    assert not cpu_path.exists()
    cmd = ['/usr/bin/time', '-o', str(cpu_path), '-f', '%U %S %e %M', 'taskset', '-c', str(ARGS.client_cpu),
           str(ARGS.client), '-j', '-t', '1', '-c', str(connections), '-n', str(count),
           '--batch-size', '1', '--timeout', '5s']
    if h2:
        cmd += ['--http2', '-p', str(parallel)]
    cmd += [f'http://127.0.0.1:{port}/']
    if trace:
        cmd = ['strace', '-f', '-xx', '-s', '512', '-e', 'trace=sendto,sendmsg',
               '-o', str(O/(stem+'-send.trace')), *cmd]
    start = time.monotonic()
    ret = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    wall = time.monotonic()-start
    (O/(stem+'.json')).open('x').write(ret.stdout)
    (O/(stem+'.stderr')).open('x').write(ret.stderr)
    assert ret.returncode == 0, (cmd, ret.stderr)
    report = json.loads(ret.stdout)
    assert report['requests'] == dict(total=count, ok=count, errors=0, connectErrors=0), report
    assert report['statusCodes'] == {'200': count} and report['latencySeconds'], report
    teardown = []
    if trace:
        for line in (O/(stem+'-send.trace')).read_text().splitlines():
            if 'sendto(' not in line and 'sendmsg(' not in line:
                continue
            match = re.search(r'sendto\(\d+, "([^"]*)", (\d+), .*\) = (\d+)$', line)
            assert match, line
            data = bytes.fromhex(match[1].replace('\\x', ''))
            size, result = map(int, match.groups()[1:])
            assert h2 and len(data) == size == result == 17, (line, data)
            assert data == b'\0\0\x08\x07' + bytes(13), data
            teardown.append(result)
        assert len(teardown) == (connections if h2 else 0), (case, teardown)
    values = list(map(float, cpu_path.read_text().split()))
    return dict(report=report, command=cmd, wall_seconds=wall, teardown_bytes=sum(teardown),
                peer_cpu=dict(user=values[0], system=values[1], wall=values[2], maxrss_kb=values[3]))


def run(variant, case, count, stem):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    command = [str(getattr(ARGS, variant)), '--threads', '1', '--tcp', str(port), '--quic', '0']
    with (O/(stem+'-server.log')).open('x') as log:
        server = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            time.sleep(.15)
            assert server.poll() is None and os.sched_getaffinity(server.pid) == {0}
            os.sched_setaffinity(server.pid, {ARGS.server_cpu})
            warm = client(port, case, ARGS.warmup, stem+'-warm')
            time.sleep(.02)
            before = proc(server.pid)
            result = client(port, case, count, stem)
            time.sleep(.02)
            after = proc(server.pid)
            assert server.poll() is None and os.sched_getaffinity(server.pid) == {ARGS.server_cpu}
        finally:
            server.terminate(); server.wait(timeout=5)
    cpu = {k: after[k]-before[k] for k in before}
    result.update(variant=variant, case=case, requests=count, warmup=warm, server_cpu=cpu,
                  cpu_ns_per_request=cpu['runtime']*1e9/count,
                  server_cores=cpu['runtime']/result['wall_seconds'], server_command=command)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(__doc__)
    for name in ['baseline', 'candidate', 'client', 'output']:
        parser.add_argument(name, type=lambda p: Path(p).resolve())
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--server-cpu', type=int, default=1)
    parser.add_argument('--client-cpu', type=int, default=8)
    parser.add_argument('--warmup', type=int, default=16384)
    parser.add_argument('--requests', type=int, help='Override counts for smoke tests only')
    parser.add_argument('--cases', nargs='+', choices=list(CASES), default=list(CASES))
    ARGS = parser.parse_args()
    assert ARGS.pairs > 0 and ARGS.warmup >= 128
    assert ARGS.requests is None or ARGS.requests >= 128
    assert 'LD_PRELOAD' not in os.environ and not any(k.endswith('_AUDIT_FILE') for k in os.environ)
    O = ARGS.output
    O.mkdir(parents=True)
    hashes = {v: hashlib.sha256(getattr(ARGS, v).read_bytes()).hexdigest()
              for v in ['baseline', 'candidate', 'client']}
    rows = []
    for pair in range(ARGS.pairs):
        for i, case in enumerate(ARGS.cases):
            order = ['baseline', 'candidate']
            if (pair + i + ARGS.reverse) % 2:
                order.reverse()
            runs = {}
            for variant in order:
                count = ARGS.requests or CASES[case][3]
                row = run(variant, case, count, f'{pair}-{case}-{variant}')
                row['pair'] = pair
                runs[variant] = row
                rows.append(row)
                print(json.dumps({k: row[k] for k in ['variant', 'case', 'cpu_ns_per_request', 'server_cores']}
                                 | {'rps': row['report']['requestsPerSec']}), flush=True)
            for metric in ['bytesSent', 'bytesReceived', 'requests', 'statusCodes']:
                assert runs['baseline']['report'][metric] == runs['candidate']['report'][metric], (case, metric)
    assert hashes == {v: hashlib.sha256(getattr(ARGS, v).read_bytes()).hexdigest() for v in hashes}
    (O/'results.json').open('x').write(json.dumps(dict(inputs=hashes, rows=rows), indent=2)+'\n')
