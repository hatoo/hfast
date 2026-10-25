"""Two post-TLS native uploads with one shared UDP ledger. Linux only."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import time
import traceback

from stream_credit_reports import validate
from udp_accounting import (namespace_delta, namespace_snapshot, process_delta,
                            process_snapshot, require, require_clean_group, require_clean_peer)


def collect(workers, phase, timeout, maximum=16 << 20):
    """Bounded reports; persist every byte before parsing, including failures."""
    rows = [None] * len(workers)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as poll:
        for i, worker in enumerate(workers):
            poll.register(worker['process'].stdout, selectors.EVENT_READ, i)
        while any(row is None for row in rows):
            require(time.monotonic() < deadline, f'{phase} timeout')
            for key, _ in poll.select(min(.1, max(0, deadline - time.monotonic()))):
                i, worker = key.data, workers[key.data]
                chunk = os.read(key.fileobj.fileno(), 65536)
                worker['log'].write(chunk)
                worker['log'].flush()
                require(chunk, f'producer {i} exited in {phase}')
                worker['buffer'] += chunk
                require(len(worker['buffer']) <= maximum, 'oversized producer report')
                if b'\n' in worker['buffer']:
                    line, extra = worker['buffer'].split(b'\n', 1)
                    require(not extra and rows[i] is None, 'duplicate producer report')
                    row = json.loads(line)
                    # Failed terminal rows remain visible while collecting the
                    # other producer. Aggregate validation will reject them.
                    require(row['phase'] in (('done', 'failed') if phase == 'done' else (phase,)),
                            f'producer {i} wrong phase: {row}')
                    rows[i] = row
                    worker['buffer'] = b''
    return rows


def validate_ready(rows, count, size, mode):
    require(len(rows) == 2, 'two ready producers required')
    for row in rows:
        require(row['phase'] == 'ready' and row['tls_ready'] is True, 'TLS not ready')
        require(row['streams'] == count and row['body_bytes_per_stream'] == size
                and row['mode'] == mode, 'wrong ready workload')
        require(row['sent_data'] == row['sent_packets'] == 0, 'upload before start barrier')
        require_clean_peer(row['udp'])
    require(len({r['port'] for r in rows}) == 2
            and len({r['udp']['after']['inode'] for r in rows}) == 2, 'shared producer socket')


def aggregate(rows, ready, count, size, mode, start_ns, end_ns):
    """Use the union interval, never a sum/average of overlapping durations."""
    validate_ready(ready, count, size, mode)
    require(len(rows) == 2, 'missing producer result')
    for row, old in zip(rows, ready):
        require(row['mode'] == mode and row['body_bytes_per_stream'] == size, 'changed workload')
        validate(row, count, size)
        require(row['port'] == old['port'] and row['udp']['before'] == old['udp']['before'],
                'producer socket replaced')
        interval = row['interval']
        require(all(type(interval[k]) is int for k in
                    ('start_monotonic_ns', 'end_monotonic_ns', 'elapsed_ns', 'cpu_elapsed_ns')),
                'invalid native clocks')
        lo, hi = interval['start_monotonic_ns'], interval['end_monotonic_ns']
        require(start_ns <= lo < hi <= end_ns, 'native interval outside controller')
        require(row['elapsed_ns'] == interval['elapsed_ns'] == hi - lo
                and interval['cpu_elapsed_ns'] > 0, 'inconsistent native duration')
        require(all(0 < n <= hi - lo for n in row['latencies_ns']), 'latency outside native interval')
    lo = min(r['interval']['start_monotonic_ns'] for r in rows)
    hi = max(r['interval']['end_monotonic_ns'] for r in rows)
    overlap = min(r['interval']['end_monotonic_ns'] for r in rows) - max(
        r['interval']['start_monotonic_ns'] for r in rows)
    require(overlap > 0, 'producers did not overlap')
    total = count * 2
    return dict(completed=total, body_bytes=total * size, errors=0,
                start_monotonic_ns=lo, end_monotonic_ns=hi, elapsed_ns=hi - lo,
                start_skew_ns=abs(rows[0]['interval']['start_monotonic_ns'] -
                                  rows[1]['interval']['start_monotonic_ns']),
                overlap_ns=overlap, requests_per_second=total * 1e9 / (hi - lo),
                peer_cpu_cores=[r['interval']['cpu_elapsed_ns'] / r['elapsed_ns'] for r in rows],
                latencies_ns=[n for r in rows for n in r['latencies_ns']])


def cpu_ticks(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
    return [int(fields[11]), int(fields[12])]


def capture(pid, port, threads, workers, ready, before, net_before, peer_before):
    after = process_snapshot(pid, port, threads)
    peers = [process_snapshot(w['process'].pid, r['port'], 1) for w, r in zip(workers, ready)]
    net_after = namespace_snapshot()
    return dict(server_before=before, server_after=after, server_delta=process_delta(before, after),
                peer_before=peer_before, peer_after=peers,
                peer_deltas=[process_delta(a, b) for a, b in zip(peer_before, peers)],
                namespace_before=net_before, namespace_after=net_after,
                namespace_delta=namespace_delta(net_before, net_after))


def validate_udp(rows, evidence):
    require_clean_group([r['udp'] for r in rows], evidence['server_delta'], evidence['namespace_delta'])
    require(len(evidence['peer_deltas']) == len(evidence['peer_before'])
            == len(evidence['peer_after']) == 2, 'missing live producer evidence')
    for row, before, after, delta in zip(rows, evidence['peer_before'], evidence['peer_after'],
                                       evidence['peer_deltas']):
        require(delta['status'] == 'available' and delta['drops'] == 0, 'live producer socket loss')
        for snapshot in (before, after):
            require(snapshot['status'] == 'available' and len(snapshot['sockets']) == 1,
                    'missing producer identity')
            live, native = snapshot['sockets'][0], row['udp']['after']
            require((live['inode'], live['rcvbuf']) == (native['inode'], native['rcvbuf']),
                    'native/live producer identity mismatch')
    # Each localhost send must have been delivered exactly once, across both
    # connections including TLS, intentional authenticated loss and final close.
    require(all(type(r[k]) is int and r[k] > 0 for r in rows
                for k in ('total_sent_datagrams', 'total_received_datagrams')), 'invalid datagram count')
    expected = sum(r['total_sent_datagrams'] + r['total_received_datagrams'] for r in rows)
    counters = evidence['namespace_delta']['counters']
    # UDP_SEGMENT may account one server send in OutDatagrams but deliver
    # several datagrams. InDatagrams counts the receives at both loopback ends.
    require(counters['InDatagrams'] == expected,
            'shared datagram ledger mismatch (queued, missing or unrelated traffic)')


def coordinate(peer, pid, port, output, cpus, *, count=1, size=1 << 20,
               mode='ordinary', threads=1, timeout=45):
    require(len(cpus) == 2 and 1 <= count <= 64 and 0 < size <= 1 << 30
            and 0 < timeout <= 300, 'invalid bounded workload')
    workers, ready, peer_before = [], [], []
    rows, evidence, result = None, None, None
    before, net_before = process_snapshot(pid, port, threads), namespace_snapshot()
    with ExitStack() as files:
        try:
            for i, core in enumerate(cpus):
                command = ['taskset', '-c', str(core), str(peer), str(port), str(count), str(size),
                           mode, str(timeout), '--controlled']
                log = files.enter_context((output / f'peer-{i}.jsonl').open('xb'))
                err = files.enter_context((output / f'peer-{i}.stderr').open('xb'))
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=err, bufsize=0,
                                           env=dict(os.environ, UPLOAD_PRODUCER_INDEX=str(i)))
                workers.append(dict(process=process, log=log, buffer=b'', command=command))
            ready = collect(workers, 'ready', timeout, 16384)
            validate_ready(ready, count, size, mode)
            peer_before = [process_snapshot(w['process'].pid, r['port'], 1)
                           for w, r in zip(workers, ready)]
            server_cpu_before = cpu_ticks(pid)
            start_ns = time.monotonic_ns()
            for worker in workers:
                worker['process'].stdin.write(b'start\n')
            rows = collect(workers, 'done', timeout + 5)
            end_ns = time.monotonic_ns()
            server_cpu_after = cpu_ticks(pid)
            # Allow final server-bound close packets to be consumed. Never
            # drain peers or suppress a queued datagram to repair the ledger.
            expected = sum(r['total_sent_datagrams'] + r['total_received_datagrams'] for r in rows)
            deadline = time.monotonic() + 1
            while True:
                net = namespace_delta(net_before, namespace_snapshot())
                if (net['status'] != 'available' or net['counters']['InDatagrams'] >= expected
                        or time.monotonic() >= deadline):
                    break
                time.sleep(.001)
            evidence = capture(pid, port, threads, workers, ready, before, net_before, peer_before)
            result = aggregate(rows, ready, count, size, mode, start_ns, end_ns)
            validate_udp(rows, evidence)
            for worker in workers:
                worker['process'].stdin.write(b'exit\n')
            for worker in workers:
                require(worker['process'].wait(timeout=5) == 0, 'producer exit failure')
                trailing = worker['process'].stdout.read()
                worker['log'].write(trailing)
                require(not trailing, 'trailing producer report')
            result.update(ready=ready, workers=rows, udp=evidence, mode=mode, streams_per_producer=count,
                          body_bytes_per_stream=size, controller_start_ns=start_ns, controller_end_ns=end_ns,
                          server_cpu=dict(before_ticks=server_cpu_before, after_ticks=server_cpu_after,
                                          ticks_per_second=os.sysconf('SC_CLK_TCK'),
                                          interval='controller start through terminal reports; excludes TLS'),
                          commands=[w['command'] for w in workers])
            return result
        except BaseException:
            (output / 'failure.txt').write_text(traceback.format_exc())
            raise
        finally:
            if evidence is None:
                evidence = capture(pid, port, threads, workers, ready, before, net_before, peer_before)
            (output / 'udp.json').write_text(json.dumps(evidence, indent=2) + '\n')
            (output / 'reports.json').write_text(json.dumps(dict(ready=ready, terminal=rows), indent=2) + '\n')
            # Keep raw output from every child, even if a sibling exited or its
            # report was malformed. Kill first, then drain; all waits are bounded.
            for worker in workers:
                process = worker['process']
                if process.poll() is None:
                    process.kill()
                remainder, _ = process.communicate(timeout=5)
                worker['log'].write(remainder)


def run(server, peer, output, cpus, *, count=1, size=1 << 20, mode='ordinary',
        threads=1, gro=True, timeout=45, smoke=False):
    available = os.sched_getaffinity(0)
    require(len(cpus) == 2 and all(c in available for c in cpus), 'unavailable producer CPUs')
    require(smoke or (0 in available and 0 not in cpus and len(set(cpus)) == 2),
            'timing requires separate server/producer CPUs')
    require(threads in (1, 2), 'one or two server workers required')
    require(not any(k in os.environ for k in ('LD_PRELOAD', 'HFAST_GRO_PRELOAD')), 'instrumented run')
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    binary = server if gro else Path(__file__).with_name('without-udp-gro.py')
    command = [str(binary), '--threads', str(threads), '--tcp', '0', '--quic', str(port)]
    manifest = dict(inputs=inputs, server_command=command, cpus=cpus, smoke=smoke, gro=gro,
                    count=count, size=size, mode=mode, timeout=timeout)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    with (output / 'server.log').open('x') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log,
                                   env=dict(os.environ, HFAST_GRO_BINARY=str(server)))
        try:
            time.sleep(.2)
            require(process.poll() is None, 'server startup failed')
            result = coordinate(peer, process.pid, port, output, cpus, count=count, size=size,
                                mode=mode, threads=threads, timeout=timeout)
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
    result.update(manifest)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
