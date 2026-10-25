#!/usr/bin/env python3
"""Coordinate one or four native producers with a single global accounting owner.

Run in an isolated network namespace. Each worker keeps one active and one quiet
connection, and at most one request burst outstanding. No production code changes.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import time

import burst_failure as failure
import burst_buffer
import burst_latency

ERROR_COUNTERS = ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'NoPorts',
                  'InCsumErrors', 'MemErrors')
COUNTERS = ('sent_datagrams', 'sent_messages', 'received_datagrams')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def udp():
    rows = [line.split()[1:] for line in Path('/proc/net/snmp').read_text().splitlines()
            if line.startswith('Udp: ')]
    require(len(rows) == 2 and len(rows[0]) == len(rows[1]), 'invalid UDP counters')
    return dict(zip(rows[0], map(int, rows[1])))


def cpu(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
    ticks = os.sysconf('SC_CLK_TCK')
    return dict(user=int(fields[11]) / ticks, system=int(fields[12]) / ticks)


def cpu_delta(before, after, seconds):
    result = {key: after[key] - before[key] for key in before}
    require(all(value >= 0 for value in result.values()), 'CPU counter decreased')
    result['cores'] = sum(result.values()) / seconds
    return result


def totals(reports):
    return {key: sum(row[peer][key] for row in reports for peer in ('active', 'quiet'))
            for key in COUNTERS}


def validate_delivery(before, after, ledger, gro):
    for key in ERROR_COUNTERS:
        require(before[key] == after[key], f'UDP error: {key}')
    received = ledger['received_datagrams']
    sent = ledger['sent_messages' if gro else 'sent_datagrams']
    incoming = after['InDatagrams'] - before['InDatagrams']
    outgoing = after['OutDatagrams'] - before['OutDatagrams']
    require(incoming == sent + received,
            f'UDP InDatagrams: {incoming}, expected {sent + received}')
    messages = ledger['sent_messages']
    require(messages + (received + 7) // 8 <= outgoing <= messages + received,
            f'UDP OutDatagrams incompatible with GSO: {outgoing}')


def empty_sockets(ports):
    require(len(ports) == len(set(ports)), 'duplicate socket port')
    found = set()
    for line in Path('/proc/net/udp').read_text().splitlines()[1:]:
        fields = line.split()
        port = int(fields[1].split(':')[1], 16)
        if port not in ports:
            continue
        require(port not in found, f'shared UDP port {port}')
        found.add(port)
        tx, rx = (int(value, 16) for value in fields[4].split(':'))
        require(tx == rx == int(fields[-1]) == 0, f'queued/dropped datagram on {port}')
    require(found == set(ports), f'missing sockets: {set(ports) - found}')


def settle(before, reports, port, gro):
    ledger = totals(reports)
    expected = (before['InDatagrams'] + ledger['received_datagrams']
                + ledger['sent_messages' if gro else 'sent_datagrams'])
    deadline = time.monotonic() + 1
    while True:
        after = udp()
        if after['InDatagrams'] >= expected:
            break
        require(time.monotonic() < deadline, 'final ACK not consumed')
        time.sleep(.001)
    validate_delivery(before, after, ledger, gro)
    empty_sockets([port] + [row[p]['port'] for row in reports for p in ('active', 'quiet')])
    return after


def validate_report(row, previous, phase, batches, batch, datagrams, latency=False, producer=0):
    require(row['phase'] == phase, 'wrong/repeated worker phase')
    require(row['errors'] == row['pending_requests'] == row['pending_fences'] == 0,
            'worker errors or unfinished work')
    require(row['quiet_pings'] == phase + 1, 'quiet peer lifecycle mismatch')
    work = row['work']
    requests = batches * batch * datagrams
    first = previous['active']['completed'] if previous else 0
    require(('latency' in row) == latency, 'wrong latency sampling mode')
    if latency:
        burst_latency.metadata(row['latency'], phase, 4 * first, requests, producer=producer)
    expected = dict(batches=batches, requests=requests, first_completed=first,
                    completed=first + requests, request_datagrams=batches * datagrams,
                    fences=batches, sent_datagrams=batches * (datagrams + 1),
                    sent_messages=batches * 2)
    for key, value in expected.items():
        require(work[key] == value, f'wrong {key}: {work[key]}, expected {value}')
    require(work['received_datagrams'] > 0 and work['burst_seconds'] > 0, 'empty work')
    for name in ('active', 'quiet'):
        peer = row[name]
        completed = first + requests if name == 'active' else 0
        require(peer['completed'] == completed and peer['next_stream'] == 4 * completed,
                f'{name} response/stream mismatch')
        require(peer['initial_limit'] == 2 * batch * datagrams
                and peer['stream_limit'] == peer['initial_limit'] + completed,
                f'{name} stream credit mismatch')
        # The static request is 18 bytes; control streams consume five bytes.
        require(peer['sent_data'] == 5 + 18 * completed, f'{name} sent byte mismatch')
        outstanding = peer['initial_max_data'] + peer['sent_data'] - peer['max_data']
        require(0 <= outstanding < peer['initial_max_data'] // 2,
                f'{name} connection credit mismatch')
        require(peer['acked_through'] == peer['last_sent'] - 1,
                f'{name} final fence/PING not acknowledged')
        if previous:
            old = previous[name]
            require(peer['port'] == old['port'], 'connection replaced during measurement')
            require(peer['initial_max_data'] == old['initial_max_data'], 'initial credit changed')
            sent = work['sent_datagrams'] + 1 if name == 'active' else 2
            messages = work['sent_messages'] + 1 if name == 'active' else 2
            require(peer['sent_datagrams'] - old['sent_datagrams'] == sent
                    and peer['sent_messages'] - old['sent_messages'] == messages
                    and peer['last_sent'] - old['last_sent'] == sent, 'sent ledger mismatch')
            received = peer['received_datagrams'] - old['received_datagrams']
            require(received > 0 and peer['last_received'] - old['last_received'] == received
                    and peer['packet_count'] - old['packet_count'] == received,
                    'received packet ledger mismatch')
            if name == 'active':
                require(received == work['received_datagrams'], 'response ledger mismatch')


def collect(workers, phase, timeout):
    """Read exactly one bounded report per process; partial lines cannot block."""
    reports = [None] * len(workers)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as poll:
        for index, worker in enumerate(workers):
            worker['report'] = None
            worker['report_line'] = b''
            poll.register(worker['process'].stdout, selectors.EVENT_READ, index)
        while any(row is None for row in reports):
            remaining = deadline - time.monotonic()
            require(remaining > 0, f'worker phase {phase} timeout')
            for key, _ in poll.select(min(.1, remaining)):
                index = key.data
                worker = workers[index]
                chunk = os.read(key.fileobj.fileno(), 65536)
                worker['stdout'].write(chunk)
                worker['stdout'].flush()
                require(chunk, f'worker {index} exited in phase {phase}; see worker stderr')
                worker['buffer'] += chunk
                require(len(worker['buffer']) <= 65536, 'oversized worker report')
                if b'\n' not in worker['buffer']:
                    continue
                line, extra = worker['buffer'].split(b'\n', 1)
                worker['report_line'] = line
                require(not extra and reports[index] is None, 'duplicate worker report')
                worker['buffer'] = b''
                row = json.loads(line)
                worker['report'] = row
                require(row['phase'] == phase, f'wrong worker {index} phase')
                reports[index] = row
    for worker in workers:
        require(worker['process'].poll() is None, 'worker exited before STOP')
    return reports


def export_latency(workers, reports, output, phase, width, timeout):
    for worker in workers:
        worker['process'].stdin.write(f'EXPORT {phase}\n'.encode())
    exported = collect(workers, phase, timeout)
    evidence = []
    for index, (report, row) in enumerate(zip(reports, exported)):
        require(row.get('latency_export') == report['latency'], 'latency export metadata mismatch')
        path = output / f'latency-{index}' / f'phase-{phase}.bin'
        meta = report['latency']
        evidence.append(burst_latency.inspect(path, meta, phase, meta['first_stream'],
                                              report['work']['requests'], width, producer=index))
    return evidence


def coordinate(peer, server_pid, port, output, cpus, batch, datagrams, batches, cycles,
               warmup, gro, timeout=60, latency=False):
    if latency:
        burst_latency.limits(batch, datagrams, batches, cycles, warmup)
    workers = []
    sample_files = []
    primary = None
    state = dict(phase=0, stage='startup', namespace_before={}, last_success=None,
                 server_baseline=failure.observe(failure.process_snapshot, server_pid))
    with ExitStack() as files:
        events = files.enter_context((output / 'phases.jsonl').open('x'))
        try:
            before = udp()
            netns = os.readlink('/proc/self/ns/net')
            state['namespace_before'] = failure.namespace_at(before, netns)
            for index, core in enumerate(cpus):
                command = ['taskset', '-c', str(core), str(peer), '--worker', str(port),
                           str(batch), str(datagrams), str(warmup)]
                if latency:
                    command += ['--latency-dir', str(output / f'latency-{index}')]
                stderr = files.enter_context((output / f'worker-{index}.stderr').open('xb'))
                stdout = files.enter_context((output / f'worker-{index}.jsonl').open('xb'))
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=stderr, bufsize=0,
                                           env=dict(os.environ, BURST_PRODUCER_INDEX=str(index)))
                workers.append(dict(process=process, stdout=stdout, buffer=b'', command=command))
                os.set_blocking(process.stdout.fileno(), False)
            state['stage'] = 'warmup'
            previous = collect(workers, 0, timeout)
            for index, row in enumerate(previous):
                validate_report(row, None, 0, warmup, batch, datagrams, latency, producer=index)
            after = settle(before, previous, port, gro)
            warmup_reports = previous
            if latency:
                state['stage'] = 'warmup-sample-export'
                sample_files += export_latency(workers, previous, output, 0,
                                               batch * datagrams, timeout)
            events.write(json.dumps(dict(phase=0, workers=previous, udp=after)) + '\n')
            events.flush()
            state['last_success'] = dict(phase=0, reports=previous,
                                         namespace=failure.namespace_at(after, netns))
            # All peers are idle after warmup. No diagnostic syscalls are added
            # to any successful measured phase or native request loop.
            for worker in workers:
                worker['socket_baseline'] = failure.observe(
                    failure.process_snapshot, worker['process'].pid)
            rows = []
            for phase in range(1, cycles + 1):
                state.update(phase=phase, stage='prepare' if latency else 'measured')
                if latency:
                    for worker in workers:
                        worker['process'].stdin.write(f'PREPARE {phase} {batches}\n'.encode())
                    ready = collect(workers, phase, timeout)
                    for index, (old, row) in enumerate(zip(previous, ready)):
                        burst_latency.metadata(row.get('latency_ready'), phase,
                            old['active']['next_stream'], batches * batch * datagrams, ready=True, producer=index)
                state['stage'] = 'measured'
                start_udp = after
                start_totals = totals(previous)
                start_cpu = cpu(server_pid)
                client_cpu = [cpu(w['process'].pid) for w in workers]
                start = time.perf_counter()
                for worker in workers:
                    worker['process'].stdin.write(f'RUN {phase} {batches}\n'.encode())
                reports = collect(workers, phase, timeout)
                for index, (old, new) in enumerate(zip(previous, reports)):
                    validate_report(new, old, phase, batches, batch, datagrams, latency, producer=index)
                after = settle(before, reports, port, gro)
                seconds = time.perf_counter() - start
                server_cpu = cpu_delta(start_cpu, cpu(server_pid), seconds)
                clients = [cpu_delta(old, cpu(w['process'].pid), seconds)
                           for old, w in zip(client_cpu, workers)]
                delta = {key: value - start_totals[key] for key, value in totals(reports).items()}
                validate_delivery(start_udp, after, delta, gro)
                requests = len(workers) * batches * batch * datagrams
                row = dict(phase=phase, requests=requests, seconds=seconds,
                           requests_per_second=requests / seconds, server_cpu=server_cpu,
                           client_cpu=clients, workers=reports, udp_before=start_udp,
                           udp_after=after, **delta)
                if latency:
                    state['stage'] = 'sample-export'
                    sample_files += export_latency(workers, reports, output, phase,
                                                   batch * datagrams, timeout)
                rows.append(row)
                events.write(json.dumps(row) + '\n')
                events.flush()
                previous = reports
                state['last_success'] = dict(phase=phase, reports=reports,
                                             namespace=failure.namespace_at(after, netns))
            # Sockets stay live until every delivery, queue and credit gate passes.
            state['stage'] = 'shutdown'
            for worker in workers:
                worker['process'].stdin.write(b'STOP\n')
            for worker in workers:
                status = worker['process'].wait(timeout=5)
                trailing = os.read(worker['process'].stdout.fileno(), 65536)
                worker['stdout'].write(trailing)
                require(status == 0, 'worker failed at shutdown')
                require(not trailing and not worker['buffer'], 'unexpected report after STOP')
            seconds = sum(row['seconds'] for row in rows)
            requests = sum(row['requests'] for row in rows)
            server_seconds = sum(row['server_cpu']['user'] + row['server_cpu']['system'] for row in rows)
            result = dict(producers=len(workers), client_cpus=cpus, connections=2 * len(workers),
                        batch=batch, datagrams=datagrams, batches=batches, cycles=rows,
                        warmup=warmup_reports, gro=gro, errors=0, pending_requests=0,
                        pending_fences=0, lost_packets=0, duplicate_responses=0,
                        measured_requests=requests, seconds=seconds,
                        requests_per_second=requests / seconds,
                        server_cores=server_seconds / seconds,
                        cpu_ns_per_request=server_seconds * 1e9 / requests,
                        completed=sum(row['active']['completed'] for row in previous),
                        workers=previous, udp_before=before, udp_after=after,
                        commands=[w['command'] for w in workers], **totals(previous))
            if latency:
                state['stage'] = 'sample-validation'
                sample_files = burst_latency.validate_exports(sample_files)
                state['stage'] = 'sample-summary'
                result['latency'] = burst_latency.finish(sample_files)
                burst_latency.compare(result, result, True)
            return result
        except BaseException as error:
            primary = error
            failure.write_failure(output, 'failure', error,
                                  lambda: failure.capture(server_pid, workers, state))
            raise
        finally:
            errors = failure.cleanup(workers)
            try:
                files.close()
            except Exception as error:
                errors.append(f'closing raw evidence: {error}')
            if errors:
                if primary is not None:
                    primary.add_note('Worker cleanup: ' + '; '.join(errors))
                else:
                    raise RuntimeError('Worker cleanup: ' + '; '.join(errors))


def run(server, peer, output, cpus, *, batch=32, datagrams=8, batches=4096,
        cycles=4, warmup=64, gro=True, timeout=60, allow_shared_cpus=False,
        udp_receive_buffer=0, latency=False):
    buffer_flags = burst_buffer.flags(udp_receive_buffer)
    if latency:
        burst_latency.limits(batch, datagrams, batches, cycles, warmup)
    require(len(cpus) in (1, 4), 'use one or four producers')
    require(all(core in os.sched_getaffinity(0) for core in cpus), 'unavailable client CPU')
    require(allow_shared_cpus or (0 in os.sched_getaffinity(0)
            and 0 not in cpus and len(set(cpus)) == len(cpus)),
            'timing requires server CPU 0 and distinct client CPUs')
    require(1 <= batch <= 32 and 1 <= datagrams <= 32
            and 0 < batches <= 1 << 20 and 0 < warmup <= 1 << 20 and cycles > 0,
            'invalid workload')
    require(not any(key in os.environ for key in (
        'LD_PRELOAD', 'GRO_AUDIT_COUNTERS', 'HFAST_GRO_PRELOAD', 'BURST_QUEUE_AUDIT')),
        'instrumented workload cannot be timed')
    output.mkdir(parents=True)
    inputs = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    binary = server if gro else Path(__file__).with_name('without-udp-gro.py')
    command = [str(binary), '--threads', '1', '--tcp', '0', '--quic', str(port),
               '--max-streams', str(2 * batch * datagrams), *buffer_flags]
    manifest = dict(inputs=inputs, server_command=command, client_cpus=cpus, batch=batch,
                    datagrams=datagrams, batches=batches, cycles=cycles, warmup=warmup,
                    gro=gro, timeout=timeout, smoke=allow_shared_cpus,
                    udp_receive_buffer_requested=udp_receive_buffer,
                    receive_buffer_evidence='receive-buffer.json')
    if latency:
        manifest['latency_interval'] = burst_latency.INTERVAL
        manifest['latency_max_samples_per_phase'] = burst_latency.MAX_SAMPLES
    with (output / 'manifest.json').open('x') as file:
        file.write(json.dumps(manifest, indent=2) + '\n')
    with (output / 'server.log').open('x') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log,
                                   env=dict(os.environ, HFAST_GRO_BINARY=str(server)))
        primary = None
        try:
            time.sleep(.2)
            require(process.poll() is None, 'server failed at startup')
            capacity_before = burst_buffer.observe(process.pid, port, udp_receive_buffer)
            with (output / 'receive-buffer.json').open('x') as evidence:
                evidence.write(json.dumps(capacity_before, indent=2) + '\n')
            result = coordinate(peer, process.pid, port, output, cpus, batch, datagrams,
                                batches, cycles, warmup, gro, timeout, latency=latency)
            require(process.poll() is None, 'server exited during measurement')
            result['udp_receive_buffer'] = burst_buffer.interval(
                capacity_before, burst_buffer.observe(process.pid, port, udp_receive_buffer))
        except BaseException as error:
            primary = error
            failure.write_failure(output, 'run-failure', error,
                                  lambda: dict(manifest=manifest, timing_evidence=False,
                                               exit_code=process.poll(),
                                               server=failure.observe(failure.process_snapshot, process.pid),
                                               namespace=failure.observe(failure.namespace_snapshot)))
            raise
        finally:
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except Exception as error:
                if primary is not None:
                    primary.add_note(f'Server cleanup: {error}')
                else:
                    raise
    require(inputs == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (server, peer)},
            'input binary changed')
    result.update(inputs=inputs, server_command=command, smoke=allow_shared_cpus)
    with (output / 'result.json').open('x') as file:
        file.write(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('server', 'peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    parser.add_argument('--client-cpus', default='8,10,12,14')
    for name, default in [('batch', 32), ('datagrams', 8), ('batches', 4096),
                          ('cycles', 4), ('warmup', 64)]:
        parser.add_argument('--' + name, type=int, default=default)
    parser.add_argument('--without-gro', action='store_true')
    parser.add_argument('--latency', action='store_true',
                        help='retain every request timestamp; prepare/export outside timing')
    parser.add_argument('--udp-receive-buffer', type=burst_buffer.argument, default=0,
                        help='server receive-buffer request in bytes (0 keeps the default)')
    args = parser.parse_args()
    result = run(args.server, args.peer, args.output, list(map(int, args.client_cpus.split(','))),
                 batch=args.batch, datagrams=args.datagrams, batches=args.batches,
                 cycles=args.cycles, warmup=args.warmup, gro=not args.without_gro,
                 udp_receive_buffer=args.udp_receive_buffer, latency=args.latency)
    print(json.dumps({key: result[key] for key in ('producers', 'measured_requests', 'completed',
          'seconds', 'requests_per_second', 'server_cores', 'cpu_ns_per_request', 'errors')}))
