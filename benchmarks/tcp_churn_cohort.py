"""Eight counted H1 churn producers using independent loopback destinations.

Use immutable release binaries. Throughput uses the common command interval,
including all eight complete reports. CPU qualification also checks the interval in
which all eight shb request worker threads are observed alive, excluding report tails.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse
import hashlib
import json
import math
import os
import signal
import socket
import statistics
import subprocess
import time

CLIENT_CPUS = tuple(range(8, 16))
SERVER_CPU = 1
DESTINATIONS = tuple(f'127.0.0.{i + 1}' for i in range(len(CLIENT_CPUS)))
CONNECTIONS = 64
REQUESTS = 131072
WARMUP = 32768
PERCENTILES = ('p10', 'p25', 'p50', 'p75', 'p90', 'p95', 'p99', 'p99.9', 'p99.99')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child_url(index, port):
    require(type(index) is int and 0 <= index < len(CLIENT_CPUS), 'invalid child index')
    require(type(port) is int and 10000 <= port <= 65535, 'invalid five-digit listener port')
    return f'http://{DESTINATIONS[index]}:{port}/'


def client_command(binary, url, cpu, count):
    return ['taskset', '-c', str(cpu), str(binary), '--disable-keepalive', '-c', str(CONNECTIONS),
            '-t', '1', '--batch-size', '1', '-n', str(count),
            '-j', '--timeout', '10s', url]


def timed_command(binary, port, index, count):
    # Relative output names make saved evidence replayable after moving its folder.
    return ['/usr/bin/time', '-o', f'child-{index}.cpu', '-f', '%U %S %e %M', '--',
            *client_command(binary, child_url(index, port), CLIENT_CPUS[index], count)]


def read_cpu(path):
    values = list(map(float, path.read_text().split()))
    require(len(values) == 4 and all(math.isfinite(x) and x >= 0 for x in values),
            'invalid child CPU report')
    return dict(zip(('user', 'system', 'wall', 'maxrss_kb'), values))


def validate_report(report, count, url):
    require(report['requests'] == dict(total=count, ok=count, errors=0, connectErrors=0),
            'request/error accounting mismatch')
    require(report['latencySamples'] == count and report['statusCodes'] == {'200': count},
            'sample/status accounting mismatch')
    require(report['protocol'] == 'HTTP/1.1' and report['threads'] == 1
            and report['connections'] == CONNECTIONS and report['url'] == url,
            'client configuration mismatch')
    for key in ('bytesReceived', 'bytesSent'):
        require(type(report[key]) is int and report[key] > 0, 'invalid byte counter')
    require(report['bytesReceived'] == count * 78, 'incomplete response bytes')
    require(report['bytesSent'] == count * 60, 'request wire byte mismatch')
    latency = report['latencySeconds']
    require(set(latency['percentiles']) == set(PERCENTILES), 'missing percentiles')
    ordered = [latency['min']] + [latency['percentiles'][p] for p in PERCENTILES] + [latency['max']]
    require(all(math.isfinite(v) and v >= 0 for v in ordered + [latency['mean']]),
            'invalid latency')
    require(ordered == sorted(ordered) and latency['min'] <= latency['mean'] <= latency['max'],
            'unordered latency')
    duration = report['durationSeconds']
    require(math.isfinite(duration) and duration > 0, 'invalid duration')
    require(math.isfinite(report['requestsPerSec']) and math.isclose(
        report['requestsPerSec'], count / duration, rel_tol=1e-10), 'invalid report rate')


def validate_cohort(folder, metadata):
    children = metadata['children']
    require(len(children) == len(CLIENT_CPUS)
            and all(type(c['index']) is int for c in children)
            and {c['index'] for c in children} == set(range(len(CLIENT_CPUS))),
            'missing or duplicate child')
    require(metadata['server_alive'] is True, 'server exited')
    start, end = metadata['start_ns'], metadata['end_ns']
    require(0 < start < end and end == max(c['complete_ns'] for c in children),
            'invalid common interval')
    count = metadata['requests_per_child']
    require(type(count) is int and count > 0, 'invalid request budget')
    rows = []
    for child in sorted(children, key=lambda c: c['index']):
        index = child['index']
        url = child_url(index, metadata['port'])
        require(child['exit_code'] == 0, 'failed child')
        require(child['cpu'] == CLIENT_CPUS[index], 'changed CPU configuration')
        require(child['url'] == url and child['destination'] == [DESTINATIONS[index], metadata['port']],
                'changed or duplicate destination tuple')
        require(child['command'] == timed_command(Path(metadata['client']), metadata['port'], index, count)
                and child['actual_command'] == child['command'], 'changed client command')
        require(start <= child['launch_ns'] < child['complete_ns'] <= end,
                'child outside common interval')
        report = json.loads((folder / f'child-{index}.json').read_text())
        validate_report(report, count, url)
        require(report['durationSeconds'] <= (child['complete_ns'] - child['launch_ns']) / 1e9,
                'reported duration exceeds observed interval')
        usage = read_cpu(folder / f'child-{index}.cpu')
        observed = (child['complete_ns'] - child['launch_ns']) / 1e9
        # GNU time prints hundredths of a second; it must fit the enclosing clock.
        require(report['durationSeconds'] <= usage['wall'] + .02
                and usage['wall'] <= observed + .02
                and usage['user'] + usage['system'] <= usage['wall'] + .03,
                'child CPU/wall counters exceed observed interval')
        rows.append(dict(**child, report=report, usage=usage))
    wall = (end - start) / 1e9
    return dict(metadata=metadata, rows=rows, requests=len(CLIENT_CPUS) * count, latency_samples=len(CLIENT_CPUS) * count,
                errors=0, wall=wall, requests_per_sec=len(CLIENT_CPUS) * count / wall,
                producer_cores=[(r['usage']['user'] + r['usage']['system']) / wall for r in rows],
                bytes={k: sum(r['report'][k] for r in rows) for k in ('bytesSent', 'bytesReceived')},
                completion_spread_seconds=(max(c['complete_ns'] for c in children)
                                          - min(c['complete_ns'] for c in children)) / 1e9)


def process_snapshot(pid):
    tids = []
    for directory in sorted(Path(f'/proc/{pid}/task').iterdir()):
        try:
            stat = (directory / 'stat').read_text().split(') ')[1].split()
            sched = list(map(int, (directory / 'schedstat').read_text().split()))
            tids.append(dict(tid=int(directory.name), start_ticks=int(stat[19]),
                             affinity=sorted(os.sched_getaffinity(int(directory.name))),
                             user=int(stat[11]) / os.sysconf('SC_CLK_TCK'),
                             system=int(stat[12]) / os.sysconf('SC_CLK_TCK'),
                             runtime=sched[0] / 1e9, runqueue=sched[1] / 1e9,
                             timeslices=sched[2]))
        except (FileNotFoundError, ProcessLookupError):
            pass  # A worker can exit while the process is producing its report.
    if not tids:
        # The process can exit after task enumeration but before any task read.
        # Treat this exactly like its /proc directory disappearing during sampling.
        raise ProcessLookupError(f'no surviving tasks for pid {pid}')
    return dict(pid=pid, tids=tids, timestamp_ns=time.monotonic_ns())


def assert_affinity(snapshot, core):
    if not (snapshot['tids'] and all(t['affinity'] == [core] for t in snapshot['tids'])):
        observed = [(t['tid'], t['affinity']) for t in snapshot['tids']]
        raise ValueError(f"unexpected task affinity for pid {snapshot['pid']}: "
                         f'expected [{core}], observed {observed}')


def validate_snapshot(snapshot):
    require(type(snapshot['timestamp_ns']) is int and snapshot['timestamp_ns'] > 0,
            'invalid snapshot clock')
    tids = snapshot['tids']
    require(len({t['tid'] for t in tids}) == len(tids), 'duplicate task')
    for task in tids:
        require(task['start_ticks'] > 0 and all(math.isfinite(task[k]) and task[k] >= 0
                for k in ('user', 'system', 'runtime', 'runqueue', 'timeslices')),
                'invalid task counter')


def cpu_delta(before, after):
    validate_snapshot(before)
    validate_snapshot(after)
    require(before['pid'] == after['pid'] and before['timestamp_ns'] < after['timestamp_ns'],
            'changed process or invalid CPU interval')
    old = {t['tid']: t for t in before['tids']}
    new = {t['tid']: t for t in after['tids']}
    require(old.keys() == new.keys(), 'task set changed inside active CPU interval')
    for tid in old:
        require(old[tid]['start_ticks'] == new[tid]['start_ticks'], 'task identity changed')
        require(all(new[tid][k] >= old[tid][k]
                    for k in ('user', 'system', 'runtime', 'runqueue', 'timeslices')),
                'task counter moved backwards')
    return {k: sum(new[t][k] - old[t][k] for t in old)
            for k in ('user', 'system', 'runtime', 'runqueue', 'timeslices')}


def active_cpu(samples):
    previous_ns = 0
    for sample in samples:
        require(sample['timestamp_ns'] > previous_ns, 'unordered CPU samples')
        previous_ns = sample['timestamp_ns']
        validate_snapshot(sample['server'])
        assert_affinity(sample['server'], SERVER_CPU)
        indices = [c['index'] for c in sample['clients']]
        require(indices == sorted(set(indices)), 'duplicate or unordered CPU clients')
        for client in sample['clients']:
            require(type(client['index']) is int and 0 <= client['index'] < len(CLIENT_CPUS),
                    'unknown CPU client')
            validate_snapshot(client)
            assert_affinity(client, CLIENT_CPUS[client['index']])
        require(all(sample['timestamp_ns'] <= process['timestamp_ns'] <= sample['complete_ns']
                    for process in [sample['server'], *sample['clients']]),
                'snapshot outside sampling interval')
    require(all(a['complete_ns'] < b['timestamp_ns'] for a, b in zip(samples, samples[1:])),
            'overlapping sampling intervals')
    active = [s for s in samples if len(s['clients']) == len(CLIENT_CPUS)
              and all(len(c['tids']) == 2 for c in s['clients'])]
    require(len(active) >= 2, 'no shared active request-worker interval')
    first, last = active[0], active[-1]
    # All observations between these boundaries must still contain all eight workers.
    between = [s for s in samples if first['timestamp_ns'] <= s['timestamp_ns'] <= last['timestamp_ns']]
    require(len(active) == len(between), 'discontinuous shared worker interval')
    for before, after in zip(active, active[1:]):
        cpu_delta(before['server'], after['server'])
        for a, b in zip(before['clients'], after['clients']):
            cpu_delta(a, b)
    seconds = (last['server']['timestamp_ns'] - first['server']['timestamp_ns']) / 1e9
    require(seconds > 0, 'invalid active CPU interval')
    server = cpu_delta(first['server'], last['server'])
    clients = [cpu_delta(first['clients'][i], last['clients'][i]) for i in range(len(CLIENT_CPUS))]
    bins = []
    previous = first
    for sample in active[1:]:
        dt = (sample['server']['timestamp_ns'] - previous['server']['timestamp_ns']) / 1e9
        if dt >= 1:
            bins.append(cpu_delta(previous['server'], sample['server'])['runtime'] / dt)
            previous = sample
    return dict(start_ns=first['timestamp_ns'], end_ns=last['timestamp_ns'], seconds=seconds,
                server=server, server_cores=server['runtime'] / seconds,
                producer_cores=[c['runtime'] / ((last['clients'][i]['timestamp_ns']
                    - first['clients'][i]['timestamp_ns']) / 1e9) for i, c in enumerate(clients)],
                server_one_second_bins=bins,
                server_bins_below_085=sum(c < .85 for c in bins), observations=len(active))


def qualification(result):
    active = result['active_cpu']
    reasons = []
    require(len(result['producer_cores']) == len(CLIENT_CPUS)
            and len(active['producer_cores']) == len(CLIENT_CPUS), 'missing producer CPU rate')
    require(all(math.isfinite(v) and v >= 0 for v in [result['wall'], active['seconds'],
                result['server_cores'], active['server_cores'],
                *result['producer_cores'], *active['producer_cores']]), 'invalid CPU rate')
    if result['wall'] < 10 or active['seconds'] < 10:
        reasons.append('interval shorter than 10 seconds')
    if result['server_cores'] < .85 or active['server_cores'] < .85:
        reasons.append('server below 0.85 core')
    if max(result['producer_cores'] + active['producer_cores']) >= .90:
        reasons.append('producer has insufficient CPU headroom')
    return dict(passed=not reasons, reasons=reasons)


def stop(processes):
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for process in processes:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
    # The group may outlive its wrapper. Do not skip it just because poll() exited.
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def child_pid(wrapper):
    try:
        pids = Path(f'/proc/{wrapper.pid}/task/{wrapper.pid}/children').read_text().split()
        return int(pids[0]) if len(pids) == 1 else None
    except FileNotFoundError:
        return None


def sample_client(wrapper, binary, index):
    pid = child_pid(wrapper)
    if pid is None:
        return None
    try:
        # taskset has to exec the fixed client before qualification.
        if Path(f'/proc/{pid}/exe').resolve() != binary:
            return None
        client = process_snapshot(pid)
    except (FileNotFoundError, ProcessLookupError):
        return None
    assert_affinity(client, CLIENT_CPUS[index])
    client['index'] = index
    return client


def run_clients(binary, server, port, folder, count, timeout=300, inject_failure=None):
    folder.mkdir()
    metadata = dict(client=str(binary), port=port, requests_per_child=count, children=[])
    processes = []
    samples = []
    with ExitStack() as stack:
        try:
            before = process_snapshot(server.pid)
            assert_affinity(before, SERVER_CPU)
            metadata['start_ns'] = time.monotonic_ns()
            for index, core in enumerate(CLIENT_CPUS):
                url = child_url(index, port)
                command = timed_command(binary, port, index, count)
                actual = command
                if inject_failure is not None and index == 1:
                    actual = ['/bin/sh', '-c', 'sleep 0.1; exit 17']
                launch = time.monotonic_ns()
                process = subprocess.Popen(actual,
                    stdout=stack.enter_context((folder / f'child-{index}.json').open('x')),
                    stderr=stack.enter_context((folder / f'child-{index}.stderr').open('x')),
                    start_new_session=True, cwd=folder)
                processes.append(process)
                metadata['children'].append(dict(index=index, cpu=core, command=command,
                    url=url, destination=[DESTINATIONS[index], port],
                    actual_command=actual, wrapper_pid=process.pid, launch_ns=launch))
            pending = set(range(len(CLIENT_CPUS)))
            deadline = time.monotonic() + timeout
            next_sample = 0
            while pending:
                require(server.poll() is None, 'server exited during cohort')
                require(time.monotonic() < deadline, 'cohort timeout')
                for index in tuple(pending):
                    code = processes[index].poll()
                    if code is not None:
                        metadata['children'][index].update(exit_code=code, complete_ns=time.monotonic_ns())
                        pending.remove(index)
                        require(code == 0, f'client {index} exited {code}')
                if time.monotonic() >= next_sample and pending:
                    snap = dict(timestamp_ns=time.monotonic_ns(), server=process_snapshot(server.pid), clients=[])
                    assert_affinity(snap['server'], SERVER_CPU)
                    for index in range(len(CLIENT_CPUS)):
                        client = sample_client(processes[index], binary, index)
                        if client is not None:
                            snap['clients'].append(client)
                    snap['complete_ns'] = time.monotonic_ns()
                    samples.append(snap)
                    next_sample = time.monotonic() + .25
                if pending:
                    time.sleep(.005)
            metadata['end_ns'] = max(c['complete_ns'] for c in metadata['children'])
            metadata['server_alive'] = server.poll() is None
            after = process_snapshot(server.pid)
            assert_affinity(after, SERVER_CPU)
            metadata.update(server_before=before, server_after=after)
            write_json(folder / 'metadata.json', metadata)
            write_json(folder / 'cpu-samples.json', samples)
            result = validate_cohort(folder, metadata)
            result['server_cpu'] = cpu_delta(before, after)
            result['server_cores'] = result['server_cpu']['runtime'] / result['wall']
            result['server_cpu_ns_per_request'] = result['server_cpu']['runtime'] * 1e9 / result['requests']
            if count >= REQUESTS:
                result['active_cpu'] = active_cpu(samples)
                result['qualification'] = qualification(result)
            write_json(folder / 'summary.json', result)
            return result
        except BaseException as error:
            write_json(folder / 'failure.json', dict(error=repr(error), metadata=metadata, samples=samples))
            raise
        finally:
            stop(processes)
            write_json(folder / 'cleanup.json', dict(owned_groups=[p.pid for p in processes],
                                                   exit_codes=[p.poll() for p in processes]))


def port_snapshot(port):
    """Bounded observation outside client intervals; never a kernel cost profile."""
    start = time.monotonic_ns()
    rows = []
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        remote, remote_port = fields[2].split(':')
        address = socket.inet_ntoa(bytes.fromhex(remote)[::-1])
        if int(remote_port, 16) == port and address in DESTINATIONS:
            local, local_port = fields[1].split(':')
            rows.append(dict(local=local, local_port=int(local_port, 16),
                             address=address, port=port, state=fields[3]))
    return dict(start_ns=start, end_ns=time.monotonic_ns(), port=port, rows=rows)


def run_server(binary, client, folder, count, hashes, inject_failure=None):
    folder.mkdir()
    require(digest(binary) == hashes['server'] and digest(client) == hashes['client'], 'binary changed')
    for _ in range(100):
        with socket.socket() as sock:
            sock.bind(('0.0.0.0', 0))
            port = sock.getsockname()[1]
        occupancy = port_snapshot(port)
        if not occupancy['rows']:
            break
    else:
        raise ValueError('no fresh destination port available')
    write_json(folder / 'ports-before.json', occupancy)
    command = [str(binary), '--threads', '1', '--tcp', str(port), '--quic', '0']
    with (folder / 'server.log').open('x') as log:
        server = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                require(server.poll() is None and time.monotonic() < deadline, 'server readiness failed')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.01)
            # An actual exchange proves worker startup/self-affinity has finished.
            ready_commands = []
            for index, core in enumerate(CLIENT_CPUS):
                url = child_url(index, port)
                ready = client_command(client, url, core, 128)
                with (folder / f'ready-{index}.json').open('x') as stdout, (folder / f'ready-{index}.stderr').open('x') as stderr:
                    result = subprocess.run(ready, stdout=stdout, stderr=stderr, timeout=15)
                require(result.returncode == 0, 'readiness protocol exchange failed')
                validate_report(json.loads((folder / f'ready-{index}.json').read_text()), 128, url)
                ready_commands.append(ready)
            for tid in Path(f'/proc/{server.pid}/task').iterdir():
                os.sched_setaffinity(int(tid.name), {SERVER_CPU})
            startup = process_snapshot(server.pid)
            assert_affinity(startup, SERVER_CPU)
            write_json(folder / 'server.json', dict(command=command, pid=server.pid, hashes=hashes,
                                                   readiness_commands=ready_commands, startup=startup))
            run_clients(client, server, port, folder / 'warmup', WARMUP if count >= REQUESTS else 16384)
            row = run_clients(client, server, port, folder / 'measured', count, inject_failure=inject_failure)
            write_json(folder / 'ports-after.json', port_snapshot(port))
            require(digest(binary) == hashes['server'] and digest(client) == hashes['client'], 'binary changed')
            return row
        finally:
            stop([server])
            write_json(folder / 'server-cleanup.json', dict(pid=server.pid, exit_code=server.poll()))


def validate_pair(left, right):
    require(left['requests'] == right['requests'], 'pair request mismatch')
    require(left['bytes'] == right['bytes'], 'pair wire byte mismatch')
    for a, b in zip(left['rows'], right['rows']):
        for key in ('bytesSent', 'bytesReceived', 'requests', 'statusCodes', 'latencySamples'):
            require(a['report'][key] == b['report'][key], f'pair child {key} mismatch')
    return dict(rps_percent=100 * (right['requests_per_sec'] / left['requests_per_sec'] - 1),
                cpu_percent=100 * (right['server_cpu_ns_per_request'] / left['server_cpu_ns_per_request'] - 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'client', 'output'):
        parser.add_argument('--' + name, required=True, type=lambda p: Path(p).resolve())
    parser.add_argument('phase', choices=('smoke', 'qualification', 'primary', 'confirm', 'controls', 'failure'))
    args = parser.parse_args()
    require({SERVER_CPU, *CLIENT_CPUS} <= os.sched_getaffinity(0), 'required CPUs unavailable')
    require('LD_PRELOAD' not in os.environ, 'preload instrumentation invalidates timing')
    args.output.mkdir()
    binaries = {k: getattr(args, k) for k in ('baseline', 'candidate', 'client')}
    hashes = {k: digest(p) for k, p in binaries.items()}
    write_json(args.output / 'inputs.json', dict(binaries={k: str(v) for k, v in binaries.items()}, hashes=hashes,
                                               phase=args.phase, requests=REQUESTS, warmup=WARMUP))
    rows, pairs = [], []
    for pair in range({'primary': 4, 'confirm': 3, 'controls': 2}.get(args.phase, 1)):
        order = ['baseline', 'candidate']
        if (pair + int(args.phase == 'confirm')) % 2:
            order.reverse()
        matched = {}
        for variant in order:
            key = 'baseline' if args.phase == 'controls' else variant
            row = run_server(binaries[key], binaries['client'], args.output / f'{pair}-{variant}',
                16384 if args.phase == 'smoke' else REQUESTS,
                dict(server=hashes[key], client=hashes['client']),
                inject_failure=True if args.phase == 'failure' else None)
            row.update(pair=pair, variant=variant)
            rows.append(row)
            matched[variant] = row
            print(json.dumps({k: row[k] for k in ('variant', 'wall', 'requests_per_sec', 'server_cores', 'producer_cores')}
                             | {'qualification': row.get('qualification'), 'active_cpu': row.get('active_cpu')}), flush=True)
            if args.phase in ('primary', 'confirm', 'controls'):
                require(row['qualification']['passed'], 'workload no longer qualifies')
        pairs.append(validate_pair(matched['baseline'], matched['candidate']))
    require(hashes == {k: digest(p) for k, p in binaries.items()}, 'input binary changed')
    write_json(args.output / 'summary.json', dict(rows=rows, pairs=pairs,
               median_rps_percent=statistics.median(p['rps_percent'] for p in pairs), hashes=hashes))


if __name__ == '__main__':
    main()
