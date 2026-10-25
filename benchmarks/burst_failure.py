"""Best-effort, untimed evidence for failed native burst runs.

Observations are not atomic. Socket deltas require stable process, namespace,
inode, FD and SOCK_DIAG cookie identities. Unavailable evidence stays explicit.
"""
import json
import os
from pathlib import Path
import socket
import sys
import time
import traceback

from udp_accounting import (namespace_delta, namespace_snapshot, owned_inodes,
                            parse_udp, process_delta, process_identity,
                            require, socket_diagnostics)


def observe(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return dict(status='unavailable', error=f'{type(error).__name__}: {error}')


def process_snapshot(pid, deadline=None):
    """Discover sockets even when a worker has not produced its first report."""
    result = dict(status='unavailable', error=None, pid=pid, port=None, sockets=[])
    try:
        deadline = time.monotonic() + 2 if deadline is None else deadline
        require(time.monotonic() < deadline, 'socket diagnostic deadline expired')
        proc = Path(f'/proc/{pid}')
        identity = process_identity(proc)
        result.update(identity)
        result['state'] = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()[0]
        result['command'] = (proc / 'cmdline').read_bytes().decode(errors='replace').split('\0')
        require(identity['netns'] == os.readlink('/proc/self/ns/net'), 'different network namespace')
        owned = owned_inodes(proc)
        result['owned_inodes'] = owned
        tables = result['tables'] = {}
        for filename, family in [('udp', socket.AF_INET), ('udp6', socket.AF_INET6)]:
            path = proc / 'net' / filename
            if filename == 'udp6' and not path.exists() and not socket.has_ipv6:
                continue
            table = tables[filename] = path.read_text()
            rows = parse_udp(table, family)
            queues = {int(f[9]): tuple(int(v, 16) for v in f[4].split(':'))
                      for f in (line.split() for line in table.splitlines()[1:])}
            for inode, row in rows.items():
                if inode in owned:
                    tx, rx = queues[inode]
                    result['sockets'].append(dict(row, fds=owned[inode], tx_queue=tx, rx_queue=rx))
        require(result['sockets'], 'no owned UDP sockets remain')
        diagnostics = socket_diagnostics({s['family'] for s in result['sockets']}, deadline=deadline)
        for row in result['sockets']:
            diag = diagnostics[row['inode']]
            require(all(row[k] == diag[k] for k in ('family', 'port'))
                    and row['drops'] == diag['diag_drops'], 'UDP socket changed during snapshot')
            row.update(diag)
        after_owned = owned_inodes(proc)
        require(all(after_owned.get(s['inode']) == s['fds'] for s in result['sockets']),
                'socket ownership changed during snapshot')
        require(process_identity(proc) == identity, 'process identity changed during snapshot')
        result['status'] = 'available'
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    return result


def namespace_at(counters, netns):
    return dict(status='available' if counters is not None and netns is not None else 'unavailable',
                error=None if counters is not None and netns is not None else 'no counter baseline',
                netns=netns, counters=counters)


def capture(server_pid, workers, state):
    deadline = time.monotonic() + 5
    namespace = observe(namespace_snapshot)
    server = observe(process_snapshot, server_pid, deadline)
    peers = []
    for index, worker in enumerate(workers):
        process = worker['process']
        sockets = observe(process_snapshot, process.pid, deadline)
        peers.append(dict(index=index, pid=process.pid, command=worker['command'],
                          exit_code=process.poll(), sockets=sockets,
                          socket_baseline=worker.get('socket_baseline'),
                          socket_delta=observe(process_delta, worker.get('socket_baseline'), sockets),
                          report=worker.get('report'),
                          report_line_hex=worker.get('report_line', b'').hex(),
                          partial_stdout_hex=worker['buffer'].hex(),
                          stdout=f'worker-{index}.jsonl', stderr=f'worker-{index}.stderr'))
    return dict(schema=1, timing_evidence=False, observed_monotonic=time.monotonic(),
                phase=state['phase'], stage=state['stage'],
                namespace_before=state['namespace_before'], namespace_failure=namespace,
                namespace_delta=namespace_delta(state['namespace_before'], namespace),
                last_success=state['last_success'],
                namespace_since_last_success=namespace_delta(
                    state['last_success']['namespace'] if state['last_success'] else {}, namespace),
                server=server, server_baseline=state['server_baseline'],
                server_delta=observe(process_delta, state['server_baseline'], server), workers=peers)


def write_failure(output, name, error, capture):
    """Never replace the triggering exception, even if diagnostics cannot be saved."""
    original = ''.join(traceback.format_exception(error))
    failures = []
    try:
        evidence = capture()
    except BaseException as diagnostic:
        evidence = dict(status='unavailable', error=f'{type(diagnostic).__name__}: {diagnostic}')
        failures.append(evidence['error'])
    try:
        evidence.update(original_error=dict(type=type(error).__name__, message=str(error),
                                            traceback=original))
        encoded = json.dumps(evidence, indent=2) + '\n'
    except BaseException as diagnostic:
        failures.append(f'encoding: {type(diagnostic).__name__}: {diagnostic}')
        encoded = json.dumps(dict(status='unavailable', diagnostic_errors=failures,
                                  original_traceback=original)) + '\n'
    for suffix, text in [('json', encoded), ('txt', original)]:
        try:
            with (output / f'{name}.{suffix}').open('x') as file:
                file.write(text)
        except BaseException as diagnostic:
            failures.append(f'{name}.{suffix}: {type(diagnostic).__name__}: {diagnostic}')
    if failures:
        message = 'Failure diagnostics incomplete: ' + '; '.join(failures)
        error.add_note(message)
        try:
            print(message, file=sys.stderr, flush=True)
        except BaseException:
            pass


def cleanup(workers):
    """Kill before draining, reap every child, and keep errors from skipping siblings."""
    errors = []
    for worker in workers:
        process = worker['process']
        for action in (lambda: process.kill() if process.poll() is None else None,
                       lambda: process.wait(timeout=5)):
            try:
                action()
            except Exception as error:
                errors.append(f'{process.pid}: {error}')
        try:
            # Nonblocking and bounded even if a faulty child left a pipe writer behind.
            os.set_blocking(process.stdout.fileno(), False)
            for _ in range(16):
                try:
                    chunk = os.read(process.stdout.fileno(), 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                worker['stdout'].write(chunk)
            else:
                errors.append(f'{process.pid}: trailing stdout exceeded 1 MiB')
            worker['stdout'].flush()
        except Exception as error:
            errors.append(f'{process.pid}: retaining stdout: {error}')
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except Exception as error:
                errors.append(f'{process.pid}: closing pipe: {error}')
    return errors
