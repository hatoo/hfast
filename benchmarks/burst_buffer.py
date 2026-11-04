"""Untimed server receive-capacity evidence shared by both burst controllers."""
import argparse
import time

import burst_failure as failure


MAX_REQUEST = 4194304


def validate(value):
    if type(value) is not int or not 0 <= value <= MAX_REQUEST:
        raise ValueError(f'UDP receive buffer must be an integer in 0..{MAX_REQUEST}')
    return value


def argument(value):
    try:
        return validate(int(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def flags(requested):
    # Omit the default so historical binaries remain usable without this option.
    validate(requested)
    return ['--udp-receive-buffer', str(requested)] if requested else []


def observe(pid, port, requested, workers=1, deadline=None):
    validate(requested)
    failure.require(type(workers) is int and workers in (1, 2), 'expected one or two workers')
    snapshot = failure.observe(failure.process_snapshot, pid, deadline)
    result = dict(requested_bytes=requested, effective_bytes=None,
                  below_doubled_request=None, status='unavailable', error=None,
                  workers=workers, snapshot=snapshot)
    try:
        failure.require(snapshot['status'] == 'available',
                        snapshot.get('error') or 'socket snapshot unavailable')
        sockets = snapshot['sockets']
        failure.require(len(sockets) == workers and all(s['port'] == port for s in sockets),
                        'wrong number of server UDP sockets on the requested port')
        effective = sockets[0]['rcvbuf']
        failure.require(type(effective) is int and effective > 0, 'invalid receive capacity')
        failure.require(all(type(s['rcvbuf']) is int and s['rcvbuf'] == effective for s in sockets),
                        'server worker receive capacities differ')
        result.update(status='available', effective_bytes=effective,
                      below_doubled_request=(effective < 2 * requested if requested else None))
    except (KeyError, TypeError, ValueError) as error:
        result['error'] = str(error)
    return result


def wait_ready(process, port, requested, workers=1, timeout=5):
    """Wait before workload launch, without retrying lost measurement evidence.

    A GRO-denial wrapper may still be importing Python modules after a fixed
    startup sleep. Only absent sockets or an incomplete set of server workers
    are retryable. Keep every observation, process identity and any sockets
    already found; permission/diagnostic failures and replacements stay errors.
    """
    deadline = time.monotonic() + timeout
    history = []
    identity = None
    seen = {}
    while True:
        row = observe(process.pid, port, requested, workers, deadline=deadline)
        snapshot = row['snapshot']
        try:
            failure.require(process.poll() is None, 'server exited during startup')
            failure.require(all(k in snapshot for k in ('pid', 'start_ticks', 'netns')),
                            row.get('error') or 'startup process identity unavailable')
            current = tuple(snapshot[k] for k in ('pid', 'start_ticks', 'netns'))
            failure.require(identity is None or current == identity,
                            'server identity changed during startup')
            identity = current
            sockets = snapshot['sockets']
            by_inode = {s['inode']: s for s in sockets}
            for inode, prior in seen.items():
                current_socket = by_inode.get(inode, {})
                failure.require(all(current_socket.get(k) == prior[k] for k in
                    ('family', 'port', 'local', 'remote', 'fds', 'cookie', 'rcvbuf')),
                    'server socket changed during startup')
                failure.require(current_socket['drops'] >= prior['drops'],
                                'server socket drops decreased during startup')
            if row['status'] == 'available':
                failure.require(time.monotonic() < deadline, 'server UDP startup deadline expired')
                row['startup_observations'] = history
                return row
            absent = (snapshot.get('error') == 'ValueError: no owned UDP sockets remain'
                      and not sockets)
            partial = (snapshot['status'] == 'available' and 0 < len(sockets) < workers
                       and all(s['port'] == port for s in sockets))
            failure.require(absent or partial, row.get('error') or 'startup evidence unavailable')
            seen.update(by_inode)
            failure.require(time.monotonic() < deadline, 'server UDP startup deadline expired')
        except (KeyError, TypeError, ValueError) as error:
            row.update(status='unavailable', effective_bytes=None, below_doubled_request=None,
                       error=str(error), startup_observations=history)
            return row
        history.append(row)
        time.sleep(min(.01, max(0, deadline - time.monotonic())))


def interval(before, after):
    result = dict(requested_bytes=before['requested_bytes'], effective_bytes=None,
                  below_doubled_request=None, status='unavailable', error=None,
                  workers=before.get('workers', 1), before=before, after=after)
    delta = failure.observe(failure.process_delta, before['snapshot'], after['snapshot'])
    result['socket_delta'] = delta
    if (before['status'] == after['status'] == delta['status'] == 'available'
            and before['requested_bytes'] == after['requested_bytes']
            and before.get('workers', 1) == after.get('workers', 1)
            and before['effective_bytes'] == after['effective_bytes']):
        result.update(status='available', effective_bytes=after['effective_bytes'],
                      below_doubled_request=after['below_doubled_request'])
    else:
        result['error'] = (before['error'] or after['error'] or delta.get('error')
                           or 'receive capacity changed')
    return result


def require_equal(baseline, candidate):
    for row in (baseline, candidate):
        failure.require(row['status'] == 'available' and row['effective_bytes'] is not None,
                        'server receive capacity unavailable; comparison excluded')
    failure.require(all(baseline[key] == candidate[key]
                        for key in ('requested_bytes', 'effective_bytes')),
                    'server receive capacities differ; comparison excluded')
    failure.require(baseline.get('workers', 1) == candidate.get('workers', 1),
                    'server worker counts differ; comparison excluded')
