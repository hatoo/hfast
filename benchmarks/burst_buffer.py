"""Untimed server receive-capacity evidence shared by both burst controllers."""
import argparse

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


def observe(pid, port, requested):
    validate(requested)
    snapshot = failure.observe(failure.process_snapshot, pid)
    result = dict(requested_bytes=requested, effective_bytes=None,
                  below_doubled_request=None, status='unavailable', error=None,
                  snapshot=snapshot)
    try:
        failure.require(snapshot['status'] == 'available',
                        snapshot.get('error') or 'socket snapshot unavailable')
        sockets = snapshot['sockets']
        failure.require(len(sockets) == 1 and sockets[0]['port'] == port,
                        'expected one server UDP socket on the requested port')
        effective = sockets[0]['rcvbuf']
        failure.require(type(effective) is int and effective > 0, 'invalid receive capacity')
        result.update(status='available', effective_bytes=effective,
                      below_doubled_request=(effective < 2 * requested if requested else None))
    except (KeyError, TypeError, ValueError) as error:
        result['error'] = str(error)
    return result


def interval(before, after):
    result = dict(requested_bytes=before['requested_bytes'], effective_bytes=None,
                  below_doubled_request=None, status='unavailable', error=None,
                  before=before, after=after)
    delta = failure.observe(failure.process_delta, before['snapshot'], after['snapshot'])
    result['socket_delta'] = delta
    if (before['status'] == after['status'] == delta['status'] == 'available'
            and before['requested_bytes'] == after['requested_bytes']
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
