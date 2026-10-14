#!/usr/bin/env python3
"""Run unchanged independent asyncio fixtures with real UDP_SEGMENT sends.

Only the socket transport is wrapped. QUIC encryption, loss injection, qlogs,
credit assertions and response checks stay in the independent fixture.
Linux CPython selector transport is required; fail closed on send errors.
This is a correctness/coverage harness, never a throughput measurement.
"""
import asyncio.selector_events
from collections import Counter
import json
from pathlib import Path
import runpy
import socket
import struct
import sys

cls = asyncio.selector_events._SelectorDatagramTransport
original_send = cls.sendto
original_close = cls.close
stats = Counter()
failures = []
live = set()


def flush(transport):
    pending = transport._c113_pending
    transport._c113_pending = []
    live.discard(transport)
    try:
        index = 0
        while index < len(pending):
            data, addr = pending[index]
            group = [data]
            total = size = len(data)
            end = index + 1
            while size and end < len(pending) and len(group) < 64:
                following, destination = pending[end]
                if destination != addr or not following or len(following) > size or total + len(following) > 65507:
                    break
                group.append(following)
                end += 1
                total += len(following)
                if len(following) < size:
                    break
            stats['datagrams'] += len(group)
            stats['bytes'] += total
            if len(group) == 1:
                original_send(transport, data, addr)
                stats['plain_messages'] += 1
            else:
                assert not transport._buffer, 'do not reorder buffered UDP writes'
                # The kernel segments these iovecs into the original datagrams.
                joined = b''.join(group)
                assert [joined[i:i+size] for i in range(0,len(joined),size)] == group
                control = [(socket.IPPROTO_UDP, 103, struct.pack('=H', size))]
                if transport._extra['peername']:
                    sent = transport._sock.sendmsg(group, control)
                else:
                    sent = transport._sock.sendmsg(group, control, 0, addr)
                assert sent == total, (sent, total)
                stats['gso_messages'] += 1
                stats['gso_datagrams'] += len(group)
                stats['short_tails'] += len(group[-1]) != size
            index = end
    except BaseException as error:
        failures.append(repr(error))
        raise


def sendto(transport, data, addr=None):
    if not hasattr(transport, '_c113_pending'):
        transport._c113_pending = []
    if not transport._c113_pending:
        transport._loop.call_soon(flush, transport)
    transport._c113_pending.append((bytes(data), addr))
    live.add(transport)
    if len(transport._c113_pending) == 64:
        flush(transport)


def close(transport):
    if getattr(transport, '_c113_pending', None):
        flush(transport)
    return original_close(transport)


cls.sendto = sendto
cls.close = close
fixture = Path(sys.argv[1]).resolve()
sys.argv = sys.argv[1:]
sys.path.insert(0, str(fixture.parent))
try:
    runpy.run_path(str(fixture), run_name='__main__')
except SystemExit as error:
    assert error.code in (None, 0), error.code
assert not live, f'{len(live)} transports have unsent data'
assert not failures, failures
assert stats['gso_messages'] > 0, stats
print('GSO_TRANSPORT ' + json.dumps(stats, sort_keys=True), flush=True)
