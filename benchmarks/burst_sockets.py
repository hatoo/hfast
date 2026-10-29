"""Strict, untimed socket identities for native multi-worker capacity references.

Every owned UDP socket and every namespace socket on its ports must match. A
shared port is allowed only for the explicitly declared server socket set.
"""
from collections import Counter
import os
from pathlib import Path
import socket

import burst_failure as failure


FAMILIES = (('udp', socket.AF_INET), ('udp6', socket.AF_INET6))


def table_rows(tables):
    rows = {}
    for name, family in FAMILIES:
        if name == 'udp6' and name not in tables and not socket.has_ipv6:
            continue
        parsed = failure.parse_udp(tables[name], family)
        for line in tables[name].splitlines()[1:]:
            fields = line.split()
            inode = int(fields[9])
            if inode == 0:
                continue
            failure.require(inode not in rows, 'duplicate socket inode across UDP tables')
            tx, rx = (int(v, 16) for v in fields[4].split(':'))
            rows[inode] = dict(parsed[inode], tx_queue=tx, rx_queue=rx)
    return rows


def validate(snapshot, ports, before=None):
    """Validate a complete process snapshot, retaining the independent raw tables."""
    failure.require(snapshot['status'] == 'available',
                    snapshot.get('error') or 'socket snapshot unavailable')
    sockets = snapshot['sockets']
    failure.require(Counter(s['port'] for s in sockets) == Counter(ports),
                    'owned UDP socket count/port mismatch')
    inodes = {s['inode'] for s in sockets}
    cookies = {tuple(s['cookie']) for s in sockets}
    failure.require(len(inodes) == len(cookies) == len(ports) > 0,
                    'duplicate socket inode/cookie')
    rows = table_rows(snapshot['tables'])
    selected = {inode for inode, row in rows.items() if row['port'] in ports}
    failure.require(selected == inodes, 'foreign/missing socket on an audited UDP port')
    for s in sockets:
        failure.require(s['inode'] > 0 and len(s['cookie']) == 2
                        and s['cookie'] != [0xffffffff, 0xffffffff], 'invalid socket identity')
        failure.require(snapshot['owned_inodes'].get(s['inode']) == s['fds'] and s['fds'],
                        'socket ownership mismatch')
        failure.require(type(s['rcvbuf']) is int and s['rcvbuf'] > 0,
                        'invalid receive capacity')
        failure.require(all(s[k] == rows[s['inode']][k]
                            for k in ('family', 'port', 'local', 'remote', 'drops',
                                      'tx_queue', 'rx_queue')), 'socket/table mismatch')
        failure.require(s['drops'] == s['diag_drops'] == s['tx_queue'] == s['rx_queue'] == 0,
                        'queued/dropped datagram on an owned socket')
    delta = failure.process_delta(before or snapshot, snapshot)
    failure.require(delta['status'] == 'available' and delta['drops'] == 0,
                    delta.get('error') or 'socket loss/unavailable delta')
    return delta


def observe(pid, ports, before=None):
    result = dict(status='unavailable', error=None, pid=pid, ports=ports,
                  snapshot=failure.observe(failure.process_snapshot, pid), delta=None)
    try:
        snap = result['snapshot']
        delta = validate(snap, ports, before)
        proc = Path(f'/proc/{pid}')
        # The failure collector checks existing sockets. Also reject additions,
        # replacement FDs and process reuse during this successful observation.
        result['ownership_after'] = failure.owned_inodes(proc)
        failure.require(result['ownership_after'] == snap['owned_inodes'],
                        'socket ownership changed during observation')
        failure.require(failure.process_identity(proc) ==
                        {k: snap[k] for k in ('start_ticks', 'netns')},
                        'process identity changed during observation')
        failure.require(snap['pid'] == pid and snap['netns'] == os.readlink('/proc/self/ns/net'),
                        'wrong process/namespace')
        result.update(status='available', delta=delta)
    except (OSError, KeyError, TypeError, ValueError) as error:
        result['error'] = f'{type(error).__name__}: {error}'
    return result


def capture(server_pid, port, server_workers, workers, reports, before=None):
    failure.require(len(workers) == len(reports), 'missing producer socket reports')
    failure.require(not before or len(before['producers']) in (0, len(workers)),
                    'producer socket population changed')
    server = observe(server_pid, [port] * server_workers,
                     before['server']['snapshot'] if before else None)
    peers = []
    for index, (worker, report) in enumerate(zip(workers, reports)):
        ports = [report[name]['port'] for name in ('active', 'quiet')]
        peers.append(observe(worker['process'].pid, ports,
                            before['producers'][index]['snapshot']
                            if before and before['producers'] else None))
    return dict(server=server, producers=peers)


def require_clean(audit):
    observations = [audit['server'], *audit['producers']]
    for row in observations:
        failure.require(row['status'] == 'available', row['error'] or 'socket audit unavailable')
    # Producer sockets may never share a port with each other or the server.
    port_sets = [set(row['ports']) for row in observations]
    failure.require(len(set.union(*port_sets)) == sum(map(len, port_sets)),
                    'shared producer/server UDP port')
    failure.require(all(len(row['ports']) == len(set(row['ports']))
                        for row in audit['producers']), 'shared producer UDP port')


def identities(audit):
    result = {}
    for row in [audit['server'], *audit['producers']]:
        for sock in row['snapshot']['sockets']:
            result.setdefault(sock['port'], set()).add(sock['inode'])
    return result


def empty(ports, expected):
    """Cheap final-settlement gate; detailed SOCK_DIAG reads remain untimed.

    Only the first warmup lacks producer inode baselines. Its producer ports still
    require exactly one socket each, then the complete audit establishes identities.
    """
    failure.require(len(ports) == len(set(ports)), 'duplicate socket port')
    tables = {name: Path('/proc/net', name).read_text() for name, _ in FAMILIES
              if name != 'udp6' or socket.has_ipv6 or Path('/proc/net/udp6').exists()}
    found = {}
    for inode, row in table_rows(tables).items():
        port = row['port']
        if port in ports:
            found.setdefault(port, set()).add(inode)
            failure.require(row['tx_queue'] == row['rx_queue'] == row['drops'] == 0,
                            f'queued/dropped datagram on {port}')
    failure.require(found.keys() == set(ports), 'missing audited sockets')
    for port, inodes in found.items():
        failure.require(inodes == expected[port] if port in expected else len(inodes) == 1,
                        f'changed/foreign/shared UDP socket on {port}')
