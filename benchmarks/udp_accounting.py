"""Untimed Linux UDP evidence. Missing/changed evidence is never zero loss.

Match process-owned /proc UDP inodes, then SOCK_DIAG cookies and SKMEMINFO.
The latter reports the actual SO_RCVBUF without duplicating another process's
file descriptors or changing its sockets. See sock_diag(7) and Linux UAPI
inet_diag.h/sock_diag.h. Snapshots are not atomic; disagreeing reads fail closed.
"""
import os
from pathlib import Path
import socket
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_udp(text, family):
    lines = text.splitlines()
    require(lines and 'inode' in lines[0].split() and 'drops' in lines[0].split(),
            'missing UDP table header')
    rows = {}
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) == 13, 'malformed UDP row')
        inode, drops = int(fields[9]), int(fields[12])
        require(inode >= 0 and 0 <= drops <= 0xffffffff, 'invalid UDP counter')
        for endpoint in fields[1:3]:
            address, port = endpoint.split(':')
            require(len(address) == (8 if family == socket.AF_INET else 32)
                    and len(port) == 4, 'invalid UDP address')
            int(address, 16)
            int(port, 16)
        if inode == 0:  # No process can own this unreferenced socket.
            continue
        require(inode not in rows, 'duplicate UDP inode')
        rows[inode] = dict(inode=inode, family=family, local=fields[1], remote=fields[2],
                           port=int(fields[1].split(':')[1], 16), drops=drops)
    return rows


def parse_diag(payload):
    require(len(payload) >= 72, 'short inet_diag_msg')
    family = payload[0]
    require(family in (socket.AF_INET, socket.AF_INET6), 'wrong diagnostic family')
    inode = struct.unpack_from('=I', payload, 68)[0]
    cookie = list(struct.unpack_from('=II', payload, 44))
    require(cookie != [0xffffffff, 0xffffffff], 'socket identity cookie unavailable')
    memory = None
    offset = 72
    while offset < len(payload):
        require(len(payload) - offset >= 4, 'short diagnostic attribute')
        length, kind = struct.unpack_from('=HH', payload, offset)
        require(4 <= length <= len(payload) - offset, 'invalid diagnostic attribute')
        if kind == 7:  # INET_DIAG_SKMEMINFO
            require(memory is None and length >= 40 and (length - 4) % 4 == 0,
                    'missing/duplicate/short socket memory information')
            memory = struct.unpack_from('=9I', payload, offset + 4)
        offset += (length + 3) & ~3
    require(memory is not None and memory[1] > 0, 'receive capacity unavailable')
    return dict(inode=inode, family=family, port=struct.unpack_from('!H', payload, 4)[0],
                cookie=cookie, rcvbuf=memory[1], diag_drops=memory[8])


def diag_messages(data, seq):
    """Validate one complete netlink datagram, including dump/error flags."""
    rows, done = [], False
    while data:
        require(len(data) >= 16 and not done, 'short/trailing netlink message')
        length, kind, flags, actual_seq, _pid = struct.unpack_from('=IHHII', data)
        require(16 <= length <= len(data) and actual_seq == seq, 'invalid netlink header')
        require(not flags & 0x10, 'interrupted socket diagnostic dump')
        payload = data[16:length]
        if kind in (2, 3):  # NLMSG_ERROR / NLMSG_DONE
            require(len(payload) >= 4, 'missing netlink status')
            status = struct.unpack_from('=i', payload)[0]
            require(status == 0, f'socket diagnostic error {status}')
            done = kind == 3
        else:
            require(kind == 20, f'unexpected netlink message {kind}')
            rows.append(parse_diag(payload))
        data = data[(length + 3) & ~3:]
    return rows, done


def socket_diagnostics(families):
    rows = {}
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as netlink:
        netlink.settimeout(2)
        for seq, family in enumerate(sorted(families), 1):
            request = (struct.pack('=BBBBI', family, socket.IPPROTO_UDP, 1 << 6, 0, 0xffffffff)
                       + bytes(40) + struct.pack('=II', 0xffffffff, 0xffffffff))
            header = struct.pack('=IHHII', 16 + len(request), 20, 0x301, seq, 0)
            netlink.sendto(header + request, (0, 0))
            done = False
            while not done:
                data, _, flags, sender = netlink.recvmsg(1 << 20)
                require(sender[0] == 0 and not flags & socket.MSG_TRUNC,
                        'untrusted/truncated socket diagnostic dump')
                batch, done = diag_messages(data, seq)
                for row in batch:
                    require(row['family'] == family, 'wrong diagnostic response family')
                    if row['inode']:
                        require(row['inode'] not in rows, 'duplicate diagnostic inode')
                        rows[row['inode']] = row
    return rows


def owned_inodes(proc):
    result = {}
    for fd in (proc / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:  # An unrelated FD may close during enumeration.
            continue
        if target.startswith('socket:[') and target.endswith(']'):
            result.setdefault(int(target[8:-1]), []).append(int(fd.name))
    return {inode: sorted(fds) for inode, fds in result.items()}


def process_identity(proc):
    stat = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
    return dict(start_ticks=int(stat[19]), netns=os.readlink(proc / 'ns/net'))


def process_snapshot(pid, port, workers):
    result = dict(status='unavailable', error=None, pid=pid, port=port, sockets=[])
    try:
        proc = Path(f'/proc/{pid}')
        identity = process_identity(proc)
        result.update(identity)
        require(identity['netns'] == os.readlink('/proc/self/ns/net'), 'different network namespace')
        owned = owned_inodes(proc)
        selected = {}
        for filename, family in [('udp', socket.AF_INET), ('udp6', socket.AF_INET6)]:
            path = proc / 'net' / filename
            if filename == 'udp6' and not path.exists() and not socket.has_ipv6:
                continue
            for inode, row in parse_udp(path.read_text(), family).items():
                if inode in owned and row['port'] == port:
                    require(inode not in selected, 'inode appears in both UDP tables')
                    selected[inode] = dict(row, fds=owned[inode])
        result['sockets'] = [selected[k] for k in sorted(selected)]
        require(len(selected) == workers and workers > 0, 'worker UDP socket count mismatch')
        diagnostics = socket_diagnostics({s['family'] for s in selected.values()})
        for inode, row in selected.items():
            require(inode in diagnostics, 'socket disappeared from diagnostics')
            diag = diagnostics[inode]
            require((row['family'], row['port'], row['drops']) ==
                    (diag['family'], diag['port'], diag['diag_drops']),
                    'UDP/diagnostic identity or drop counter changed during snapshot')
            row.update(diag)
        after_owned = owned_inodes(proc)
        require(all(after_owned.get(k) == owned[k] for k in selected), 'socket ownership changed')
        require(process_identity(proc) == identity, 'process identity changed')
        result['status'] = 'available'
    except (OSError, ValueError, IndexError, struct.error) as error:
        result['error'] = f'{type(error).__name__}: {error}'
    return result


def process_delta(before, after):
    result = dict(status='unavailable', error=None, drops=None, sockets=[])
    try:
        require(before['status'] == after['status'] == 'available', 'socket snapshot unavailable')
        require(all(before[k] == after[k] for k in ('pid', 'start_ticks', 'netns', 'port')),
                'process or namespace changed')
        old = {s['inode']: s for s in before['sockets']}
        new = {s['inode']: s for s in after['sockets']}
        require(len(old) == len(before['sockets']) and len(new) == len(after['sockets'])
                and old.keys() == new.keys() and old, 'socket set changed/duplicated')
        for inode in sorted(old):
            a, b = old[inode], new[inode]
            require(all(a[k] == b[k] for k in ('cookie', 'fds', 'family', 'local', 'remote', 'rcvbuf')),
                    'socket identity or receive capacity changed')
            require(b['drops'] >= a['drops'], 'socket counter reset/wrapped')
            result['sockets'].append(dict(inode=inode, cookie=b['cookie'], rcvbuf=b['rcvbuf'],
                                          drops=b['drops'] - a['drops']))
        result.update(status='available', drops=sum(s['drops'] for s in result['sockets']))
    except (KeyError, ValueError, TypeError) as error:
        result['error'] = str(error)
    return result


def namespace_snapshot():
    result = dict(status='unavailable', error=None, counters={})
    try:
        result['netns'] = os.readlink('/proc/self/ns/net')
        rows = [line.split()[1:] for line in Path('/proc/net/snmp').read_text().splitlines()
                if line.startswith('Udp:')]
        require(len(rows) == 2 and len(rows[0]) == len(rows[1]), 'invalid UDP SNMP table')
        result['counters'] = dict(zip(rows[0], map(int, rows[1])))
        require(len(result['counters']) == len(rows[0])
                and all(v >= 0 for v in result['counters'].values()), 'invalid UDP SNMP values')
        require(all(k in result['counters'] for k in ('InErrors', 'RcvbufErrors', 'SndbufErrors',
                                                     'NoPorts', 'InDatagrams', 'OutDatagrams')),
                'missing UDP SNMP counters')
        result['status'] = 'available'
    except (OSError, ValueError) as error:
        result['error'] = str(error)
    return result


def namespace_delta(before, after):
    result = dict(status='unavailable', error=None, counters=None)
    try:
        require(before['status'] == after['status'] == 'available', 'namespace counters unavailable')
        require(before['netns'] == after['netns'], 'network namespace changed')
        a, b = before['counters'], after['counters']
        require(a.keys() == b.keys() and all(b[k] >= a[k] for k in a), 'UDP counters changed/reset')
        result.update(status='available', counters={k: b[k] - a[k] for k in a})
    except (KeyError, ValueError, TypeError) as error:
        result['error'] = str(error)
    return result


def require_clean_peer(udp):
    require(udp['status'] == 'available' and udp['drops'] == 0,
            f'peer UDP loss evidence not clean: {udp}')


def require_clean_run(peer_udp, server_delta, net_delta):
    require_clean_peer(peer_udp)
    require(server_delta['status'] == 'available' and server_delta['drops'] == 0,
            f'server UDP loss evidence not clean: {server_delta}')
    require(net_delta['status'] == 'available', f'namespace evidence unavailable: {net_delta}')
    unexpected = {k: v for k, v in net_delta['counters'].items()
                  if k not in ('InDatagrams', 'OutDatagrams') and v != 0}
    require(not unexpected, f'unexpected namespace UDP counters: {unexpected}')
