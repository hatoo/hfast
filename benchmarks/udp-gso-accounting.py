#!/usr/bin/env python3
"""Prove segment/message accounting for this host in an isolated net namespace."""
import json
import socket
import struct


def counters():
    with open('/proc/net/snmp') as source:
        rows = [line.split()[1:] for line in source if line.startswith('Udp: ')]
    return dict(zip(rows[0], map(int, rows[1])))


def check():
    rows = []
    for gro in (False, True):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(('127.0.0.1', 0))
            receiver.settimeout(1)
            receiver.setsockopt(socket.IPPROTO_UDP, 104, int(gro))
            sender.connect(receiver.getsockname())
            for lengths in [(100,), (100, 100, 100), (100, 100, 37), (100,) * 8, (1000,) * 64]:
                packets = [bytes([i + 1]) * length for i, length in enumerate(lengths)]
                before = counters()
                if len(packets) == 1:
                    assert sender.send(packets[0]) == len(packets[0])
                else:
                    assert sender.sendmsg(packets, [(socket.IPPROTO_UDP, 103, struct.pack('=H', lengths[0]))]) == sum(lengths)
                actual = []
                messages = 0
                while len(actual) < len(packets):
                    payload, ancillary, flags, address = receiver.recvmsg(65536, socket.CMSG_SPACE(4))
                    assert flags == 0 and address == sender.getsockname()
                    segment = None
                    for level, kind, data in ancillary:
                        assert level == socket.IPPROTO_UDP and kind == 104 and len(data) == 4
                        segment, = struct.unpack('=i', data)
                    if segment is None:
                        actual.append(payload)
                    else:
                        assert gro and segment == lengths[0]
                        actual.extend(payload[i:i+segment] for i in range(0, len(payload), segment))
                    messages += 1
                assert actual == packets
                assert messages == (1 if gro else len(packets))
                after = counters()
                delta = {key: after[key] - before[key] for key in before}
                assert delta['InDatagrams'] == messages, delta
                assert delta['OutDatagrams'] == 1, delta
                assert all(value == 0 for key, value in delta.items()
                           if key not in ('InDatagrams', 'OutDatagrams')), delta
                rows.append(dict(gro=gro, lengths=lengths, messages=messages, datagrams=len(packets), delta=delta))
            receiver.setblocking(False)
            try:
                receiver.recv(65536)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('unexpected extra datagram')
    return rows


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
