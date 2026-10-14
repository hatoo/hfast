#!/usr/bin/env python3
"""Mixed H1/H2 classification, queued input, and exact replies through half-close.

All sockets first send the shared PRI prefix and wait until the server consumes
it. The remainder exceeds one receive chunk. Independent hyper-h2 validates H2
frames and stream completion; literal bytes validate H1. No timing claims.
"""
import argparse
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

import h2.config
import h2.connection
import h2.events

RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 13\r\n\r\nHello, World!")
REQUEST = b"GET /mixed HTTP/1.1\r\nHost: localhost\r\n\r\n"
COUNT = 601


def queued(port):
    queues = {}
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[1].split(':')[1], 16) == port and fields[3] == '01':
            queues[int(fields[2].split(':')[1], 16)] = int(fields[4].split(':')[1], 16)
    return queues


def check(port):
    peers = []
    try:
        for i in range(34):
            sock = socket.create_connection(('127.0.0.1', port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client = None
            if i % 2:
                client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
                client.initiate_connection()
                wire = client.data_to_send()
                for stream in range(1, COUNT * 2, 2):
                    headers = [(b':method', b'GET'), (b':scheme', b'http'),
                               (b':authority', b'localhost'), (b':path', b'/mixed')]
                    if stream == 1:
                        headers.append((b'x-large', b'!' * 20000))
                    client.send_headers(stream, headers, end_stream=True)
                wire += client.data_to_send()
            else:
                wire = b'PRINT /mixed HTTP/1.1\r\nHost: localhost\r\n\r\n' + REQUEST * (COUNT - 1)
            assert wire.startswith(b'PRI') and len(wire) > 16384
            peers.append(dict(sock=sock, client=client, wire=wire, bytes=bytearray(),
                              headers=set(), bodies={}, ended=set(), eof=False))
        for p in peers:
            p['sock'].sendall(b'PRI')
        deadline = time.monotonic() + 10
        while True:
            sizes = queued(port)
            if all(sizes.get(p['sock'].getsockname()[1], -1) == 0 for p in peers):
                break
            assert time.monotonic() < deadline, ('shared prefix not consumed', sizes)
            time.sleep(.001)
        assert not select.select([p['sock'] for p in peers], [], [], 0)[0], 'undecided prefix produced output'
        for p in peers:
            p['sock'].sendall(p['wire'][3:])
            p['sock'].shutdown(socket.SHUT_WR)
            p['sock'].setblocking(False)
        deadline = time.monotonic() + 15
        while not all(p['eof'] for p in peers):
            ready, _, _ = select.select([p['sock'] for p in peers if not p['eof']], [], [], .05)
            for p in peers:
                if p['sock'] not in ready:
                    continue
                data = p['sock'].recv(65536)
                if not data:
                    p['eof'] = True
                    if p['client']:
                        wanted = set(range(1, COUNT * 2, 2))
                        assert p['headers'] == p['ended'] == set(p['bodies']) == wanted
                        assert all(bytes(b) == b'Hello, World!' for b in p['bodies'].values())
                    else:
                        assert p['bytes'] == RESPONSE * COUNT
                    continue
                p['bytes'].extend(data)
                if p['client']:
                    for event in p['client'].receive_data(data):
                        if isinstance(event, h2.events.ResponseReceived):
                            assert event.stream_id not in p['headers']
                            assert dict(event.headers) == {b':status': b'200', b'content-type': b'text/plain', b'content-length': b'13'}
                            p['headers'].add(event.stream_id)
                            p['bodies'][event.stream_id] = bytearray()
                        elif isinstance(event, h2.events.DataReceived):
                            assert event.stream_id in p['headers'] and event.stream_id not in p['ended']
                            p['bodies'][event.stream_id].extend(event.data)
                        elif isinstance(event, h2.events.StreamEnded):
                            assert event.stream_id not in p['ended']
                            p['ended'].add(event.stream_id)
                        else:
                            assert isinstance(event, (h2.events.RemoteSettingsChanged, h2.events.SettingsAcknowledged)), event
                else:
                    assert len(p['bytes']) <= len(RESPONSE) * COUNT
            assert time.monotonic() < deadline, 'mixed receive progress deadline'
        return dict(connections=len(peers), h1_responses=17*COUNT, h2_responses=17*COUNT,
                    sent_bytes=sum(len(p['wire']) for p in peers), received_bytes=sum(len(p['bytes']) for p in peers),
                    clean_eofs=len(peers), unexpected_errors=0)
    finally:
        for p in peers:
            p['sock'].close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--threads', type=int, choices=[1, 2], default=1)
    args = parser.parse_args()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    with tempfile.TemporaryFile(mode='w+') as log:
        server = subprocess.Popen([str(args.binary.resolve()), '--tcp', str(port), '--quic', '0',
                                   '--threads', str(args.threads)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline
                    time.sleep(.01)
            print(json.dumps(check(port), indent=2))
            assert server.poll() is None
        finally:
            server.terminate()
            server.wait(timeout=5)
            if server.returncode not in [-15, 0]:
                log.seek(0)
                print(log.read())


if __name__ == '__main__':
    main()
