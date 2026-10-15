#!/usr/bin/env python3
"""Independently decode native CRYPTO bytes, ranges and packet numbers with aioquic.

Untimed only. Uses pinned aioquic internals from interop-requirements.txt.
"""
import argparse
import asyncio
import datetime
import json
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import crypto_churn as c

RESPONSE = b'\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!'


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.trace = self._quic._quic_logger
        self.crypto = {'INITIAL': [], 'HANDSHAKE': []}
        self.tls_done = False
        self.responses = 0
        self.drop_response = False
        self.closed_by_peer = False
        handlers = self._quic._QuicConnection__frame_handlers
        crypto, epochs = handlers[6]

        def record(context, frame_type, buf):
            pos = buf.tell()
            start = buf.pull_uint_var()
            length = buf.pull_uint_var()
            data = buf.pull_bytes(length)
            self.crypto[context.epoch.name].append(dict(start=start, stop=start + length, data=data))
            buf.seek(pos)
            return crypto(context, frame_type, buf)

        handlers[6] = (record, epochs)
        close, epochs = handlers[0x1d]

        def closed(context, frame_type, buf):
            self.closed_by_peer = True
            return close(context, frame_type, buf)

        handlers[0x1d] = (closed, epochs)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            c.require(event.alpn_protocol == 'h3' and not event.session_resumed, 'wrong TLS handshake')
            self.tls_done = True
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                c.require(self.tls_done and http_event.stream_id == 0 and http_event.stream_ended,
                          'wrong/incomplete native request')
                c.require(dict(http_event.headers) == {
                    b':method': b'GET', b':scheme': b'https',
                    b':authority': b'localhost', b':path': b'/'}, 'wrong request headers')
                if not self.drop_response:
                    self._quic.send_stream_data(0, RESPONSE, end_stream=True)
                    self.responses += 1

    def verify(self, mode, expected=None):
        c.require(self.tls_done and self.responses == 1 and self.closed_by_peer,
                  'TLS/HTTP/close not independently completed')
        events = self.trace.to_dict()['events']
        pns = {'initial': [], 'handshake': []}
        for event in events:
            if event['name'] == 'transport:packet_received':
                packet = event['data']
                for frame in packet['frames']:
                    if frame['frame_type'] == 'crypto':
                        pns[packet['header']['packet_type']].append(packet['header']['packet_number'])
        result = {}
        for i, epoch in enumerate(('INITIAL', 'HANDSHAKE')):
            frames = self.crypto[epoch]
            size = max(f['stop'] for f in frames)
            c.require([[f['start'], f['stop']] for f in frames] == c.schedule(mode, size),
                      'independent wire ranges differ')
            packet_numbers = pns[epoch.lower()]
            c.require(len(packet_numbers) == len(frames)
                      and packet_numbers == sorted(set(packet_numbers)), 'wire packet replay')
            reconstructed = [None] * size
            for frame in frames:
                for offset, byte in enumerate(frame['data'], frame['start']):
                    c.require(reconstructed[offset] in (None, byte), 'altered overlap bytes')
                    reconstructed[offset] = byte
            c.require(None not in reconstructed, 'missing wire TLS bytes')
            if expected is not None:
                plan = expected[i]
                c.require(bytes(reconstructed).hex() == plan['original_hex'], 'altered native TLS bytes')
                c.require(packet_numbers == [f['packet'] for f in plan['sent']], 'wrong native packet audit')
            result[epoch] = dict(bytes=size, frames=len(frames), packet_numbers=packet_numbers)
        return result


async def check(peer, output, configuration, mode):
    protocols = []

    def factory(*args, **kwargs):
        protocol = Server(*args, **kwargs)
        protocols.append(protocol)
        return protocol

    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    process = await asyncio.create_subprocess_exec(str(peer), str(port), mode, '2', '1',
                                                  stdin=asyncio.subprocess.PIPE,
                                                  stdout=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE)
    rows = []
    try:
        for phase, reply in [('ready', b'start\n'), ('done', b'validate\n'), ('validated', b'exit\n')]:
            line = await asyncio.wait_for(process.stdout.readline(), 15)
            c.require(line, 'native peer exited')
            row = json.loads(line)
            rows.append(row)
            c.require(row['phase'] == phase, f'native interop failed: {row}')
            if phase == 'done':
                c.validate_done(row, mode, 2)
            process.stdin.write(reply)
            await process.stdin.drain()
        c.require(await asyncio.wait_for(process.wait(), 5) == 0, 'native peer exit failure')
        await asyncio.sleep(.05)
        c.require(len(protocols) == 4, 'wrong connection lifecycle count')
        verified = [p.verify(mode, rows[1]['epochs'] if i == 1 else None)
                    for i, p in enumerate(protocols)]
        return dict(mode=mode, connections=4, responses=4, verified=verified, peer=rows)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        (output / f'{mode}.stderr').open('xb').write(await process.stderr.read())
        (output / f'{mode}.peer.json').open('x').write(json.dumps(rows, indent=2) + '\n')
        server.close()


async def missing_response(peer, output, configuration):
    protocols = []

    def factory(*args, **kwargs):
        protocol = Server(*args, **kwargs)
        protocol.drop_response = len(protocols) == 2
        protocols.append(protocol)
        return protocol

    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    process = await asyncio.create_subprocess_exec(str(peer), str(port), 'normal', '2', '1',
                                                  stdin=asyncio.subprocess.PIPE,
                                                  stdout=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE)
    rows = []
    try:
        ready = json.loads(await asyncio.wait_for(process.stdout.readline(), 15))
        rows.append(ready)
        c.require(ready['phase'] == 'ready', 'negative fixture failed before measurement')
        process.stdin.write(b'start\n')
        await process.stdin.drain()
        row = json.loads(await asyncio.wait_for(process.stdout.readline(), 15))
        rows.append(row)
        expected = dict(phase='failed', work_phase='measured', offered=2, completed=1,
                        requests=2, responses=1, tls_completed=2, close_sent=1, failed=1)
        c.require(all(row[k] == v for k, v in expected.items()), 'incorrect partial failure counts')
        c.require(len(row['latencies_ns']) == 1 and row['latencies_ns'][0] > 0
                  and row['failed_latency_ns'] >= 5_000_000_000, 'lost latency evidence')
        c.require(await asyncio.wait_for(process.wait(), 5) == 1, 'missing response accepted')
        c.require(len(protocols) == 3 and all(p.tls_done for p in protocols)
                  and [p.responses for p in protocols] == [1, 1, 0], 'wrong fault injection')
        return dict(expected_failures=1, partial_report=row)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        (output / 'missing-response.stderr').open('xb').write(await process.stderr.read())
        (output / 'missing-response.peer.json').open('x').write(json.dumps(rows, indent=2) + '\n')
        server.close()


async def main(args):
    args.output.mkdir(parents=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    configuration = QuicConfiguration(is_client=False, alpn_protocols=['h3'],
                                      quic_logger=QuicLogger(), max_data=1 << 30,
                                      max_stream_data=1 << 20)
    configuration.certificate = certificate
    configuration.private_key = key
    results = []
    for mode in ('normal', 'reverse', 'overlap-duplicates'):
        results.append(await check(args.peer, args.output, configuration, mode))
    negative = await missing_response(args.peer, args.output, configuration)
    summary = dict(cases=results, connections=12, responses=12, errors=0, timing=False,
                   negative=negative)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(dict(connections=12, responses=12, errors=0, expected_failures=1)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    asyncio.run(main(parser.parse_args()))
