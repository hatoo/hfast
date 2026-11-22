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
from aioquic.buffer import Buffer
from aioquic.tls import Epoch
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
        self.empty_no_progress = {'INITIAL': 0, 'HANDSHAKE': 0}
        self.initial_datagram_sizes = []
        self.fault = None
        self.fault_epoch = Epoch.INITIAL
        self.fault_hits = 0
        handlers = self._quic._QuicConnection__frame_handlers
        crypto, epochs = handlers[6]

        def record(context, frame_type, buf):
            pos = buf.tell()
            start = buf.pull_uint_var()
            length = buf.pull_uint_var()
            data = buf.pull_bytes(length)
            end = buf.tell()
            if context.epoch == Epoch.INITIAL:
                c.require(self.datagram_size >= 1200, 'undersized Initial datagram')
                self.initial_datagram_sizes.append(self.datagram_size)
            self.crypto[context.epoch.name].append(dict(start=start, stop=start + length, data=data))
            buf.seek(pos)
            state = self._quic.tls.state
            if self.fault == 'missing-prefix' and context.epoch == self.fault_epoch and start == 0 and length:
                buf.seek(end)
                self.fault_hits += 1
                return
            if self.fault == 'corrupt-byte' and context.epoch == self.fault_epoch and start == 0 and length:
                bad = Buffer(capacity=length + 16)
                bad.push_uint_var(start)
                bad.push_uint_var(length)
                bad.push_bytes(bytes([data[0] ^ 0x80]) + data[1:])
                buf.seek(end)
                self.fault_hits += 1
                return crypto(context, frame_type, Buffer(data=bad.data))
            result = crypto(context, frame_type, buf)
            if not length:
                c.require(self._quic.tls.state == state, 'empty CRYPTO advanced TLS')
                self.empty_no_progress[context.epoch.name] += 1
            return result

        handlers[6] = (record, epochs)
        write_ack = self._quic._write_ack_frame

        def acknowledge(builder, space, now):
            if self.fault == 'missing-empty-ack' and space is self._quic._spaces[self.fault_epoch]:
                # Omit packet zero from every ACK, retaining the other packets.
                # The peer must stop before real TLS bytes, even with sparse ACKs.
                if 0 in space.ack_queue:
                    space.ack_queue.subtract(0, 1)
                    self.fault_hits += 1
                if not len(space.ack_queue):
                    space.ack_at = None
                    return
            return write_ack(builder, space, now)

        self._quic._write_ack_frame = acknowledge
        close, epochs = handlers[0x1d]

        def closed(context, frame_type, buf):
            self.closed_by_peer = True
            return close(context, frame_type, buf)

        handlers[0x1d] = (closed, epochs)

    def datagram_received(self, data, addr):
        self.datagram_size = len(data)
        return super().datagram_received(data, addr)

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

    def verify(self, mode, expected=None, empty_prefix=0):
        c.require(self.tls_done and self.responses == 1 and self.closed_by_peer,
                  'TLS/HTTP/close not independently completed')
        events = self.trace.to_dict()['events']
        pns = {'initial': [], 'handshake': []}
        empty_pns = {'initial': [], 'handshake': []}
        ack_ranges = {'initial': [], 'handshake': []}
        for event in events:
            if event['name'] == 'transport:packet_sent':
                packet = event['data']
                epoch = packet['header']['packet_type']
                for frame in packet['frames']:
                    if epoch in ack_ranges and frame['frame_type'] == 'ack':
                        ack_ranges[epoch].extend(frame['acked_ranges'])
            if event['name'] == 'transport:packet_received':
                packet = event['data']
                epoch = packet['header']['packet_type']
                for frame in packet['frames']:
                    if frame['frame_type'] == 'crypto':
                        pn = packet['header']['packet_number']
                        pns[epoch].append(pn)
                        if frame['length'] == 0:
                            empty_pns[epoch].append(pn)
                        else:
                            c.require(len(empty_pns[epoch]) == empty_prefix
                                      and all(any(a <= n <= b for a, b in ack_ranges[epoch])
                                              for n in empty_pns[epoch]),
                                      'real TLS bytes preceded the empty ACK fence')
        result = {}
        for i, epoch in enumerate(('INITIAL', 'HANDSHAKE')):
            frames = self.crypto[epoch]
            size = max(f['stop'] for f in frames)
            c.require([[f['start'], f['stop']] for f in frames] == c.schedule(mode, size, empty_prefix),
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
            c.require(self.empty_no_progress[epoch] == empty_prefix, 'wrong empty TLS progress count')
            if expected is not None:
                plan = expected[i]
                c.require(bytes(reconstructed).hex() == plan['original_hex'], 'altered native TLS bytes')
                c.require(packet_numbers == [f['packet'] for f in plan['sent']], 'wrong native packet audit')
            result[epoch] = dict(bytes=size, frames=len(frames), packet_numbers=packet_numbers,
                                 empty_no_progress=self.empty_no_progress[epoch],
                                 empty_acked=empty_pns[epoch.lower()],
                                 minimum_initial_datagram=min(self.initial_datagram_sizes))
        return result


async def check(peer, output, configuration, mode, empty_prefix=0):
    protocols = []

    def factory(*args, **kwargs):
        protocol = Server(*args, **kwargs)
        protocols.append(protocol)
        return protocol

    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    process = await asyncio.create_subprocess_exec(str(peer), str(port), mode, '2', '1', str(empty_prefix),
                                                  stdin=asyncio.subprocess.PIPE,
                                                  stdout=asyncio.subprocess.PIPE, limit=262144,
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
                c.validate_done(row, mode, 2, empty_prefix)
            process.stdin.write(reply)
            await process.stdin.drain()
        c.require(await asyncio.wait_for(process.wait(), 5) == 0, 'native peer exit failure')
        await asyncio.sleep(.05)
        c.require(len(protocols) == 4, 'wrong connection lifecycle count')
        verified = [p.verify(mode, rows[1]['epochs'] if i == 1 else None, empty_prefix)
                    for i, p in enumerate(protocols)]
        return dict(mode=mode, empty_prefix=empty_prefix, connections=4, responses=4, verified=verified, peer=rows)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        (output / f'{mode}-empty{empty_prefix}.stderr').open('xb').write(await process.stderr.read())
        (output / f'{mode}-empty{empty_prefix}.peer.json').open('x').write(json.dumps(rows, indent=2) + '\n')
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


async def crypto_fault(peer, output, configuration, fault, epoch):
    """Change one independent receiver after a completed measured connection."""
    protocols = []

    def factory(*args, **kwargs):
        protocol = Server(*args, **kwargs)
        if len(protocols) == 2:
            protocol.fault = fault
            protocol.fault_epoch = epoch
        protocols.append(protocol)
        return protocol

    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    process = await asyncio.create_subprocess_exec(
        str(peer), str(port), 'reverse', '2', '1', '32',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, limit=262144)
    rows = []
    stem = f'{fault}-{epoch.name.lower()}'
    try:
        ready = json.loads(await asyncio.wait_for(process.stdout.readline(), 15))
        rows.append(ready)
        c.require(ready['phase'] == 'ready', 'fault fixture failed during warmup')
        process.stdin.write(b'start\n')
        await process.stdin.drain()
        row = json.loads(await asyncio.wait_for(process.stdout.readline(), 15))
        rows.append(row)
        expected = dict(phase='failed', work_phase='measured', offered=2, completed=1,
                        requests=1, responses=1, tls_completed=1, close_sent=1, failed=1)
        c.require(all(row[k] == v for k, v in expected.items()), 'wrong CRYPTO fault accounting')
        c.require(len(row['latencies_ns']) == 1 and row['latencies_ns'][0] > 0
                  and row['failed_latency_ns'] > 0, 'fault lost latency samples')
        c.require(await asyncio.wait_for(process.wait(), 5) == 1, 'CRYPTO fault accepted')
        c.require(len(protocols) == 3 and protocols[-1].fault_hits > 0, 'CRYPTO fault not reached')
        p = protocols[-1]
        c.require(not p.tls_done and p.responses == 0, 'CRYPTO fault produced a success')
        if fault == 'missing-empty-ack':
            frames = p.crypto[epoch.name]
            c.require(len(frames) == 32 and all(not f['data'] for f in frames),
                      'missing ACK failed to fence real TLS data')
        else:
            c.require(p.empty_no_progress[epoch.name] == 32, 'missing empty-prefix exposure')
        return dict(fault=fault, epoch=epoch.name, fault_hits=p.fault_hits,
                    expected_failures=1, partial_report=row)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        (output / f'{stem}.stderr').open('xb').write(await process.stderr.read())
        (output / f'{stem}.peer.json').open('x').write(json.dumps(rows, indent=2) + '\n')
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
    if args.empty_prefixes:
        for mode in ('normal', 'reverse'):
            for empty_prefix in (1, 32, 512):
                results.append(await check(args.peer, args.output, configuration, mode, empty_prefix))
    negative = await missing_response(args.peer, args.output, configuration)
    faults = []
    if args.empty_prefixes:
        for epoch in (Epoch.INITIAL, Epoch.HANDSHAKE):
            for fault in ('missing-prefix', 'corrupt-byte', 'missing-empty-ack'):
                faults.append(await crypto_fault(args.peer, args.output, configuration, fault, epoch))
    total = sum(r['connections'] for r in results)
    summary = dict(cases=results, connections=total, responses=total, errors=0, timing=False,
                   negative=negative, crypto_faults=faults)
    (args.output / 'summary.json').open('x').write(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(dict(connections=total, responses=total, errors=0, expected_failures=1 + len(faults))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    parser.add_argument('--empty-prefixes', action='store_true')
    asyncio.run(main(parser.parse_args()))
