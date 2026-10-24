#!/usr/bin/env python3
"""Independent native upload wire/accounting checks and hostile server controls.

Requires the pinned aioquic from interop-requirements.txt. This is untimed.
"""
import argparse
import asyncio
import datetime
import json
from pathlib import Path
import socket
import subprocess

from aioquic.buffer import Buffer
from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.packet import pull_ack_frame
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

RESPONSE = b'\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def expand(ranges):
    return {pn for lo, hi in ranges for pn in range(lo, hi + 1)}


def validate(row, count, size):
    require(row['phase'] == 'done' and row['error'] is None, f'peer failed: {row.get("error")}')
    require(row['completed'] == count and len(row['streams']) == count, 'completion count')
    require(len(row['latencies_ns']) == count and all(x > 0 for x in row['latencies_ns']), 'all latencies')
    require(row['control_acked'], 'missing control ACK')
    for i, s in enumerate(row['streams']):
        require(s['id'] == 4 * i and s['sent'] == s['end'], 'wrong stream extent')
        require(s['body_acked'] == size and s['acked_ranges'] == [[0, s['end'] - 1]], 'missing upload ACK')
        require(s['fin_sent'] and s['fin_acked'] and s['response_fin'], 'missing FIN')
        require(s['response_ranges'] == [[0, len(RESPONSE) - 1]], 'incomplete response')
        require(s['latency_ns'] == row['latencies_ns'][i], 'latency mismatch')
    require(row['sent_data'] == 5 + sum(s['end'] for s in row['streams']), 'connection byte count')
    require(row['sent_data'] <= row['max_data'] and row['max_flights'] <= 64, 'flow/flight limit')
    seen = expand(row['received_ranges'])
    acked = expand(row['acked_packet_ranges'])
    suppressed = expand(row['suppressed_ack_only_ranges'])
    require(acked == seen - suppressed, 'omitted/invented packet ACK')
    if row['mode'] == 'sparse':
        require(row['max_ack_ranges'] >= 2 and len(row['credit_release_history']) == count and all(h[-1][1] >= 10 for h in row['credit_release_history']) and row['sparse_fence_acked'], 'sparse/retry schedule not reached')
        require(expand(row['withheld_credit_ranges']) <= acked, 'late credit ACK omitted')
    if row['mode'] == 'pto':
        require(row['pto_proven'], 'timer recovery during transmit silence not exercised')
    if row['mode'] in ('loss', 'reorder'):
        require(row['dropped_credit_packets'] == 2, 'loss schedule not reached')
    if row['mode'] == 'reorder':
        require(row['replayed'] and row['duplicate_packets'] >= 2, 'reorder/duplicate schedule not reached')


class Server(QuicConnectionProtocol):
    def __init__(self, *args, size, fault, failures, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.size, self.fault, self.failures = size, fault, failures
        self.tls_done = False
        self.headers = set()
        self.bodies = {}
        self.fins = set()
        self.acks = set()
        self.ack_frames = 0
        self.ack_max_ranges = 0
        self.responses = 0
        handlers = self._quic._QuicConnection__frame_handlers
        for kind in (2, 3):
            original, epochs = handlers[kind]

            def record(context, frame_type, buf, original=original):
                pos = buf.tell()
                ranges, _ = pull_ack_frame(buf)
                if context.epoch == tls.Epoch.ONE_RTT:
                    self.acks.update(n for r in ranges for n in r)
                    self.ack_frames += 1
                    self.ack_max_ranges = max(self.ack_max_ranges, len(ranges))
                buf.seek(pos)
                return original(context, frame_type, buf)

            handlers[kind] = (record, epochs)
        original_ack = self._quic._write_ack_frame

        def ack(builder, space, now):
            if ((self.fault == 'missing-body-ack' and self.bodies)
                    or (self.fault == 'missing-fin-ack' and self.fins)):
                space.ack_at = None
                return
            return original_ack(builder, space, now)

        self._quic._write_ack_frame = ack

    def quic_event_received(self, event):
        try:
            if isinstance(event, HandshakeCompleted):
                require(event.alpn_protocol == 'h3' and not event.session_resumed, 'wrong TLS')
                self.tls_done = True
            for ev in self.http.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    require(self.tls_done and not ev.stream_ended and ev.stream_id not in self.headers, 'wrong request lifecycle')
                    require(dict(ev.headers) == {b':method': b'POST', b':scheme': b'https',
                            b':authority': b'localhost', b':path': b'/'}, 'wrong POST headers')
                    self.headers.add(ev.stream_id)
                    self.bodies[ev.stream_id] = 0
                    if self.fault == 'early-response':
                        self._quic.send_stream_data(ev.stream_id, RESPONSE, end_stream=True)
                if isinstance(ev, DataReceived):
                    require(ev.stream_id in self.headers and ev.stream_id not in self.fins, 'unsolicited/duplicate body')
                    require(ev.data == b'x' * len(ev.data), 'wrong upload byte')
                    self.bodies[ev.stream_id] += len(ev.data)
                    require(self.bodies[ev.stream_id] <= self.size, 'extra upload bytes')
                    if ev.stream_ended:
                        require(self.bodies[ev.stream_id] == self.size, 'early request FIN')
                        self.fins.add(ev.stream_id)
                        if self.fault in ('missing-response', 'early-response'):
                            continue
                        data = RESPONSE
                        if self.fault == 'wrong-body': data = RESPONSE[:-1] + b'?'
                        if self.fault == 'duplicate-response': data += RESPONSE
                        if self.fault == 'late-wrong-body' and ev.stream_id == 4:
                            def later(stream=ev.stream_id):
                                self._quic.send_stream_data(stream, RESPONSE[:-1] + b'?', end_stream=True)
                                self.transmit()
                            asyncio.get_running_loop().call_later(.1, later)
                        else:
                            self._quic.send_stream_data(ev.stream_id, data, end_stream=self.fault != 'missing-response-fin')
                        self.responses += 1
        except Exception as error:
            self.failures.append(str(error))
            self.close(error_code=1, reason_phrase=str(error))


def configuration():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    conf = QuicConfiguration(is_client=False, alpn_protocols=['h3'], max_data=8192, max_stream_data=4096)
    conf.certificate, conf.private_key = certificate, key
    return conf


async def independent(peer, output, mode, fault=None):
    count, size = 2, 65543
    protocols, failures = [], []

    def factory(*args, **kwargs):
        protocol = Server(*args, size=size, fault=fault, failures=failures, **kwargs)
        protocols.append(protocol)
        return protocol

    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: failures.append(str(context)))
    server = await serve('127.0.0.1', 0, configuration=configuration(), create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    process = await asyncio.create_subprocess_exec(str(peer), str(port), str(count), str(size), mode, '3',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    name = fault or mode
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), 12)
        (output / f'{name}.stdout').write_bytes(stdout)
        (output / f'{name}.stderr').write_bytes(stderr)
        require(not failures, f'independent server failed: {failures}')
        row = json.loads(stdout)
        require(len(protocols) == 1 and protocols[0].tls_done, 'wrong handshake count')
        protocol = protocols[0]
        if fault:
            require(process.returncode != 0 and row['phase'] == 'failed', f'negative control accepted: {fault}')
            require(row['completed'] < count and len(row['latencies_ns']) == row['completed'], 'failed sample accounting')
            expected_error = {
                'missing-body-ack': 'timeout:', 'missing-fin-ack': 'timeout:',
                'missing-response': 'timeout:', 'missing-response-fin': 'timeout:',
                'early-response': 'response before acknowledged upload/FIN',
                'wrong-body': 'wrong response status/body bytes',
                'late-wrong-body': 'wrong response status/body bytes',
                'duplicate-response': 'extra or duplicate logical response',
            }[fault]
            require(row['error'].startswith(expected_error), 'failure was not the injected fault')
            if fault == 'late-wrong-body':
                require(row['completed'] == 1 and row['streams'][0]['latency_ns'] > 0, 'partial success/latency lost')
            if fault == 'missing-body-ack':
                require(all(not s['fin_sent'] and s['body_acked'] < size for s in row['streams']), 'FIN sent without body ACK')
            if fault in ('missing-fin-ack', 'missing-response', 'missing-response-fin'):
                require(all(s['body_acked'] == size and s['fin_sent'] for s in row['streams']), 'fault before complete body/FIN')
            if fault == 'missing-fin-ack':
                require(all(not s['fin_acked'] and s['response_fin'] for s in row['streams']), 'invented FIN ACK or missing response')
            if fault in ('missing-response', 'missing-response-fin'):
                require(all(s['fin_acked'] and not s['response_fin'] for s in row['streams']), 'request FIN not ACKed or invented response FIN')
            if fault == 'missing-response-fin':
                require(all(s['response_ranges'] == [[0, len(RESPONSE) - 1]] for s in row['streams']), 'response bytes missing too')
        else:
            require(process.returncode == 0, stderr.decode())
            validate(row, count, size)
            require(protocol.responses == count and len(protocol.fins) == count, 'wire completion count')
            require(protocol.bodies == {i * 4: size for i in range(count)}, 'wire body count')
            intended = expand(row['acked_packet_ranges'])
            floor = min(expand(row['received_ranges']))
            require({n for n in protocol.acks if n >= floor} == intended, 'independent ACK wire union')
            require(row['connection_blocked_observations'] > 0 and row['stream_blocked_observations'] > 0,
                    'flow blocking/resumption not exercised')
        return dict(case=name, expected_failure=bool(fault), peer=row, wire_body_bytes=protocol.bodies,
                    wire_acks=protocol.ack_frames, wire_max_ack_ranges=protocol.ack_max_ranges)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        server.close()
        loop.set_exception_handler(previous_handler)


async def hfast_check(peer, binary, output, mode, count, size, threads):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    name = f'hfast-{mode}-s{count}-t{threads}'
    with (output / f'{name}.server').open('x') as log:
        server = subprocess.Popen([str(binary), '--threads', str(threads), '--tcp', '0', '--quic', str(port)],
                                  stdout=log, stderr=subprocess.STDOUT)
        process = None
        try:
            await asyncio.sleep(.2)
            require(server.poll() is None, 'hfast startup failed')
            process = await asyncio.create_subprocess_exec(str(peer), str(port), str(count), str(size), mode, '45',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 55)
            (output / f'{name}.stdout').write_bytes(stdout)
            (output / f'{name}.stderr').write_bytes(stderr)
            require(process.returncode == 0, stderr.decode())
            row = json.loads(stdout)
            validate(row, count, size)
            require(all(row['credit_frames_per_stream']), 'large upload did not exercise credit')
            return dict(case=name, peer=row)
        finally:
            if process and process.returncode is None:
                process.kill()
                await process.wait()
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


async def main(args):
    args.output.mkdir(parents=True, exist_ok=False)
    cases = []
    if not args.only_server:
        vectors = json.loads(subprocess.check_output([str(args.peer), '--ack-vectors'], timeout=10))
        expected = expand(vectors['ranges'])
        for case in vectors['cases']:
            union, count = set(), 0
            for chunk in case['chunks']:
                require(len(chunk) <= case['budget'], 'ACK chunk exceeds packet budget')
                buf = Buffer(data=bytes(chunk))
                require(buf.pull_uint_var() == 2, 'not an ACK frame')
                ranges, _ = pull_ack_frame(buf)
                require(buf.eof(), 'extra ACK bytes')
                for r in ranges:
                    require(r.start >= 0, 'negative ACK range')
                    union.update(r)
                    count += len(r)
            require(union == expected and count == len(expected), 'independent ACK chunk union mismatch')
        (args.output / 'ack-vectors.json').write_text(json.dumps(vectors) + '\n')
        # PTO resends control credit in hfast; aioquic may send only a PING probe.
        # Exercise the unchanged hfast-specific silent-credit assertion below.
        for mode in ('ordinary', 'loss', 'reorder', 'sparse'):
            cases.append(await independent(args.peer, args.output, mode))
        for fault in ('missing-body-ack', 'early-response', 'missing-response', 'missing-response-fin',
                      'wrong-body', 'duplicate-response', 'missing-fin-ack', 'late-wrong-body'):
            cases.append(await independent(args.peer, args.output, 'ordinary', fault))
    if args.server:
        for mode in (args.mode.split(',') if args.mode else ['ordinary', 'loss', 'reorder', 'sparse', 'pto']):
            for count in args.streams:
                cases.append(await hfast_check(args.peer, args.server, args.output, mode, count, args.bytes, args.threads))
    (args.output / 'summary.json').write_text(json.dumps(dict(cases=cases, timing=False), indent=2) + '\n')
    print(json.dumps(dict(cases=len(cases), expected_failures=sum(c.get('expected_failure', False) for c in cases))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('peer', type=lambda s: Path(s).resolve())
    parser.add_argument('output', type=lambda s: Path(s).resolve())
    parser.add_argument('--server', type=lambda s: Path(s).resolve())
    parser.add_argument('--only-server', action='store_true')
    parser.add_argument('--mode')
    parser.add_argument('--streams', type=int, nargs='+', default=[1, 8, 32])
    parser.add_argument('--bytes', type=int, default=(1 << 24) + 65543)
    parser.add_argument('--threads', type=int, default=1)
    asyncio.run(main(parser.parse_args()))
