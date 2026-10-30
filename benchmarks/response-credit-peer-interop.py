#!/usr/bin/env python3
"""Independent aioquic peer: actual TLS limits, QPACK, grants, ACKs and faults."""
import argparse
import asyncio
import datetime
import json
from pathlib import Path
import time

from aioquic import tls
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived
from aioquic.quic.packet import pull_ack_frame, pull_quic_transport_parameters
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pylsqpack

from response_credit_reports import RESPONSE, validate
from udp_accounting import require


class Server(QuicConnectionProtocol):
    def __init__(self, *args, step, count, fault, failures, **kwargs):
        super().__init__(*args, **kwargs)
        self.step, self.count, self.fault, self.failures = step, count, fault, failures
        self.headers, self.requests, self.grants, self.acks = {}, {}, [], set()
        self.tls_done, self.control_sent, self.ack_disabled = False, False, False
        self.parameters = None
        q = self._quic
        original_tp = q._parse_transport_parameters

        def parameters(data, from_session_ticket=False):
            p = pull_quic_transport_parameters(Buffer(data=data))
            self.parameters = {k: getattr(p, k) for k in ('initial_max_data', 'initial_max_stream_data_bidi_local',
                              'initial_max_stream_data_uni', 'initial_max_streams_uni')}
            return original_tp(data, from_session_ticket)
        q._parse_transport_parameters = parameters
        handlers = q._QuicConnection__frame_handlers
        for kind in (2, 3, 0x11, 0x13):
            original, epochs = handlers[kind]

            def record(context, frame_type, buf, original=original, kind=kind):
                pos = buf.tell()
                if kind in (2, 3):
                    ranges, _ = pull_ack_frame(buf)
                    if context.epoch == tls.Epoch.ONE_RTT:
                        self.acks.update(n for r in ranges for n in r)
                elif kind == 0x11:
                    self.grants.append((buf.pull_uint_var(), buf.pull_uint_var()))
                elif kind == 0x13:
                    require(buf.pull_uint_var() == 1, 'wrong control count grant')
                buf.seek(pos)
                result = original(context, frame_type, buf)
                if kind == 0x13 and not self.control_sent:
                    require(self.tls_done, 'control before handshake')
                    q.send_stream_data(3, b'\x00\x04\x00', end_stream=False)
                    self.control_sent = True
                if kind == 0x11 and self.fault == 'missing-grant-ack' and self.grants[-1][0] % 4 == 0:
                    self.ack_disabled = True
                return result
            handlers[kind] = (record, epochs)
        original_ack = q._write_ack_frame

        def ack(builder, space, now):
            if self.ack_disabled:
                space.ack_at = None
                return
            return original_ack(builder, space, now)
        q._write_ack_frame = ack
        original_stream = q._write_stream_frame

        def stream(builder, space, stream, max_offset):
            if self.fault == 'credit-overrun' and stream.stream_id % 4 == 0:
                max_offset = 25
            return original_stream(builder, space, stream, max_offset)
        q._write_stream_frame = stream

    def quic_event_received(self, event):
        try:
            if isinstance(event, HandshakeCompleted):
                require(event.alpn_protocol == 'h3' and not event.session_resumed, 'TLS mismatch')
                self.tls_done = True
            if not isinstance(event, StreamDataReceived): return
            sid = event.stream_id
            if sid in self.headers:
                # aioquic 1.3 can deliver an empty FIN event for a repeated
                # STREAM FIN after its bytes were consumed. It is one request.
                require(not event.data and event.end_stream, 'data after request FIN')
                return
            data = self.requests.setdefault(sid, bytearray())
            data.extend(event.data)
            if sid % 4 == 2:
                expected = {2: b'\x00\x04\x00', 6: b'\x02', 10: b'\x03'}[sid]
                require(not event.end_stream and bytes(data) == expected[:len(data)], 'wrong client control bytes')
                return
            require(self.tls_done and sid % 4 == 0 and sid < self.count * 4, 'wrong request stream')
            if not event.end_stream: return
            require(sid not in self.headers, 'duplicate request FIN')
            b = Buffer(data=bytes(data))
            require(b.pull_uint_var() == 1, 'expected HEADERS')
            block = b.pull_bytes(b.pull_uint_var())
            require(b.eof(), 'extra request bytes')
            _, fields = pylsqpack.Decoder(0, 0).feed_header(sid, block)
            require(dict(fields) == {b':method': b'GET', b':scheme': b'https', b':authority': b'localhost', b':path': b'/'}, 'QPACK request mismatch')
            self.headers[sid] = fields
            if self.fault == 'missing-response': return
            response = RESPONSE
            if self.fault == 'wrong-byte': response = RESPONSE[:-1] + b'?'
            if self.fault == 'premature-fin': response = RESPONSE[:1]
            if self.fault == 'extra-byte': response += b'!'
            self._quic.send_stream_data(sid, response, end_stream=self.fault != 'missing-fin')
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
    conf = QuicConfiguration(is_client=False, alpn_protocols=['h3'], max_data=1 << 20, max_stream_data=4096)
    conf.certificate, conf.private_key = certificate, key
    return conf


async def check(peer, output, step, mode, fault=None, controlled=False):
    count = 2
    protocols, failures = [], []
    def factory(*a, **kw):
        p = Server(*a, step=step, count=count, fault=fault, failures=failures, **kw)
        protocols.append(p)
        return p
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: failures.append(str(context)))
    server = await serve('127.0.0.1', 0, configuration=configuration(), create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    name = f'{step}-{mode}-{fault or "valid"}' + ('-controlled' if controlled else '')
    process = await asyncio.create_subprocess_exec(str(peer), str(port), str(count), str(step), mode, '2',
        *(['--controlled'] if controlled else []), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        if controlled:
            ready_bytes = await asyncio.wait_for(process.stdout.readline(), 7)
            (output / f'{name}.ready').write_bytes(ready_bytes)
            ready = json.loads(ready_bytes)
            require(ready['phase'] == 'ready' and ready['started_requests'] == 0
                    and ready['control_bytes'] == 3 and ready['bootstrap_acked'], 'premature ready barrier')
            await asyncio.sleep(.05)
            require(len(protocols) == 1 and not protocols[0].headers
                    and all(s % 4 == 2 for s in protocols[0].requests), 'request before start barrier')
            lo = time.monotonic_ns()
            process.stdin.write(b'start\n')
            await process.stdin.drain()
            stdout = await asyncio.wait_for(process.stdout.readline(), 7)
            hi = time.monotonic_ns()
            process.stdin.write(b'exit\n')
            extra, stderr = await asyncio.wait_for(process.communicate(), 3)
            require(not extra, 'extra controlled report')
            interval = json.loads(stdout)['interval']
            require(lo <= interval['start_monotonic_ns'] < interval['end_monotonic_ns'] <= hi,
                    'interval includes bootstrap/barrier/report')
        else:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 9)
        (output / f'{name}.stdout').write_bytes(stdout)
        (output / f'{name}.stderr').write_bytes(stderr)
        require(not failures, f'independent server failed: {failures}')
        require(len(protocols) == 1, 'wrong connection count')
        p = protocols[0]
        require(p.parameters == dict(initial_max_data=1 << 20, initial_max_stream_data_bidi_local=step,
                    initial_max_stream_data_uni=step, initial_max_streams_uni=0), 'wrong advertised TLS limits')
        row = json.loads(stdout)
        if fault:
            require(process.returncode != 0 and row['phase'] == 'failed', f'fault accepted: {fault}')
            expected = {'wrong-byte': 'wire bytes differ', 'premature-fin': 'wire premature/control FIN',
                        'extra-byte': 'timeout', 'missing-fin': 'timeout', 'missing-response': 'timeout',
                        'missing-grant-ack': 'timeout', 'credit-overrun': 'wire length/credit exceeded'}[fault]
            require(expected in row['error'], f'wrong failure: {row["error"]}')
            if fault == 'missing-grant-ack':
                require(row['retries'] > 0 and row['unacked_work'] > 0, 'omitted grant retry not detected')
            else:
                require(row['completed'] < count, 'incomplete response counted')
            result = dict(fault=fault, rejected=True, error=row['error'])
        else:
            require(process.returncode == 0, stderr.decode())
            result = validate(row, count, step, mode)
            require(len(p.headers) == count, 'missing wire request')
            actual = set(p.grants)
            expected = {(3, 3)} | {(sid, n) for _, kind, sid, n, delivered, _ in row['sent_work'] if kind == 2 and delivered}
            require(actual == expected, 'wire grant transcript mismatch')
            # Peer has exited, but all datagrams already submitted can still be
            # queued for the event loop. Let the server consume the final ACK.
            await asyncio.sleep(.01)
            floor = min(lo for lo, hi in row['received_ranges'])
            intended = {n for lo, hi in row['acked_packet_ranges'] for n in range(lo, hi + 1)}
            require({n for n in p.acks if n >= floor} == intended, 'wire ACK union mismatch')
        (output / f'{name}.wire.json').write_text(json.dumps(dict(parameters=p.parameters,
            grants=p.grants, request_ids=sorted(p.headers), acked=sorted(p.acks), result=result), indent=2) + '\n')
        print(json.dumps(dict(case=name, **result)), flush=True)
        return result
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        server.close()
        loop.set_exception_handler(previous)


async def main(a):
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for step in (1, 2, 25):
        rows.append(await check(a.peer, a.output, step, 'each'))
    for mode in ('withheld', 'sparse', 'loss', 'reorder'):
        rows.append(await check(a.peer, a.output, 1, mode))
    rows.append(await check(a.peer, a.output, 1, 'each', controlled=True))
    for fault in ('wrong-byte', 'premature-fin', 'extra-byte', 'missing-fin', 'missing-response', 'missing-grant-ack', 'credit-overrun'):
        rows.append(await check(a.peer, a.output, 1, 'each', fault))
    (a.output / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('peer', type=lambda s: Path(s).resolve())
    p.add_argument('output', type=lambda s: Path(s).resolve())
    asyncio.run(main(p.parse_args()))
