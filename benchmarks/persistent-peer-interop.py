#!/usr/bin/env python3
"""Untimed independent TLS, per-peer HTTP, close and failed-response oracles."""
import argparse
import asyncio
import datetime
import importlib.util
import json
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import persistent_peers as p
from burst_workers import require

spec = importlib.util.spec_from_file_location('churn_interop', Path(__file__).with_name('crypto-churn-interop.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Server(base.Server):
    def __init__(self, *args, fault=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fault = fault
        self.requests = []

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            require(event.alpn_protocol == 'h3' and not event.session_resumed, 'wrong/full TLS handshake')
            self.tls_done = True
        for http in self.http.handle_event(event):
            if isinstance(http, HeadersReceived):
                require(self.tls_done and http.stream_ended, 'request before TLS or missing FIN')
                require(http.stream_id == len(self.requests) * 4, 'wrong/repeated request stream')
                require(len(http.headers) == 4 and dict(http.headers) == {
                    b':method': b'GET', b':scheme': b'https', b':authority': b'localhost', b':path': b'/'},
                    'incorrect request headers')
                self.requests.append(http.stream_id)
                fault = self.fault if http.stream_id == 8 else None
                if fault == 'missing-response':
                    continue
                data = base.RESPONSE if fault != 'wrong-body' else base.RESPONSE[:-1] + b'?'
                self._quic.send_stream_data(http.stream_id, data, end_stream=(fault != 'missing-fin'))
                self.responses += 1


async def check(peer, output, configuration, fault):
    protocols = []

    def factory(*args, **kwargs):
        server = Server(*args, fault=(fault if len(protocols) == 2 else None), **kwargs)
        protocols.append(server)
        return server

    server = await serve('127.0.0.1', 0, configuration=configuration, create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    proc = await asyncio.create_subprocess_exec(str(peer), str(port), '3', '2', '2', '1',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    rows = []

    async def read():
        raw = await asyncio.wait_for(proc.stdout.readline(), 15)
        require(raw, 'peer exited without report')
        row = json.loads(raw)
        rows.append(row)
        return row

    async def send(command):
        proc.stdin.write(command.encode() + b'\n')
        await proc.stdin.drain()

    try:
        ready = await read()
        p.validate_peers(ready, 'ready', 3, 1, 2)
        require(len(protocols) == 3 and all(s.tls_done and s.requests == [0, 4] for s in protocols),
                'ready did not establish every peer independently')
        await send('start')
        done = await read()
        if fault:
            require(done['phase'] == 'failed' and done['failed'] == 1 and done['work_phase'] == 'measured',
                    'fault not rejected during measurement')
            require(len(done['peers']) == 3, 'failed peer omitted')
            for i, row in enumerate(done['peers']):
                expected = 4 if i < 2 else (3 if fault == 'missing-response' else 2)
                require(row['tls_completed'] and row['requests'] == 4 and row['responses'] == expected
                        and len(row['latencies_ns']) == expected and all(n > 0 for n in row['latencies_ns'])
                        and not row['close_sent'], 'partial counts/latencies discarded')
            require(await asyncio.wait_for(proc.wait(), 5) == 1, 'fault accepted')
        else:
            p.validate_done(done, 3, 2, 2)
            await send('report')
            reported = await read()
            p.validate_peers(reported, 'reported', 3, 3, 2, ready, samples=True)
            await send('close')
            closed = await read()
            p.validate_peers(closed, 'closed', 3, 3, 2, reported)
            await send('exit')
            require(await asyncio.wait_for(proc.wait(), 5) == 0, 'peer failed')
            await asyncio.sleep(.05)
            require(len(protocols) == 3 and all(s.tls_done and s.closed_by_peer
                    and s.requests == list(range(0, 24, 4)) and s.responses == 6 for s in protocols),
                    'independent TLS/request/response/close mismatch')
        return dict(fault=fault, connections=len(protocols), requests=[s.requests for s in protocols],
                    responses=[s.responses for s in protocols], expected_failure=bool(fault), peer=rows)
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        name = fault or 'normal'
        (output / f'{name}.stderr').open('xb').write(await proc.stderr.read())
        (output / f'{name}.peer.json').open('x').write(json.dumps(rows, indent=2) + '\n')
        server.close()


async def main(args):
    args.output.mkdir(parents=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=['h3'], quic_logger=QuicLogger(),
                                      max_data=1 << 30, max_stream_data=1 << 20)
    configuration.certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()))
    configuration.private_key = key
    results = []
    for fault in (None, 'missing-response', 'wrong-body', 'missing-fin'):
        results.append(await check(args.peer, args.output, configuration, fault))
    (args.output / 'summary.json').open('x').write(json.dumps(dict(cases=results, timing=False), indent=2) + '\n')
    print(json.dumps(dict(cases=4, connections=12, expected_failures=3)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('peer', 'output'):
        parser.add_argument(name, type=lambda s: Path(s).resolve())
    asyncio.run(main(parser.parse_args()))
