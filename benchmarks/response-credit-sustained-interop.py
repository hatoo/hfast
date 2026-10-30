#!/usr/bin/env python3
"""Independent aioquic multi-wave, credit, late-packet and hostile-server oracle."""
import argparse
import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import time

from aioquic import tls
from aioquic.asyncio import serve
from aioquic.buffer import Buffer
from aioquic.quic.packet import push_ack_frame, pull_quic_transport_parameters

from response_credit_sustained_reports import limits, validate
from response_credit_reports import RESPONSE
from udp_accounting import require

spec = importlib.util.spec_from_file_location('single_wave_interop', Path(__file__).with_name('response-credit-peer-interop.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Server(base.Server):
    def __init__(self, *args, window, scenario, **kwargs):
        super().__init__(*args, **kwargs)
        self.window, self.scenario = window, scenario
        self.credit_open = scenario not in ('stream-credit', 'data-credit', 'no-credit')
        self.release_scheduled = False
        self.initial_server_limits = None
        self.credit_wire, self.old_packets = [], []
        self.first_ack = None
        self.old_sent = False
        self.ack_gate_until = None
        q = self._quic
        if scenario in ('stream-credit', 'no-credit'):
            q._local_max_streams_bidi.value = window
            q._local_max_streams_bidi.sent = window
        if scenario == 'data-credit':
            q._local_max_data.value = 5 + 18 * window
            q._local_max_data.sent = 5 + 18 * window
        original_parameters = q._serialize_transport_parameters

        def parameters():
            data = original_parameters()
            p = pull_quic_transport_parameters(Buffer(data=data))
            self.initial_server_limits = dict(max_data=p.initial_max_data, max_streams=p.initial_max_streams_bidi)
            return data
        q._serialize_transport_parameters = parameters
        original_limits = q._write_connection_limits

        def connection_limits(builder, space):
            if scenario in ('stream-credit', 'data-credit', 'no-credit'):
                if not self.credit_open:
                    if len(self.headers) >= window and not self.release_scheduled and scenario != 'no-credit':
                        self.release_scheduled = True
                        asyncio.get_running_loop().call_later(.12, self.release_credit)
                    return
                for limit, value, old in ((q._local_max_data, 5+18*self.count, 5+18*window),
                                         (q._local_max_streams_bidi, self.count, window)):
                    # Emit newest credit followed by stale credit in the same
                    # authenticated packet. The client must use the maximum.
                    value = max(value, limit.value)
                    if limit.value != value or limit.sent != value:
                        limit.value = value
                        buf = builder.start_frame(limit.frame_type, capacity=24,
                            handler=q._on_connection_limit_delivery, handler_args=(limit,))
                        buf.push_uint_var(value)
                        buf = builder.start_frame(limit.frame_type, capacity=16)
                        buf.push_uint_var(old)
                        self.credit_wire.extend([(int(limit.frame_type), value), (int(limit.frame_type), old)])
                        limit.sent = value
            else:
                original_limits(builder, space)
            if scenario == 'late-old' and len(self.headers) > window and not self.old_sent:
                require(self.first_ack is not None, 'missing original ACK snapshot')
                buf = builder.start_frame(2, capacity=256)
                push_ack_frame(buf, self.first_ack, 0)
                # Fresh packet number, retired stream 0: validate but never
                # attribute its complete bytes/FIN to the reused live slot.
                buf = builder.start_frame(0x0b, capacity=64)
                buf.push_uint_var(0)
                buf.push_uint_var(len(RESPONSE))
                buf.push_bytes(RESPONSE)
                self.old_packets.append(builder.packet_number)
                self.old_sent = True
        q._write_connection_limits = connection_limits
        original_ack = q._write_ack_frame

        def ack(builder, space, now):
            if self.headers and self.first_ack is None:
                self.first_ack = copy.deepcopy(space.ack_queue)
            if self.headers and scenario == 'no-request-ack':
                space.ack_at = None
                return
            if self.headers and scenario == 'original-ack' and not self.old_sent:
                if self.ack_gate_until is None: self.ack_gate_until = now + .12
                if now < self.ack_gate_until:
                    space.ack_at = self.ack_gate_until
                    return
                buf = builder.start_frame(2, capacity=256)
                push_ack_frame(buf, self.first_ack, 0)
                self.old_packets.append(builder.packet_number)
                self.old_sent = True
                space.ack_at = now + .02
                return
            if scenario == 'original-ack' and self.old_sent and len(self.headers) <= window:
                # Do not ACK the newer request copies until a new wave proves
                # that the original copy was sufficient to retire the old one.
                buf = builder.start_frame(2, capacity=256)
                push_ack_frame(buf, self.first_ack, 0)
                space.ack_at = None
                return
            return original_ack(builder, space, now)
        q._write_ack_frame = ack

    def release_credit(self):
        self.credit_open = True
        self._quic.send_ping(900)
        self.transmit()


async def check(peer, output, schedule='byte', mode='each', scenario='ordinary', fault=None,
                count=32, window=8, controlled=False):
    protocols, failures = [], []
    def factory(*a, **kw):
        p = Server(*a, step=limits(schedule)[0], count=count, fault=fault, failures=failures,
                   window=window, scenario=scenario, **kw)
        protocols.append(p)
        return p
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: failures.append(str(context)))
    server = await serve('127.0.0.1', 0, configuration=base.configuration(), create_protocol=factory)
    port = server._transport.get_extra_info('sockname')[1]
    name = f'{schedule}-{mode}-{scenario}-{fault or "valid"}-{count}' + ('-controlled' if controlled else '')
    hostile = fault or scenario in ('no-credit','no-request-ack')
    budget = 3 if hostile else 10
    process = await asyncio.create_subprocess_exec(str(peer), str(port), str(count), str(window), schedule, mode, str(budget), '--trace',
        *(['--controlled'] if controlled else []), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=16 << 20)
    try:
        if controlled:
            ready_bytes = await asyncio.wait_for(process.stdout.readline(), 7)
            (output / f'{name}.ready').write_bytes(ready_bytes)
            ready = json.loads(ready_bytes)
            require(ready['phase'] == 'ready' and ready['started_requests'] == 0 and ready['control_bytes'] == 3 and ready['bootstrap_acked'], 'premature ready barrier')
            await asyncio.sleep(.05)
            require(len(protocols) == 1 and not protocols[0].headers, 'request before start barrier')
            lo = time.monotonic_ns()
            process.stdin.write(b'start\n')
            await process.stdin.drain()
            stopped_bytes = await asyncio.wait_for(process.stdout.readline(), budget + 2)
            hi = time.monotonic_ns()
            (output / f'{name}.stopped').write_bytes(stopped_bytes)
            stopped = json.loads(stopped_bytes)
            require(stopped['phase'] == 'stopped', 'missing stop barrier')
            process.stdin.write(b'report\n')
            stdout = await asyncio.wait_for(process.stdout.readline(), 7)
            process.stdin.write(b'exit\n')
            extra, stderr = await asyncio.wait_for(process.communicate(), 3)
            require(not extra, 'extra controlled report')
            interval = json.loads(stdout)['interval']
            require(lo <= interval['start_monotonic_ns'] < interval['end_monotonic_ns'] <= hi, 'interval includes barrier/report')
        else:
            stdout, stderr = await asyncio.wait_for(process.communicate(), budget + 7)
        (output / f'{name}.stdout').write_bytes(stdout)
        (output / f'{name}.stderr').write_bytes(stderr)
        require(not failures, f'independent server failed: {failures}')
        require(len(protocols) == 1, 'wrong connection count')
        p = protocols[0]
        require(p.parameters == dict(initial_max_data=25*count+3, initial_max_stream_data_bidi_local=limits(schedule)[0],
                    initial_max_stream_data_uni=limits(schedule)[0], initial_max_streams_uni=0), 'wrong serialized TLS limits')
        row = json.loads(stdout)
        if hostile:
            require(process.returncode != 0 and row['phase'] == 'failed', f'fault accepted: {fault or scenario}')
            expected = {'wrong-byte':'wire bytes differ', 'premature-fin':'wire premature/control FIN',
                        'credit-overrun':'wire length/credit exceeded'}.get(fault, 'timeout')
            require(expected in row['error'], f'wrong failure: {row["error"]}')
            if scenario == 'no-credit':
                require(len(p.headers) == window and row['blocked_streams'] > 0, 'request sent without stream credit')
            if scenario == 'no-request-ack':
                require(row['request_acks'] == 0 and row['retired'] == 0 and row['retries'] > 0, 'response inferred request ACK')
            result = dict(rejected=True, error=row['error'], scenario=scenario, fault=fault)
        else:
            require(process.returncode == 0, stderr.decode())
            result = validate(row, count, window, schedule, mode)
            require(sorted(p.headers) == list(range(0,count*4,4)), 'wire requests differ')
            require(set(p.grants) == {(3,3)} | {(sid,n) for sid in p.headers for n in limits(schedule)[1:]}, 'actual wire grant sequence differs')
            await asyncio.sleep(.01)
            floor = min(lo for lo, _ in row['received_ranges'])
            intended = {n for lo,hi in row['acked_packet_ranges'] for n in range(lo,hi+1)}
            require({n for n in p.acks if n >= floor} == intended, 'actual wire ACK union differs')
            if scenario == 'stream-credit': require(row['blocked_streams'] > 0 and p.initial_server_limits['max_streams'] == window and p.credit_wire, 'stream-credit gate absent')
            if scenario == 'data-credit': require(row['blocked_data'] > 0 and p.initial_server_limits['max_data'] == 5+18*window and p.credit_wire, 'data-credit gate absent')
            if scenario == 'late-old': require(p.old_sent and row['late_duplicates'] > 0, 'old stream/ACK not exercised')
            if scenario == 'original-ack': require(p.old_sent and row['retries'] > 0, 'old original ACK after retries absent')
        (output / f'{name}.wire.json').write_text(json.dumps(dict(parameters=p.parameters,
            server_limits=p.initial_server_limits, credit_wire=p.credit_wire, grants=p.grants,
            request_ids=sorted(p.headers), acked=sorted(p.acks), old_packets=p.old_packets, result=result), indent=2)+'\n')
        print(json.dumps(dict(case=name, **result)), flush=True)
        return result
    finally:
        if process.returncode is None: process.kill(); await process.wait()
        server.close()
        loop.set_exception_handler(previous)


async def main(a):
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for schedule in ('byte','two-byte','two-fragment','full'):
        rows.append(await check(a.peer,a.output,schedule))
    for mode in ('withheld','sparse','loss','reorder'):
        rows.append(await check(a.peer,a.output,mode=mode))
    for scenario in ('stream-credit','data-credit','late-old','original-ack'):
        rows.append(await check(a.peer,a.output,schedule='full',scenario=scenario))
    rows.append(await check(a.peer,a.output,controlled=True))
    # 4-byte stream IDs and many generations, still inside the trace budget.
    rows.append(await check(a.peer,a.output,schedule='full',count=4112,window=32))
    for fault in ('wrong-byte','premature-fin','extra-byte','missing-fin','missing-response','missing-grant-ack','credit-overrun'):
        rows.append(await check(a.peer,a.output,fault=fault))
    for scenario in ('no-credit','no-request-ack'):
        rows.append(await check(a.peer,a.output,schedule='full',scenario=scenario))
    (a.output/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('peer',type=lambda s:Path(s).resolve())
    p.add_argument('output',type=lambda s:Path(s).resolve())
    asyncio.run(main(p.parse_args()))
