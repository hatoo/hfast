"""Independent authenticated-plaintext oracle for sparse aborted uploads.

This intentionally shares no native encoder/accounting implementation. aioquic
decodes QUIC integers and pylsqpack decodes the HTTP headers. It is not a second
TLS implementation, and no timing inference is made from the observer.
"""
from aioquic.buffer import Buffer
import pylsqpack

HALF = 1 << 23
INITIAL_DATA = 1 << 30
ERROR = 0x10c
RESPONSE = b'\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def datagram_receipts(report, counters):
    """Require intact GRO aggregates, including TLS and the final close.

    UDP InDatagrams counts receive messages: an intact GRO aggregate contributes
    one, not its segment count. Authenticated packet fences independently require
    every segment. A host that splits the aggregates fails this fixture's gate.
    """
    sent, received = report['sent_datagrams_before_close'], report['received_datagrams']
    excess=report['gso_segment_excess']
    require(type(sent) is int and type(received) is int and sent>0 and received>0,
            'invalid native datagram receipts')
    require(type(excess) is int and 0<=excess<sent, 'invalid GSO accounting')
    require(counters['InDatagrams']==sent+received+1-excess, 'UDP datagram receipt mismatch')


def frames(data):
    b = Buffer(data=data)
    while not b.eof():
        ty = b.pull_uint_var()
        if ty in (0, 1, 0x1e):
            yield ty, ()
        elif ty == 2:
            largest, delay, count, first = (b.pull_uint_var() for _ in range(4))
            require(delay == 0 and first <= largest, 'invalid ACK')
            lo = largest - first
            ranges = [(lo, largest)]
            for _ in range(count):
                hi = lo - b.pull_uint_var() - 2
                lo = hi - b.pull_uint_var()
                require(0 <= lo <= hi, 'invalid ACK range')
                ranges.append((lo, hi))
            yield ty, ranges
        elif ty == 4:
            yield ty, tuple(b.pull_uint_var() for _ in range(3))
        elif 8 <= ty <= 15:
            sid = b.pull_uint_var()
            offset = b.pull_uint_var() if ty & 4 else 0
            size = b.pull_uint_var() if ty & 2 else b.capacity-b.tell()
            yield ty, (sid, offset, bool(ty & 1), b.pull_bytes(size))
        elif ty in (0x10, 0x11, 0x12, 0x13):
            yield ty, tuple(b.pull_uint_var() for _ in range(2 if ty == 0x11 else 1))
        else:
            raise ValueError(f'unexpected frame {ty:#x}')


def headers(data, method, sid):
    b = Buffer(data=data)
    require(b.pull_uint_var() == 1, 'missing HEADERS')
    encoded = b.pull_bytes(b.pull_uint_var())
    blocked, result = pylsqpack.Decoder(0, 0).feed_header(sid, encoded)
    expected = [(b':method', method), (b':scheme', b'https'),
                (b':authority', b'localhost'), (b':path', b'/')]
    require(not blocked and result == expected, 'wrong HTTP headers')
    if method == b'POST':
        require(b.pull_uint_var() == 0, 'missing DATA')
        require(b.pull_uint_var() + len(data) == HALF, 'wrong declared body')
    require(b.eof(), 'unexpected request prefix bytes')


def verify(records, report):
    count = report['cohort']
    require(report.get('iterations',1)<=64, 'wire audit exceeds bounded history')
    require(count in (16, 64, 256), 'invalid cohort')
    require(report['mode'] in ('inline', 'separate', 'survivors', 'late-ack'), 'invalid mode')
    iterations=report.get('iterations',1)
    require(type(iterations) is int and 1<=iterations<=8192, 'invalid iterations')
    aborted_ids={4*(cycle*(count+2)+n) for cycle in range(iterations) for n in range(count)}
    reset_ids=[v[0] for row in records if row['direction']=='rx'
               for ty,v in frames(bytes.fromhex(row['hex'])) if ty==4]
    require(len(reset_ids)==len(set(reset_ids)), 'duplicate reset')
    require(set(reset_ids)==aborted_ids, 'missing reset/response/retirement')
    stream_limit, data_limit = count*2, INITIAL_DATA
    states, last, snapshots, fences = {}, {}, {}, {}
    flow, aborted_bytes, request_bytes, retired = 0, 0, 0, 0
    acked = None
    controls = set()
    limits = {}
    for rec in records:
        direction, pn = rec['direction'], rec['pn']
        require(direction in ('tx', 'rx'), 'invalid direction')
        require(direction not in last or pn == last[direction]+1, 'packet gap/replay')
        last[direction] = pn
        for ty, v in frames(bytes.fromhex(rec['hex'])):
            if direction == 'tx':
                if 8 <= ty <= 15:
                    sid, offset, fin, data = v
                    if sid % 4 == 2:
                        require((sid, offset, fin, data) in ((2,0,False,b'\x00\x04\x00'),
                                (6,0,False,b'\x02'),(10,0,False,b'\x03')) and sid not in controls,
                                'wrong/duplicate control stream')
                        controls.add(sid)
                        flow += len(data)
                        continue
                    require(sid % 4 == 0 and sid//4 < stream_limit, 'ungranted stream')
                    if offset == 0:
                        require(sid not in states and sid == len(states)*4, 'omitted/duplicate request')
                        aborted = sid in aborted_ids
                        require(fin != aborted, 'wrong request FIN')
                        headers(data, b'POST' if aborted else b'GET', sid)
                        states[sid] = dict(end=len(data), markers=[], reset=None, output=None,
                                           retired=False, aborted=aborted)
                        flow += len(data)
                        if aborted:
                            aborted_bytes += len(data)
                        else:
                            request_bytes += len(data)
                    else:
                        st = states[sid]
                        require(st['aborted'] and st['reset'] is None and not fin and data == b'x',
                                'invalid partial body')
                        expected = HALF-2+len(st['markers'])
                        require(len(st['markers']) < 2 and offset == expected, 'missing/duplicate crossing')
                        st['markers'].append(offset)
                        flow += offset+1-st['end']
                        st['end'] = offset+1
                        aborted_bytes += 1
                    require(flow <= data_limit, 'connection credit exceeded')
                    require(states[sid]['end'] <= 2*HALF, 'stream credit exceeded')
                elif ty == 4:
                    sid, error, final = v
                    st = states[sid]
                    require(st['aborted'] and st['reset'] is None, 'duplicate/unsolicited receive reset')
                    require(st['markers'] == [HALF-2, HALF-1], 'reset before crossing')
                    require(error == ERROR and final == HALF == st['end'], 'wrong receive final size/error')
                    st['reset'] = pn
                elif ty == 2:
                    require(v[0][1] <= last.get('rx', v[0][1]), 'ACK of unseen packet')
                    for st in states.values():
                        target = st['output']
                        if target is not None and not st['retired'] and any(lo <= target <= hi for lo,hi in v):
                            st['retired'] = True
                            retired += 1
                else:
                    require(ty in (0,1), 'unexpected client frame')
            else:
                if ty == 2:
                    require(v == [(0,v[0][1])] and v[0][1] <= last['tx'], 'incomplete request ACK')
                    acked = max(acked or 0, v[0][1])
                elif ty == 4:
                    sid, error, size = v
                    st = states[sid]
                    require(st['aborted'] and st['reset'] is not None, 'unsolicited reset')
                    require(st['output'] is None, 'duplicate reset')
                    require(error == ERROR and size == 0, 'wrong reset final size/error')
                    st['output'] = pn
                elif 8 <= ty <= 15:
                    sid, offset, fin, data = v
                    if sid == 3:
                        require((offset,fin,data)==(0,False,b'\x00\x04\x00'), 'wrong server control')
                        continue
                    st = states[sid]
                    require(not st['aborted'], 'premature success for aborted upload')
                    require(st['output'] is None, 'duplicate response')
                    require((offset,fin,data)==(0,True,RESPONSE), 'wrong/incomplete response')
                    st['output'] = pn
                elif ty == 0x11:
                    sid, limit = v
                    require(sid in states and states[sid]['markers']==[HALF-2,HALF-1]
                            and limit == 3*HALF, 'wrong stream credit')
                    limits[sid] = limit
                elif ty == 0x12:
                    require(acked in snapshots, 'credit without processing fence')
                    expected = count*2 + snapshots[acked][1]
                    require(v[0] == expected and v[0]-stream_limit >= count, 'wrong stream retirement credit')
                    stream_limit = v[0]
                elif ty == 0x10:
                    require(acked in snapshots, 'data credit without processing fence')
                    expected = INITIAL_DATA + snapshots[acked][0]
                    require(v[0] == expected and v[0]-data_limit >= INITIAL_DATA//2, 'wrong connection credit')
                    data_limit = v[0]
                else:
                    require(ty in (0,1,0x1e,0x13), 'unexpected server frame')
        if direction == 'tx':
            snapshots[pn] = (flow,retired)
        elif acked is not None:
            fences[acked]=(pn,stream_limit,data_limit)
    require(controls == {2,6,10}, 'missing control streams')
    require(len(states) == (count+2)*iterations and all(st['output'] is not None and st['retired'] for st in states.values()),
            'missing reset/response/retirement')
    require(acked == last['tx'], 'missing final authenticated fence')
    # Padded native datagrams form only the credit-crossing/reset bursts.
    padded=[row for row in records if row['direction']=='tx' and len(bytes.fromhex(row['hex']))==1171]
    segments=len(padded)
    bursts=iterations*(1 if report['mode']=='inline' else 2)
    if 'gso_segment_excess' in report:
        require(report['gso_segment_excess']==segments-bursts, 'GSO transcript mismatch')
    if report['mode'] in ('separate','late-ack'):
        require(set(limits)==aborted_ids, 'missing surviving stream credit')
    elif report['mode']=='survivors':
        require({sid for sid in aborted_ids if (sid//4)%(count+2)%2} <= set(limits), 'missing surviving stream credit')
    expected = dict(responses=2*iterations,cancelled=count*iterations,resets=count*iterations,errors=0,reset_final_size=HALF,
                    reset_final_bytes=HALF*count*iterations,aborted_wire_bytes=25*count*iterations,prefix_bytes=23,
                    request_bytes=request_bytes,flow_control_bytes=flow,initial_stream_limit=2*count,
                    advertised_stream_limit=stream_limit,advertised_data_limit=data_limit,
                    timing_qualified=False,manual_sparse_driver=True)
    for key,value in expected.items():
        require(report[key]==value, f'report mismatch: {key}')
    require(aborted_bytes == 25*count*iterations and request_bytes == 36*iterations, 'wire byte mismatch')
    for key,size in [('response_latency_ns',2*iterations),('cancellation_latency_ns',count*iterations)]:
        require(len(report[key])==size and all(type(x) is int and x>0 for x in report[key]), 'missing/invalid samples')
    if 'cancellation_stream_ids' in report:
        require(sorted(report['cancellation_stream_ids'])==sorted(aborted_ids), 'missing/duplicate cancellation samples')
        if 'cycles' in report:
            verify_report(report)
            for cycle in report['cycles']:
                pn=cycle['sent_through']
                require(pn in snapshots and snapshots[pn]==(cycle['flow_control_bytes'],(cycle['first_stream_id']//4)+count+2), 'wrong cumulative cycle ledger')
                require(fences.get(pn)==(cycle['received_through'],cycle['advertised_stream_limit'],cycle['advertised_data_limit']), 'wrong cumulative cycle receive fence')
        else:
            require(max(report['cancellation_latency_ns'])<=report['cancellation_cohort_ns'], 'invalid cancellation interval')
    return dict(aborted_streams=count*iterations,successes=2*iterations,retired=retired,wire_bytes=aborted_bytes+request_bytes+5,
                reset_final_bytes=HALF*count*iterations,stream_limits=len(limits),processing_fences=True)



def verify_report(report):
    """Validate every cumulative cohort and sample after an unlogged interval.

    The independent plaintext ledger is additionally required on audit runs;
    these compact receipts alone do not prove internal server queue exposure.
    """
    count=report['cohort']; total=report['iterations']; warmup=report['warmup']
    require(count in (16,64,256) and type(total) is int and 2<=total<=8192, 'invalid iterations')
    require(type(warmup) is int and 0<warmup<total and report['measured']==total-warmup, 'invalid phase counts')
    require(report['mode'] in ('inline','separate','survivors','late-ack'), 'invalid mode')
    require(len(report['cycles'])==total, 'missing cumulative cycle')
    require(report['initial_stream_limit']==2*count, 'wrong initial credit')
    expected=dict(cancelled=count*total,resets=count*total,responses=2*total,errors=0,
        reset_final_size=HALF,reset_final_bytes=count*total*HALF,aborted_wire_bytes=25*count*total,
        request_bytes=36*total,prefix_bytes=23,flow_control_bytes=5+total*(count*HALF+36),
        timing_qualified=False,manual_sparse_driver=True)
    for key,value in expected.items():require(report[key]==value,f'report mismatch: {key}')
    for key,size in [('cancellation_latency_ns',count*total),('response_latency_ns',2*total),
                     ('cancellation_stream_ids',count*total),('response_stream_ids',2*total)]:
        require(len(report[key])==size and all(type(x) is int and x>=(0 if key.endswith('ids') else 1) for x in report[key]), 'missing/invalid samples')
    stream_limit=count*2; data_limit=INITIAL_DATA; sent=received=-1
    for i,row in enumerate(report['cycles']):
        first=i*(count+2)*4
        require(row['first_stream_id']==first,'wrong advancing stream IDs')
        require(sorted(report['cancellation_stream_ids'][i*count:(i+1)*count])==list(range(first,first+count*4,4)), 'missing/duplicate cancellation samples')
        require(report['response_stream_ids'][i*2:(i+1)*2]==[first+count*4,first+(count+1)*4], 'missing/duplicate response samples')
        require(max(report['cancellation_latency_ns'][i*count:(i+1)*count])<=row['cancellation_cohort_ns']<=row['cycle_ns'], 'invalid cancellation interval')
        require(sum(report['response_latency_ns'][i*2:(i+1)*2])<=row['cycle_ns'], 'invalid response interval')
        require(row['sent_through']>sent and row['received_through']>received,'missing advancing ACK fences')
        sent,received=row['sent_through'],row['received_through']
        flow=5+(i+1)*(count*HALF+36)
        require(row['flow_control_bytes']==flow,'wrong cumulative flow')
        # Cancellation ACK retires this cohort atomically; the two GETs then
        # retire individually. Check grants at each actual processing fence.
        for retired in [i*(count+2)+count, (i+1)*(count+2)-1, (i+1)*(count+2)]:
            if 2*count+retired-stream_limit>=count:stream_limit=2*count+retired
        require(row['advertised_stream_limit']==stream_limit,'wrong cumulative stream credit')
        require(data_limit<=row['advertised_data_limit']<=INITIAL_DATA+flow and
                INITIAL_DATA+flow-row['advertised_data_limit']<INITIAL_DATA//2,'wrong cumulative data credit')
        data_limit=row['advertised_data_limit']
    require(report['advertised_stream_limit']==stream_limit and report['advertised_data_limit']==data_limit,'wrong final credit')
    require(0<report['max_packet_history']<=128,'unbounded packet history')
    interval=report['interval']
    require(interval['elapsed_ns']==interval['end_monotonic_ns']-interval['start_monotonic_ns']>0 and
            interval['cpu_elapsed_ns']>0,'invalid native interval')
    return dict(aborted_streams=count*total,successes=2*total,retired=(count+2)*total,
                wire_bytes=(25*count+36)*total+5,reset_final_bytes=HALF*count*total,
                native_receipts=True,wire_audit=False)


def encode(items):
    """Independent aioquic encoder, used only for negative transcript controls."""
    b=Buffer(capacity=65536)
    for ty,v in items:
        if 8 <= ty <= 15:
            sid,offset,fin,data=v
            b.push_uint_var(0x0e|int(fin))
            for n in (sid,offset,len(data)):b.push_uint_var(n)
            b.push_bytes(data)
        elif ty==2:
            b.push_uint_var(2)
            for n in (v[0][1],0,len(v)-1,v[0][1]-v[0][0]):b.push_uint_var(n)
            for (previous,_),(lo,hi) in zip(v,v[1:]):
                b.push_uint_var(previous-hi-2);b.push_uint_var(hi-lo)
        else:
            b.push_uint_var(ty)
            for n in v:b.push_uint_var(n)
    return b.data.hex()


def negative_controls(records, report):
    import copy
    results=[]
    decoded=[list(frames(bytes.fromhex(row['hex']))) for row in records]
    rx=next(i for i,row in enumerate(records) if row['direction']=='rx' and any(t==4 for t,_ in decoded[i]))
    tx=next(i for i,row in enumerate(records) if row['direction']=='tx' and any(t==4 for t,_ in decoded[i]))
    reset=next(v for t,v in decoded[rx] if t==4)
    mutations={
        'missing-reset':(rx,[(t,v) for t,v in decoded[rx] if t!=4 or v!=reset],'missing reset/response/retirement'),
        'duplicate-reset':(rx,decoded[rx]+[(4,reset)],'duplicate reset'),
        'wrong-reset-final-size':(rx,[(t,(v[0],v[1],1)) if t==4 and v==reset else (t,v) for t,v in decoded[rx]],'wrong reset final size/error'),
        'wrong-receive-final-size':(tx,[(t,(v[0],v[1],HALF-1)) if t==4 else (t,v) for t,v in decoded[tx]],'wrong receive final size/error'),
        'premature-success':(rx,[(0x0f,(reset[0],0,True,RESPONSE))]+decoded[rx],'premature success for aborted upload'),
    }
    last_rx=max(i for i,row in enumerate(records) if row['direction']=='rx')
    mutations['missing-final-fence']=(last_rx,[(t,v) for t,v in decoded[last_rx] if t!=2],'missing final authenticated fence')
    for name,(index,items,reason) in mutations.items():
        damaged=copy.deepcopy(records)
        damaged[index]['hex']=encode(items)
        try:verify(damaged,report)
        except ValueError as exc:
            require(reason in str(exc),f'{name} failed for wrong reason: {exc}')
            results.append(dict(name=name,reason=str(exc)))
        else:raise ValueError(f'{name} unexpectedly passed')
    for name,key,value,reason in [
        ('omitted-cancellation','cancelled',report['cancelled']-1,'report mismatch: cancelled'),
        ('gap-counted-as-upload','aborted_wire_bytes',report['reset_final_bytes'],'report mismatch: aborted_wire_bytes'),
        ('missing-sample','response_latency_ns',report['response_latency_ns'][:-1],'missing/invalid samples'),
        ('missing-cancellation-sample','cancellation_latency_ns',report['cancellation_latency_ns'][:-1],'missing/invalid samples'),
        ('unqualified-timing','timing_qualified',True,'report mismatch: timing_qualified'),
    ]:
        damaged=copy.deepcopy(report);damaged[key]=value
        try:verify(records,damaged)
        except ValueError as exc:
            require(reason in str(exc),f'{name} failed for wrong reason: {exc}')
            results.append(dict(name=name,reason=str(exc)))
        else:raise ValueError(f'{name} unexpectedly passed')
    if 'cycles' in report:
        for key,value,reason in [('first_stream_id',0,'wrong advancing stream IDs'),
                                 ('flow_control_bytes',5,'wrong cumulative flow'),
                                 ('advertised_stream_limit',report['initial_stream_limit'],'wrong cumulative stream credit'),
                                 ('sent_through',report['cycles'][0]['sent_through'],'missing advancing ACK fences')]:
            damaged=copy.deepcopy(report);damaged['cycles'][-1][key]=value
            try:verify_report(damaged)
            except ValueError as exc:
                require(reason in str(exc),f'{key} failed for wrong reason: {exc}')
                results.append(dict(name='cumulative-'+key,reason=str(exc)))
            else:raise ValueError(f'{key} unexpectedly passed')
    return results
