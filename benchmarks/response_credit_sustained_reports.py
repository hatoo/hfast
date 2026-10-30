"""Independent set/byte audit of bounded sustained response-credit reports."""
from collections import Counter
from response_credit_reports import RESPONSE, contains
from udp_accounting import require, require_clean_peer


def limits(schedule):
    return {'byte': list(range(1, 26)), 'two-byte': list(range(2, 25, 2)) + [25],
            'two-fragment': [1, 25], 'full': [25]}[schedule]


def validate(row, count, window, schedule, mode):
    require(row['phase'] == 'done' and row['error'] is None, f'native failure: {row.get("error")}')
    require((row['count'], row['window'], row['schedule'], row['mode']) == (count, window, schedule, mode), 'workload changed')
    require(row['completed'] == row['retired'] == row['request_acks'] == len(row['samples']) == count, 'missing completion/sample/request ACK')
    require(row['response_bytes'] == count * 25, 'missing bytes')
    require(row['request_bytes_reserved'] == 5 + 18 * count <= row['max_data'] and count <= row['max_streams'], 'request credit exceeded')
    grants = count * (len(limits(schedule)) - 1)
    require(row['grants'] == row['grant_acks'] == grants, 'missing grant generation/ACK')
    require(row['bootstrap_acked'] and row['fence_acked'] and row['control_bytes'] == 3 and row['unacked_work'] == 0, 'unsettled control/work')
    require(0 < row['max_flights'] <= 64, 'unbounded live flight state')
    require(row['received_ranges'] == row['acked_packet_ranges'], 'missing packet ACK')
    require_clean_peer(row['udp'])
    interval = row['interval']
    require(interval['end_monotonic_ns'] - interval['start_monotonic_ns'] == interval['elapsed_ns'] > 0 and interval['cpu_elapsed_ns'] > 0, 'invalid interval')
    previous_wave_end = None
    for i, (sid, start, end) in enumerate(row['samples']):
        require(sid == 4 * i and type(start) is int and type(end) is int, 'sample identity/type')
        require(row['workload_start_ns'] <= start < end <= row['workload_end_ns'], 'sample timestamp outside workload')
        if i % window == 0:
            if i: previous_wave_end = max(s[2] for s in row['samples'][i-window:i])
        if previous_wave_end is not None:
            require(start >= previous_wave_end, 'new wave before previous completion')
    if row['trace']:
        generations, last_ping, previous = {}, None, -1
        for pn, kind, sid, limit, sent, retry in row['sent_work']:
            require(pn >= previous, 'packet numbers reversed')
            previous = pn
            key = (kind, sid, limit)
            if kind == 3:
                if not retry: last_ping = (3, pn, 0)
                require(last_ping is not None, 'PING retry before original')
                key = last_ping
            require(retry == (key in generations), 'missing original or repeated generation')
            generations.setdefault(key, []).append((pn, sent))
            if not sent: require(not contains(row['server_ack_ranges'], pn), 'ACK of dropped grant')
        expected = {(0, 3, 3), (4, 0, 0)}
        for sid in range(0, 4 * count, 4):
            expected.add((1, sid, 0))
            expected.update((2, sid, n) for n in limits(schedule)[1:])
        require({k for k in generations if k[0] != 3} == expected, 'missing work generation')
        require(Counter(tuple(w) for w in row['acked_work'] if w[0] != 3) == Counter(expected), 'wrong work retirement')
        for copies in generations.values():
            require(any(sent and contains(row['server_ack_ranges'], pn) for pn, sent in copies), 'unacknowledged packet copies')
        require(sum(k[0] == 3 for k in generations) == sum(w[0] == 3 for w in row['acked_work']), 'unacknowledged PING')
        seen, fin, control = [set() for _ in range(count)], set(), set()
        for pn, sid, offset, data, ended, disposition in row['frames']:
            expected_bytes = b'\x00\x04\x00' if sid == 3 else RESPONSE
            require(sid == 3 or sid % 4 == 0 and 0 <= sid // 4 < count, 'foreign response stream')
            require(0 <= offset <= offset + len(data) <= len(expected_bytes) and bytes(data) == expected_bytes[offset:offset+len(data)], 'wire bytes differ')
            require(not ended or sid != 3 and offset + len(data) == 25, 'wire FIN differs')
            require(disposition in (0, 1, 2, 3), 'invalid disposition')
            if disposition == 1: continue
            require(contains(row['received_ranges'], pn), 'missing received packet')
            if disposition == 3: continue
            if sid == 3: control.update(range(offset, offset+len(data)))
            else:
                seen[sid//4].update(range(offset, offset+len(data)))
                if ended: fin.add(sid)
        require(control == set(range(3)) and all(s == set(range(25)) for s in seen) and fin == set(range(0, count*4, 4)), 'missing response/control bytes/FIN')
    else:
        require(not row['sent_work'] and not row['frames'] and not row['acked_work'], 'unexpected unbounded transcript')
    if mode == 'loss':
        require(row['dropped_response_packets'] == 2 and row['dropped_grants'] == int(schedule != 'full'), 'loss not exercised')
        if schedule != 'full': require(row['retries'] > 0, 'retry not exercised')
    if mode == 'reorder': require(row['dropped_response_packets'] == 2 and row['replayed'] and row['duplicate_packets'] >= 2, 'reordering not exercised')
    if mode in ('withheld', 'sparse'): require(row['withheld_ranges'], 'ACK withholding not exercised')
    if mode == 'sparse': require(row['max_ack_ranges'] > 1, 'sparse ACK absent')
    return dict(count=count, window=window, schedule=schedule, mode=mode, completed=count,
                latency_samples=count, response_bytes=count*25, grants=grants, retries=row['retries'],
                elapsed_seconds=interval['elapsed_ns']/1e9, peer_cpu_seconds=interval['cpu_elapsed_ns']/1e9,
                peer_cpu_cores=interval['cpu_elapsed_ns']/interval['elapsed_ns'],
                sent_packets=row['sent_packets'], ack_packets=row['ack_packets'], received_packets=row['received_packets'])
