"""Independent byte/set oracle for the native response-credit transcript."""
from udp_accounting import require, require_clean_peer

RESPONSE = b'\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!'


def contains(ranges, value):
    return any(lo <= value <= hi for lo, hi in ranges)


def validate(row, count, step, mode):
    require(row['phase'] == 'done' and row['error'] is None, 'native failure')
    require((row['count'], row['step'], row['mode']) == (count, step, mode), 'workload changed')
    require(row['completed'] == count and len(row['streams']) == count, 'completion count')
    require(row['bootstrap_acked'] and row['control_bytes'] == 3 and row['fence_acked'], 'missing control/ACK fence')
    require(row['unacked_work'] == 0, 'unacknowledged work')
    require_clean_peer(row['udp'])
    interval = row['interval']
    require(interval['elapsed_ns'] == interval['end_monotonic_ns'] - interval['start_monotonic_ns'] > 0
            and interval['cpu_elapsed_ns'] > 0, 'invalid clock interval')
    require(row['acked_packet_ranges'] == row['received_ranges'], 'missing final ACK history')
    for stream, r in enumerate(row['streams']):
        require(r['id'] == stream * 4 and r['limit'] == r['grant_acked'] == 25, 'stream/credit mismatch')
        require(r['seen'] == (1 << 25) - 1 and r['fin'] and r['request_acked'], 'incomplete response or request ACK')
        require(type(r['started_ns']) is int and type(r['completed_ns']) is int
                and type(r['latency_ns']) is int, 'missing latency sample')
        require(0 < r['latency_ns'] == r['completed_ns'] - r['started_ns'] <= interval['elapsed_ns'], 'bad latency')
        require(row['workload_start_ns'] <= r['started_ns'] < r['completed_ns'] <= row['workload_end_ns'], 'sample outside workload')
    # Packet numbers and generation lists are checked independently of native
    # flight removal. Every original work generation needs a delivered copy ACK.
    generations, previous, last_ping = {}, -1, None
    for pn, kind, sid, limit, delivered, retry in row['sent_work']:
        require(pn > previous, 'duplicate/reversed transmitted PN')
        previous = pn
        key = (kind, sid, limit)
        if kind == 3:
            if not retry: last_ping = (3, pn, 0)
            require(last_ping is not None, 'PING retry before original')
            key = last_ping
        if kind in (0, 1, 2, 4):
            require(retry == (key in generations), 'missing original/retry generation')
        generations.setdefault(key, []).append((pn, delivered))
        if not delivered:
            require(not contains(row['server_ack_ranges'], pn), 'ACK of dropped grant')
    expected = {(0, 3, 3), (4, 0, 0)}
    for sid in range(0, count * 4, 4):
        expected.add((1, sid, 0))
        expected.update((2, sid, limit) for limit in sorted(set(range(step * 2, 25, step)) | ({25} if step < 25 else set())))
    require({key for key in generations if key[0] != 3} == expected, 'omitted or extra grant/request generation')
    for key, copies in generations.items():
        require(any(sent and contains(row['server_ack_ranges'], pn) for pn, sent in copies), 'unacknowledged generation')
    require(sorted(tuple(v) for v in row['acked_work'] if v[0] != 3) == sorted(expected), 'duplicate/missing work success')
    require(sum(v[0] == 3 for v in row['acked_work']) == sum(k[0] == 3 for k in generations), 'missing PING ACK')
    seen, fin, frame_count, duplicate_count = [set() for _ in range(count)], [False] * count, [0] * count, [0] * count
    control = set()
    for pn, sid, offset, data, ended, disposition in row['frames']:
        data = bytes(data)
        expected_bytes = b'\x00\x04\x00' if sid == 3 else RESPONSE
        require(sid == 3 or (sid % 4 == 0 and 0 <= sid // 4 < count), 'extra response')
        require(0 <= offset <= offset + len(data) <= len(expected_bytes)
                and data == expected_bytes[offset:offset + len(data)], 'conflicting overlap/bytes')
        require(not ended or (sid != 3 and offset + len(data) == 25), 'premature FIN')
        require(disposition in (0, 1, 2, 3), 'invalid frame disposition')
        if disposition == 1:
            if mode == 'loss': require(not contains(row['received_ranges'], pn), 'dropped packet received')
            continue
        require(contains(row['received_ranges'], pn), 'missing received PN')
        if disposition == 3:
            continue
        if sid == 3:
            control.update(range(offset, offset + len(data)))
        else:
            i = sid // 4
            # Replayed packets already seen are not redelivered by native code.
            # Record each accepted packet only once below.
            frame_count[i] += 1
            span = set(range(offset, offset + len(data)))
            duplicate_count[i] += span <= seen[i] and (not ended or fin[i])
            seen[i].update(span)
            fin[i] |= ended
    require(control == set(range(3)), 'missing SETTINGS bytes')
    require(all(s == set(range(25)) for s in seen) and all(fin), 'missing response interval/FIN')
    require(frame_count == [r['frames'] for r in row['streams']]
            and duplicate_count == [r['duplicates'] for r in row['streams']], 'frame delivery accounting')
    if mode == 'loss':
        require(row['dropped_response_packets'] == 2 and row['dropped_grants'] == (step < 25)
                and (step == 25 or row['retries'] > 0), 'loss/retry not exercised')
    if mode == 'reorder':
        require(row['dropped_response_packets'] == 2 and row['replayed'] and row['duplicate_packets'] >= 2,
                'reordered duplicates not exercised')
    if mode in ('sparse', 'withheld'):
        require(row['withheld_ranges'], 'withheld ACK schedule not exercised')
    if mode == 'sparse': require(row['max_ack_ranges'] > 1, 'sparse ACK ranges absent')
    return dict(count=count, step=step, mode=mode, completed=count,
                latency_samples=count, response_bytes=count * 25,
                grants=len(expected) - count - 2, retries=row['retries'],
                dropped_response_packets=row['dropped_response_packets'], dropped_grants=row['dropped_grants'])
