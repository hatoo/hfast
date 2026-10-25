"""Shared complete-work validation for single and coordinated native uploads."""
from udp_accounting import require_clean_peer

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
    require_clean_peer(row['udp'])
