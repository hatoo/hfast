"""Independent sets and stream-offset oracle for the aggregate credit transcript."""
from collections import Counter
from udp_accounting import require


def step_for(schedule):
    return {'byte': 1, 'two-byte': 2, 'full': 25}[schedule]


def generations(count, window, schedule):
    step = step_for(schedule)
    value = 3
    for first in range(0, count, window):
        end = 3 + min(first + window, count) * 25
        while value < end:
            value = min(value + step, end)
            yield value


def grant_count(count, window, schedule):
    step = step_for(schedule)
    waves, tail = divmod(count, window)
    return waves * ((25 * window + step - 1) // step) + (25 * tail + step - 1) // step


def validate_connection(row, count, window, schedule):
    c = row['connection_credit']
    end = 3 + count * 25
    require(c['initial'] == 3 and c['step'] == step_for(schedule), 'wrong aggregate initial credit/step')
    require(all(c[k] == end for k in ('limit', 'acked', 'charged', 'wire_unique', 'received')), 'unsettled aggregate bytes/credit/ACK')
    require(c['completed_waves'] == (count + window - 1) // window, 'missing aggregate wave')
    if not row['trace']:
        require(not c['events'], 'unexpected aggregate transcript')
        return
    granted = acked = received = charged = wire_unique = 3
    retired, wave_end, completed = 0, 3, 0
    slots, requests = {}, set()
    wire, delivered, grants, acks = Counter(), Counter(), [], []
    known_grants = set()
    for kind, a, b, n in c['events']:
        require(all(type(x) is int and x >= 0 for x in (kind, a, b, n)), 'invalid aggregate event')
        if kind == 0:
            require(not slots and a == retired * 4 and 0 < b <= window and retired + b <= count and n == 0,
                    'aggregate wave alias/size')
            require(granted == acked == received == wave_end, 'wave before aggregate settlement')
            slots = {sid: dict(high=0, wire=set(), received=set()) for sid in range(a, a + b * 4, 4)}
            requests = set()
            wave_end = 3 + (retired + b) * 25
        elif kind == 6:
            require(a in slots and a not in requests and b == n == 0, 'aggregate request ACK identity')
            requests.add(a)
        elif kind == 1:
            require(slots and requests == set(slots), 'connection grant before request ACKs')
            require(received == granted == acked and granted < wave_end and b == n == 0,
                    'connection grant before unique bytes/ACK')
            require(a == min(granted + c['step'], wave_end), 'wrong connection generation')
            granted = a
            grants.append(a)
            known_grants.add(a)
        elif kind == 2:
            require(a in known_grants and b == n == 0, 'ACK of unknown connection grant')
            acked = max(acked, a)
            acks.append(a)
        elif kind in (3, 4):
            require(a % 4 == 0 and a // 4 < retired + len(slots) and b + n <= 25, 'foreign aggregate byte range')
            (wire if kind == 3 else delivered)[a, b, n] += 1
            if a // 4 < retired:
                continue
            s = slots[a]
            data = set(range(b, b + n))
            if kind == 3:
                charged += max(0, b + n - s['high'])
                s['high'] = max(s['high'], b + n)
                require(charged <= granted, 'wire aggregate credit exceeded')
                wire_unique += len(data - s['wire'])
                s['wire'].update(data)
            else:
                require(data <= s['wire'], 'aggregate delivery without wire evidence')
                received += len(data - s['received'])
                s['received'].update(data)
        elif kind == 5:
            require(slots and a == retired * 4 and b == len(slots) and n == 0, 'wrong aggregate retirement')
            require(granted == acked == received == wave_end and requests == set(slots), 'unsettled aggregate retirement')
            require(all(s['received'] == set(range(25)) for s in slots.values()), 'missing aggregate stream bytes')
            retired += len(slots)
            completed += 1
            slots.clear()
        else:
            raise ValueError('unknown aggregate event')
    require(not slots and retired == count and completed == c['completed_waves'], 'incomplete aggregate transcript')
    require(granted == acked == received == charged == wire_unique == end, 'aggregate transcript totals differ')
    require(grants == list(generations(count, window, schedule)) and acks == grants, 'missing/duplicate aggregate generation ACK')
    require(grants == [n for _, k, _, n, _, retry in row['sent_work'] if k == 5 and not retry], 'aggregate grants differ from flight records')
    require(acks == [n for k, _, n in row['acked_work'] if k == 5], 'aggregate ACKs differ from flight records')
    frames = [f for f in row['frames'] if f[1] != 3]
    require(wire == Counter((sid, off, len(data)) for _, sid, off, data, _, _ in frames), 'aggregate wire records differ')
    require(delivered == Counter((sid, off, len(data)) for _, sid, off, data, _, disposition in frames if disposition not in (1, 3)), 'aggregate delivered records differ')
