"""Fixed asymmetric workloads and conservative, sample-backed overlap gates.

All producers share CLOCK_MONOTONIC in one time namespace. The native ledger's
Instant epoch is bracketed by two clock reads, so no zero-error clock conversion
is assumed. Every cold interval must contain the whole hot interval even at the
unfavourable ends of those brackets. No samples are trimmed to obtain overlap.
"""
import burst_latency as latency
import burst_buffer


def require(ok, message):
    if not ok:
        raise ValueError('burst schedule: ' + message)


def validate(configs, producers, cycles, warmup):
    require(isinstance(configs, list) and len(configs) == producers == 4,
            'four explicit producer configurations required')
    for row in configs:
        require(isinstance(row, dict) and set(row) == {
            'role', 'batch', 'datagrams', 'batches', 'delay_ns'}, 'invalid producer configuration')
        require(row['role'] in ('hot', 'cold'), 'invalid producer role')
        require(type(row['delay_ns']) is int and 0 <= row['delay_ns'] <= 100_000_000,
                'invalid start delay')
        latency.limits(row['batch'], row['datagrams'], row['batches'], cycles, warmup)
    require(sum(row['role'] == 'hot' for row in configs) == 1, 'exactly one hot producer required')
    window = max(row['batch'] * row['datagrams'] for row in configs)
    require(all(window % (row['batch'] * row['datagrams']) == 0 for row in configs),
            'burst widths must divide the common credit window')
    return window


def clock(row, run_at, before, after, namespace):
    stamp = row.get('phase_clock')
    require(isinstance(stamp, dict) and set(stamp) == {
        'clock', 'namespace', 'run_at_ns', 'start_ns', 'end_ns',
        'epoch_low_ns', 'epoch_high_ns', 'first_sent_ns', 'last_complete_ns'},
        'missing or invalid phase clock')
    require(stamp['clock'] == 'CLOCK_MONOTONIC' and stamp['namespace'] == namespace,
            'clock or time namespace mismatch')
    require(type(stamp['run_at_ns']) is int and stamp['run_at_ns'] == run_at,
            'wrong release deadline')
    for key in ('start_ns', 'end_ns', 'epoch_low_ns', 'epoch_high_ns',
                'first_sent_ns', 'last_complete_ns'):
        require(type(stamp[key]) is int and 0 <= stamp[key] < 1 << 64, 'invalid clock integer')
    low, high = stamp['epoch_low_ns'], stamp['epoch_high_ns']
    first, last = stamp['first_sent_ns'], stamp['last_complete_ns']
    require(low <= high and first < last <= row['latency']['end_ns'], 'reversed phase clock')
    require(before < run_at <= stamp['start_ns'] <= low + first
            and high + last <= high + row['latency']['end_ns'] <= stamp['end_ns'] <= after,
            'timestamps outside controller phase')
    return dict(producer=row['latency']['producer'], phase=row['phase'],
                first_low_ns=low + first, first_high_ns=high + first,
                last_low_ns=low + last, last_high_ns=high + last,
                clock_uncertainty_ns=high - low)


def overlap(intervals, configs):
    require(len(intervals) == len(configs) == 4, 'missing producer interval')
    require([r['producer'] for r in intervals] == list(range(4)), 'duplicate/wrong producer interval')
    require(len({r['phase'] for r in intervals}) == 1, 'mixed overlap phases')
    hot_index = next(i for i, c in enumerate(configs) if c['role'] == 'hot')
    hot = intervals[hot_index]
    cold = []
    for i, row in enumerate(intervals):
        if i == hot_index:
            continue
        lead = hot['first_low_ns'] - row['first_high_ns']
        tail = row['last_low_ns'] - hot['last_high_ns']
        cold.append(dict(producer=i, initial_margin_ns=lead, final_margin_ns=tail,
                         covers_hot=lead >= 0 and tail >= 0))
    return dict(phase=hot['phase'], hot_producer=hot_index, intervals=intervals,
                cold=cold, suitable=all(row['covers_hot'] for row in cold))


def finish(evidence, reports, configs):
    """Validate reported endpoints against ALL independently parsed raw samples."""
    by_id = {(r['latency']['producer'], r['phase']): r for rows in reports for r in rows}
    require(len(by_id) == sum(map(len, reports)), 'repeated report identity')
    require(len(evidence) == len(by_id), 'missing/extra phase export')
    seen = set()
    for item in evidence:
        meta = item['metadata']
        identity = (meta['producer'], meta['phase'])
        require(identity in by_id and identity not in seen, 'wrong or repeated sample identity')
        seen.add(identity)
        row = by_id[identity]
        require(meta == row['latency'], 'sample/report metadata mismatch')
        require(item['first_sent_ns'] == row['phase_clock']['first_sent_ns']
                and item['last_complete_ns'] == row['phase_clock']['last_complete_ns'],
                'sample/report clock endpoints differ')
    measured = [e for e in evidence if e['metadata']['phase'] > 0]
    groups = {role: latency.summarize([e for e in measured
              if configs[e['metadata']['producer']]['role'] == role]) for role in ('hot', 'cold')}
    groups['producers'] = [latency.summarize([e for e in measured if e['metadata']['producer'] == i])
                           for i in range(len(configs))]
    return groups


def compare(baseline, candidate):
    """A rate comparison cannot silently change counts, starts or populations."""
    for row in (baseline, candidate):
        require(row['schedule']['suitable'], 'unsuitable overlap')
    require(all(baseline['schedule'][key] == candidate['schedule'][key] for key in
                ('config', 'initial_window', 'warmup_batches', 'cycles', 'barrier_lead_ns'))
            and all(baseline[key] == candidate[key] for key in
                    ('producer_sha256', 'client_cpus', 'gro', 'smoke'))
            and len(baseline['cycles']) == len(candidate['cycles'])
            and baseline['measured_requests'] == candidate['measured_requests'],
            'different fixed workloads')
    burst_buffer.require_equal(baseline['udp_receive_buffer'], candidate['udp_receive_buffer'])
    latency.compare(baseline, candidate, True)
