"""Independent, bounded validation and exact quantiles for native burst samples.

Files contain <8sIIQQ header (magic, phase, producer, first stream, count), followed by
count <QQQ records (stream, send ns, authenticated completion ns). Phase-relative
timestamps are exact; records are sorted by duration outside measured work.
"""
from array import array
from contextlib import ExitStack
import hashlib
import heapq
import os
import stat
import struct

MAX_SAMPLES = 1 << 22
MAX_PHASE = 64
HEADER = struct.Struct('<8sIIQQ')
SAMPLE = struct.Struct('<QQQ')
MAGIC = b'HFBSTL02'
INTERVAL = 'before-sendmsg-to-validated-authenticated-response-ns-v1'


def require(ok, message):
    if not ok:
        raise ValueError('burst latency: ' + message)


def limits(batch, datagrams, batches, cycles, warmup):
    for value in (batch, datagrams, batches, cycles, warmup):
        require(type(value) is int and value > 0, 'invalid workload')
    require(batch <= 32 and datagrams <= 32, 'invalid burst width')
    require(cycles <= MAX_PHASE and batches <= 1 << 20 and warmup <= 1 << 20,
            'phase/batch limit exceeded')
    require(max(batches, warmup) * batch * datagrams <= MAX_SAMPLES,
            'sample limit exceeded (4194304 per worker/phase)')


def metadata(row, phase, first, count, *, ready=False, producer=0):
    require(isinstance(row, dict), 'missing metadata')
    expected = dict(version=2, producer=producer, phase=phase, first_stream=first, expected=count,
                    count=0 if ready else count, bytes=32 if ready else 32 + 24 * count)
    require(type(producer) is int and 0 <= producer < 4, 'invalid producer')
    require(0 <= phase <= MAX_PHASE and 0 < count <= MAX_SAMPLES,
            'metadata outside resource limits')
    require(first % 4 == 0 and 0 <= first < first + count * 4 <= 1 << 62,
            'invalid stream interval')
    require(set(row) == {*expected, 'end_ns'}, 'unexpected metadata fields')
    for key, value in expected.items():
        require(type(row[key]) is int and row[key] == value, f'wrong {key}')
    end = row['end_ns']
    require((end is None) if ready else (type(end) is int and 0 < end < 1 << 64),
            'invalid end timestamp')


def open_file(path, size):
    # A FIFO, symlink or oversized file must not block or trigger a large read.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size == size,
                'truncated/oversized/nonregular sample file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def records(file, meta, digest):
    head = file.read(HEADER.size)
    digest.update(head)
    require(len(head) == HEADER.size, 'truncated header')
    require(HEADER.unpack(head) == (MAGIC, meta['phase'], meta['producer'], meta['first_stream'], meta['count']),
            'wrong sample header/phase/count')
    left = meta['count']
    while left:
        count = min(left, 2048)
        chunk = file.read(count * SAMPLE.size)
        digest.update(chunk)
        require(len(chunk) == count * SAMPLE.size, 'truncated samples')
        yield from SAMPLE.iter_unpack(chunk)
        left -= count
    require(not file.read(1), 'extra samples')


def inspect(path, meta, phase, first, count, width, producer=0):
    """Quick bounded export handshake. Full record checks run after STOP.

    Scanning large exports between phases could expire idle QUIC connections or
    worker command deadlines. Only a fixed-size header is read while peers live.
    This observation is NOT accepted latency evidence until validate() succeeds.
    """
    metadata(meta, phase, first, count, producer=producer)
    with open_file(path, meta['bytes']) as file:
        require(file.read(HEADER.size) == HEADER.pack(MAGIC, phase, producer, first, count),
                'wrong sample header/phase/count')
    return dict(path=str(path), metadata=meta, width=width, producer=producer)


def validate(path, meta, phase, first, count, width, producer=0):
    metadata(meta, phase, first, count, producer=producer)
    require(type(width) is int and 1 <= width <= 1024 and count % width == 0,
            'invalid burst width')
    # A compact membership bitmap plus two timestamps per burst; independent
    # of file contents and bounded before allocation. Never accumulate records.
    seen = bytearray((count + 7) // 8)
    starts = array('Q', [0]) * (count // width)
    ends = array('Q', [0]) * (count // width)
    digest = hashlib.sha256()
    last_duration = 0
    with open_file(path, meta['bytes']) as file:
        for stream, sent, complete in records(file, meta, digest):
            require(first <= stream < first + count * 4 and (stream - first) % 4 == 0,
                    'wrong stream ID')
            index = (stream - first) // 4
            mask = 1 << (index % 8)
            require(not seen[index // 8] & mask, 'duplicate sample')
            seen[index // 8] |= mask
            require(sent < complete <= meta['end_ns'], 'zero/reversed/outside-phase timestamp')
            duration = complete - sent
            require(duration >= last_duration, 'unsorted sample durations')
            last_duration = duration
            burst = index // width
            if ends[burst]:
                require(starts[burst] == sent, 'burst send timestamps differ')
            starts[burst] = sent
            ends[burst] = max(ends[burst], complete)
    # Exactly count unique in-range records also proves no missing requests.
    require(all(ends), 'missing burst')
    require(all(ends[i - 1] <= starts[i] for i in range(1, len(starts))),
            'overlapping or reversed serial bursts')
    return dict(path=str(path), sha256=digest.hexdigest(), metadata=meta)


def durations(file, evidence):
    digest = hashlib.sha256()
    for _, sent, complete in records(file, evidence['metadata'], digest):
        yield complete - sent
    require(digest.hexdigest() == evidence['sha256'], 'sample file changed after validation')


def summarize(evidence):
    """Exact nearest-rank quantiles over a sorted merge, with bounded buffers.

    At most 4 workers * (64 phases + warmup) files may be open. No raw sample
    vector or lossy histogram is created. Called only after workers stop.
    """
    require(0 < len(evidence) <= 4 * (MAX_PHASE + 1), 'invalid file count')
    count = sum(e['metadata']['count'] for e in evidence)
    ranks = {name: max(1, (count * numerator + denominator - 1) // denominator)
             for name, numerator, denominator in [('p50', 1, 2), ('p99', 99, 100),
                                                   ('p99_9', 999, 1000)]}
    total = 0
    result = dict(count=count)
    with ExitStack() as files:
        iterators = [durations(files.enter_context(open_file(e['path'], e['metadata']['bytes'])), e)
                     for e in evidence]
        actual = 0
        for actual, duration in enumerate(heapq.merge(*iterators), 1):
            total += duration
            if actual == 1:
                result['min_ns'] = duration
            for name, rank in ranks.items():
                if actual == rank:
                    result[name + '_ns'] = duration
            result['max_ns'] = duration
    require(actual == count, 'merged sample count mismatch')
    result.update(sum_ns=total, mean_ns=total / count)
    return result


def finish(evidence):
    identities = [(e['metadata']['producer'], e['metadata']['phase']) for e in evidence]
    require(len(identities) == len(set(identities)), 'repeated producer/phase export')
    warmup = [e for e in evidence if e['metadata']['phase'] == 0]
    measured = [e for e in evidence if e['metadata']['phase'] > 0]
    return dict(version=2, interval=INTERVAL, warmup=summarize(warmup),
                measured=summarize(measured), files=evidence)


def validate_exports(exports):
    evidence = []
    for row in exports:
        meta = row['metadata']
        evidence.append(validate(row['path'], meta, meta['phase'], meta['first_stream'],
                                 meta['count'], row['width'], producer=row['producer']))
    return evidence


def compare(baseline, candidate, enabled):
    """Reject omitted/mixed sampling modes before reporting any paired gain."""
    for row in (baseline, candidate):
        require(('latency' in row) == enabled, 'mixed or missing sampling mode')
        if enabled:
            data = row['latency']
            require(data['version'] == 2 and data['interval'] == INTERVAL, 'different interval')
            require(data['measured']['count'] == row['measured_requests'], 'missing measured samples')
            require(data['warmup']['count'] + data['measured']['count'] == row['completed'],
                    'missing warmup samples')
    if not enabled:
        return {}
    return {name + '_percent': (candidate['latency']['measured'][name + '_ns'] /
                               baseline['latency']['measured'][name + '_ns'] - 1) * 100
            for name in ('p50', 'p99', 'p99_9')}
