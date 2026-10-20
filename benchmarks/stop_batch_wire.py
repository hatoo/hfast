"""Independent aioquic/pylsqpack decoding of the native peer's plaintext trace.

This checks wire semantics after authentication, not an independent TLS audit.
Only the loss-free, fully sent response workload is supported.
"""
from aioquic.buffer import Buffer
import pylsqpack

from stop_batch import require

RESPONSE = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!"
ERROR = 0x10c


def frames(data):
    b = Buffer(data=data)
    while not b.eof():
        ty = b.pull_uint_var()
        if ty in (0, 1, 0x1e):
            yield ty, ()
        elif ty == 2:
            largest, delay, count, first = (b.pull_uint_var() for _ in range(4))
            lo = largest - first
            ranges = [(lo, largest)]
            for _ in range(count):
                hi = lo - b.pull_uint_var() - 2
                lo = hi - b.pull_uint_var()
                require(lo >= 0, "invalid ACK range")
                ranges.append((lo, hi))
            yield ty, ranges
        elif ty in (4, 5):
            yield ty, tuple(b.pull_uint_var() for _ in range(3 if ty == 4 else 2))
        elif 8 <= ty <= 15:
            sid = b.pull_uint_var()
            offset = b.pull_uint_var() if ty & 4 else 0
            size = b.pull_uint_var() if ty & 2 else b.capacity - b.tell()
            yield ty, (sid, offset, bool(ty & 1), b.pull_bytes(size))
        elif ty in (0x10, 0x12, 0x13):
            yield ty, (b.pull_uint_var(),)
        else:
            raise ValueError(f"unexpected frame type {ty:#x}")


def verify(records, report):
    streams, reset_ids, last = {}, set(), {}
    completed = 0
    advertised = report["initial_stream_limit"]
    request_headers = [(b":method", b"GET"), (b":scheme", b"https"),
                       (b":authority", b"localhost"), (b":path", b"/")]
    stops_per_packet = []
    decoder = pylsqpack.Decoder(0, 0)
    for rec in records:
        direction, pn = rec["direction"], rec["pn"]
        require(direction in ("tx", "rx"), "invalid direction")
        require(direction not in last or pn == last[direction] + 1, "trace packet gap/replay")
        last[direction] = pn
        stops = 0
        for ty, v in frames(bytes.fromhex(rec["hex"])):
            if direction == "tx":
                if 8 <= ty <= 15 and v[0] % 4 == 0:
                    sid, offset, fin, data = v
                    require(sid not in streams and offset == 0 and fin, "invalid request stream")
                    require(sid == len(streams)*4, "omitted request ID")
                    body = Buffer(data=data)
                    require(body.pull_uint_var() == 1, "missing HTTP headers")
                    headers = body.pull_bytes(body.pull_uint_var())
                    require(body.eof(), "unexpected request bytes")
                    blocked, decoded = decoder.feed_header(sid, headers)
                    require(not blocked and decoded == request_headers, "wrong QPACK request")
                    streams[sid] = dict(response=None, stop=None, reset=None, done=False)
                elif ty == 5:
                    sid, error = v
                    require(sid in streams and streams[sid]["response"] is not None, "stop before response")
                    st = streams[sid]
                    if not st["done"] and st["stop"] is None:
                        st["stop"] = error
                    stops += 1
                elif ty == 2:
                    for st in streams.values():
                        target = st["reset"] if st["stop"] is not None else st["response"]
                        if target is not None and not st["done"] and any(lo <= target <= hi for lo, hi in v):
                            st["done"] = True
                            completed += 1
                else:
                    require(ty in (0, 1) or (8 <= ty <= 15 and v[0] in (2, 6, 10)),
                            "unexpected client output")
            else:
                if 8 <= ty <= 15 and v[0] % 4 == 0:
                    sid, offset, fin, data = v
                    require(sid in streams, "unsolicited response")
                    st = streams[sid]
                    require(st["response"] is None and st["stop"] is None, "duplicate/cancelled response")
                    require(offset == 0 and fin and data == RESPONSE, "wrong HTTP response")
                    st["response"] = pn
                elif ty == 4:
                    sid, error, size = v
                    require(sid in streams, "unsolicited reset")
                    st = streams[sid]
                    require(not st["done"] and st["stop"] is not None, "unexpected reset")
                    require(st["reset"] is None, "duplicate reset")
                    require(error == st["stop"] == ERROR and size == len(RESPONSE), "corrupt reset")
                    st["reset"] = pn
                    reset_ids.add(sid)
                elif ty == 0x12:
                    require(v[0] == report["initial_stream_limit"] + completed, "wrong exact credit")
                    require(v[0] >= advertised, "credit decreased")
                    advertised = v[0]
                else:
                    require(ty in (0, 1, 2, 0x10, 0x13, 0x1e) or
                            (8 <= ty <= 15 and v == (3, 0, False, b"\0\4\0")),
                            "unexpected server output")
        if stops:
            require(stops <= report["stop_batch"], "too many stops in packet")
            stops_per_packet.append(stops)
    require(len(streams) == completed == report["responses"], "uncompleted/missing responses or resets")
    require(len(reset_ids) == report["resets"], "missing resets")
    require(all(st["response"] is not None and st["done"] and
                (st["stop"] is None or st["reset"] is not None) for st in streams.values()),
            "leftover stream state")
    require(advertised == report["advertised_stream_limit"], "wrong final credit")
    expected_stops = (len(report["cycles"])+1)*report["cancellations"]
    if report["mode"] == "repeat":
        expected_stops *= 2
    require(sum(stops_per_packet) == expected_stops, "missing/duplicate stops")
    return dict(responses=len(streams), resets=len(reset_ids), packets=len(records),
                stops=sum(stops_per_packet), stop_packets=len(stops_per_packet),
                advertised_stream_limit=advertised)
