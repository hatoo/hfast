"""Independent aioquic/pylsqpack decoding of the native peer's plaintext trace.

This checks wire semantics after authentication, not an independent TLS audit.
Both loss-free workloads require exact application and transport retirement.
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
    if report["mode"] == "unsent":
        return verify_unsent(records, report)
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


def verify_unsent(records, report):
    """Reconstruct occupancy and both stream directions from authenticated frames.

    This deliberately does not use the native peer's response/reset counters to
    determine completion. ACKs retire only the exact observed response/reset PN.
    """
    from collections import deque

    streams, last, sent = {}, {}, set()
    pending_responses = deque()
    decoder = pylsqpack.Decoder(0, 0)
    headers = [(b":method", b"GET"), (b":scheme", b"https"),
               (b":authority", b"localhost"), (b":path", b"/")]
    advertised = report["initial_stream_limit"]
    completed = response_count = reset_count = request_bytes = 0
    acked = -1
    last_ping = None
    group = None
    groups = []
    counts = dict(tx=0, rx=0)

    def covered(pn, ranges):
        return pn is not None and any(lo <= pn <= hi for lo, hi in ranges)

    def live_responses():
        return {sid for sid, st in streams.items() if st["fin"] and not st["done"]}

    for rec in records:
        direction, pn = rec["direction"], rec["pn"]
        require(direction in ("tx", "rx"), "invalid direction")
        require(direction not in last or pn == last[direction]+1, "trace packet gap/replay")
        last[direction] = pn
        counts[direction] += 1
        parsed = list(frames(bytes.fromhex(rec["hex"])))
        if direction == "tx":
            sent.add(pn)
            if parsed == [(1, ())]:
                last_ping = pn
        stops = 0
        for ty, v in parsed:
            if direction == "tx":
                if 8 <= ty <= 15 and v[0] % 4 == 0:
                    sid, offset, fin, data = v
                    require(sid == 4*len(streams) and offset == 0, "missing/duplicate request ID")
                    require(sid//4 < advertised, "request exceeds stream credit")
                    body = Buffer(data=data)
                    require(body.pull_uint_var() == 1, "missing request HEADERS")
                    block = body.pull_bytes(body.pull_uint_var())
                    require(body.eof(), "extra request bytes")
                    blocked, decoded = decoder.feed_header(sid, block)
                    require(not blocked and decoded == headers, "wrong QPACK request")
                    if not fin:
                        if group is None:
                            require(last_ping is not None and acked >= last_ping,
                                    "missing authenticated priming fence")
                            live = live_responses()
                            require(len(live) == report["window"] and not pending_responses,
                                    "wrong live response window")
                            group = dict(live=live, targets=[], resets=set(), stopping=False,
                                         last_stop=None)
                        require(not group["stopping"] and live_responses() == group["live"],
                                "request creation after stop or changed live window")
                        group["targets"].append(sid)
                    else:
                        require(group is None, "followup before complete cancellation ACK")
                        # hfast sends each request packet's answers newest
                        # first. Preserve that baseline order as well as bytes.
                        pending_responses.appendleft(sid)
                    streams[sid] = dict(fin=fin, request_pn=pn, size=len(data), response=None,
                                        stop=None, receive_reset=None, reset=None, done=False)
                    request_bytes += len(data)
                elif ty == 5:
                    sid, error = v
                    require(group is not None and sid in group["targets"], "unexpected stop target")
                    require(len(group["targets"]) == report["cancellations"], "missing unsent requests")
                    require(live_responses() == group["live"], "early response retirement")
                    require(all(acked >= streams[x]["request_pn"] for x in group["targets"]),
                            "stop before authenticated request processing fence")
                    st = streams[sid]
                    require(not st["fin"] and st["response"] is None and st["stop"] is None,
                            "sent or duplicate cancellation")
                    require(error == ERROR, "wrong stop error")
                    st["stop"] = error
                    group["stopping"] = True
                    group["last_stop"] = pn
                    stops += 1
                elif ty == 4:
                    sid, error, size = v
                    require(sid in streams, "unsolicited receive reset")
                    st = streams[sid]
                    require(not st["fin"] and st["stop"] == ERROR and st["receive_reset"] is None,
                            "missing stop or duplicate receive reset")
                    require(error == ERROR and size == st["size"], "wrong receive final size")
                    st["receive_reset"] = pn
                elif ty == 2:
                    require(v == [(0, last.get("rx"))] or group is None,
                            "partial/late cancellation ACK")
                    if group is not None:
                        require(group["stopping"] and len(group["resets"]) == report["cancellations"],
                                "early cancellation ACK")
                        require(acked >= group["last_stop"], "missing cancellation processing fence")
                        require(live_responses() == group["live"], "changed survivor window")
                        require(all(covered(streams[sid]["response"], v) for sid in group["live"]),
                                "missing survivor ACK")
                        require(all(streams[sid]["receive_reset"] is not None and
                                    covered(streams[sid]["reset"], v) for sid in group["targets"]),
                                "missing receive completion/reset ACK")
                        groups.append(dict(survivors=len(group["live"]), cancellations=len(group["targets"])))
                        group = None
                    for st in streams.values():
                        target = st["response"] if st["fin"] else st["reset"]
                        if not st["done"] and covered(target, v):
                            require(st["fin"] or st["receive_reset"] is not None,
                                    "retired before receive completion")
                            st["done"] = True
                            completed += 1
                else:
                    require(ty in (0, 1) or (8 <= ty <= 15 and v[0] in (2, 6, 10)),
                            "unexpected client frame")
            else:
                if 8 <= ty <= 15 and v[0] % 4 == 0:
                    sid, offset, fin, data = v
                    require(sid in streams and streams[sid]["fin"], "response on unsent/unknown stream")
                    st = streams[sid]
                    require(st["response"] is None and pending_responses and pending_responses.popleft() == sid,
                            "missing/duplicate/reordered response")
                    require(offset == 0 and fin and data == RESPONSE, "wrong survivor bytes/FIN")
                    st["response"] = pn
                    response_count += 1
                elif ty == 4:
                    sid, error, size = v
                    require(group is not None and sid in group["targets"], "unexpected reset")
                    st = streams[sid]
                    require(st["stop"] == ERROR and st["receive_reset"] is not None and not st["done"],
                            "reset before cancellation")
                    require(st["reset"] is None and error == ERROR and size == 0,
                            "duplicate or corrupt unsent reset")
                    st["reset"] = pn
                    group["resets"].add(sid)
                    reset_count += 1
                elif ty == 2:
                    require(len(v) == 1 and v[0][0] == 0 and v[0][1] in sent,
                            "server ACK omits or invents client packet")
                    acked = max(acked, v[0][1])
                elif ty == 0x12:
                    require(v[0] == report["initial_stream_limit"]+completed and v[0] > advertised,
                            "early/late/duplicate stream credit")
                    advertised = v[0]
                else:
                    require(ty in (0, 1, 0x10, 0x13, 0x1e) or
                            (8 <= ty <= 15 and v == (3, 0, False, b"\0\4\0")),
                            "unexpected server frame")
        if stops:
            require(stops <= report["stop_batch"], "too many stops in packet")
    require(group is None and not pending_responses and all(st["done"] for st in streams.values()),
            "leftover response/reset/receive state")
    require(acked == max(sent), "missing final processing ACK")
    require(len(groups) == len(report["cycles"])+report["warmup_cycles"], "wrong cancellation cycle count")
    require(response_count == report["responses"] and reset_count == report["resets"] == report["cancelled_requests"],
            "missing response or cancellation")
    require(len(streams) == completed == report["retired_streams"], "wrong stream retirement")
    require(request_bytes == report["request_bytes"], "wrong request bytes")
    require(advertised == report["advertised_stream_limit"], "wrong final credit")
    for direction, field in (("tx", "sent_packets"), ("rx", "received_packets")):
        require(counts[direction] == 2 + sum(r[field] for r in [report["warmup"], *report["extra_warmup"], *report["cycles"]]),
                "missing/extra transcript packet")
    return dict(responses=response_count, cancelled_requests=reset_count, resets=reset_count,
                retired_streams=completed, packets=len(records), request_bytes=request_bytes,
                advertised_stream_limit=advertised, windows=groups)
