#!/usr/bin/env python3
"""Run untimed native traces, independently decode them, and corrupt each oracle."""
import argparse
import copy
import json
from pathlib import Path

from aioquic.buffer import Buffer
import stop_batch as s
from stop_batch_wire import frames, verify


def negative_oracles(records, report):
    def rejected(mutated):
        try:
            verify(mutated, report)
        except (ValueError, KeyError, AssertionError):
            return
        raise ValueError("corrupted transcript passed independent oracle")

    reset_index = next(i for i, r in enumerate(records) if r["direction"] == "rx" and
                       any(ty == 4 for ty, _ in frames(bytes.fromhex(r["hex"]))))
    sid, error, size = next(v for ty, v in frames(bytes.fromhex(records[reset_index]["hex"])) if ty == 4)
    cases = []
    for change in ("missing", "duplicate", "wrong-error", "wrong-size", "unexpected"):
        damaged = copy.deepcopy(records)
        buf = Buffer(capacity=1200)
        for ty, values in frames(bytes.fromhex(damaged[reset_index]["hex"])):
            if ty == 4 and values[0] == sid:
                if change == "missing":
                    continue
                if change == "wrong-error":
                    values = (sid, error+1, size)
                if change == "wrong-size":
                    values = (sid, error, size+1)
                if change == "unexpected":
                    values = (sid+1, error, size)
                for _ in range(2 if change == "duplicate" else 1):
                    buf.push_uint_var(4)
                    for v in values:
                        buf.push_uint_var(v)
            elif ty == 2:
                buf.push_uint_var(2)
                buf.push_uint_var(values[0][1])
                buf.push_uint_var(0)
                buf.push_uint_var(len(values)-1)
                buf.push_uint_var(values[0][1]-values[0][0])
                for (prev_lo, _), (lo, hi) in zip(values, values[1:]):
                    buf.push_uint_var(prev_lo-hi-2)
                    buf.push_uint_var(hi-lo)
            elif ty in (0, 1, 0x1e, 4, 0x10, 0x12, 0x13):
                buf.push_uint_var(ty)
                for v in values:
                    buf.push_uint_var(v)
            else:
                raise ValueError("unexpected frame in reset packet mutation")
        damaged[reset_index]["hex"] = buf.data.hex()
        rejected(damaged)
        cases.append(change)
    damaged = copy.deepcopy(report)
    damaged["advertised_stream_limit"] += 1
    try:
        verify(records, damaged)
    except ValueError:
        cases.append("wrong-credit")
    else:
        raise ValueError("wrong credit accepted")
    return cases


def encode(values):
    """Independent aioquic frame writer used only to damage known-good traces."""
    buf = Buffer(capacity=65536)
    for ty, v in values:
        if 8 <= ty <= 15:
            sid, offset, fin, data = v
            buf.push_uint_var(0x0e | int(fin))
            for n in (sid, offset, len(data)):
                buf.push_uint_var(n)
            buf.push_bytes(data)
        elif ty == 2:
            buf.push_uint_var(2)
            for n in (v[0][1], 0, len(v)-1, v[0][1]-v[0][0]):
                buf.push_uint_var(n)
            for (prev, _), (lo, hi) in zip(v, v[1:]):
                buf.push_uint_var(prev-hi-2)
                buf.push_uint_var(hi-lo)
        else:
            buf.push_uint_var(ty)
            for n in v:
                buf.push_uint_var(n)
    return buf.data.hex()


def unsent_negative_oracles(records, report):
    cases = negative_oracles(records, report)
    decoded = [list(frames(bytes.fromhex(r["hex"]))) for r in records]
    first_stop = next(i for i, fs in enumerate(decoded) if records[i]["direction"] == "tx" and any(t == 5 for t, _ in fs))
    first_target = next(i for i, fs in enumerate(decoded) if records[i]["direction"] == "tx" and
                        any(8 <= t <= 15 and v[0] % 4 == 0 and not v[2] for t, v in fs))
    first_reset = next(i for i, fs in enumerate(decoded) if records[i]["direction"] == "rx" and any(t == 4 for t, _ in fs))
    final_reset_ack = next(i for i in range(first_reset+1, len(records)) if records[i]["direction"] == "tx" and any(t == 2 for t, _ in decoded[i]))
    last_rx = max(i for i, r in enumerate(records) if r["direction"] == "rx")
    creation_ack = max(i for i in range(first_stop) if records[i]["direction"] == "rx")
    sid = next(v[0] for t, v in decoded[first_stop] if t == 5)
    last_before_stop = records[creation_ack]["pn"]
    mutations = {
        "request-fin": (first_target, [(t, (v[0], v[1], True, v[3])) if 8 <= t <= 15 else (t, v) for t, v in decoded[first_target]]),
        "missing-receive-reset": (first_stop, [(t, v) for t, v in decoded[first_stop] if t != 4 or v[0] != sid]),
        "wrong-receive-final-size": (first_stop, [(t, (v[0], v[1], v[2]+1)) if t == 4 and v[0] == sid else (t, v) for t, v in decoded[first_stop]]),
        "missing-stop": (first_stop, [(t, v) for t, v in decoded[first_stop] if t != 5 or v[0] != sid]),
        "early-retirement": (first_stop, [(2, [(0, last_before_stop)])] + decoded[first_stop]),
        "missing-request-fence": (creation_ack, [(t, v) for t, v in decoded[creation_ack] if t != 2]),
        "missing-final-fence": (last_rx, [(t, v) for t, v in decoded[last_rx] if t != 2]),
        "late-reset-ack": (final_reset_ack, [(t, [(0, v[0][1]-1)]) if t == 2 else (t, v) for t, v in decoded[final_reset_ack]]),
        "target-response": (first_reset, decoded[first_reset]+[(0x0f, (sid, 0, True, b"unexpected"))]),
    }
    for name, (index, values) in mutations.items():
        damaged = copy.deepcopy(records)
        damaged[index]["hex"] = encode(values)
        try:
            verify(damaged, report)
        except (ValueError, KeyError, AssertionError):
            cases.append(name)
        else:
            raise ValueError(f"unsent transcript fault passed: {name}")
    return cases


def main(args):
    args.output.mkdir(parents=True)
    rows = []
    cases = [(mode, 1024, 64) for mode in ("plain", "repeat", "stop-ack", "ack-stop")]
    cases += [("unsent", 512, 128), ("unsent", 4096, 1024)]
    for mode, window, cancellations in cases:
        name = f"unsent-w{window}" if mode == "unsent" else mode
        out = args.output/name
        report = s.run(args.server, args.peer, out, window, cancellations, 32, 64, 1, mode,
                       args.client_cpu, trace=True, warmup_cycles=2 if mode == "unsent" else 1)
        records = [json.loads(line) for line in (out/"wire.jsonl").read_text().splitlines()]
        row = verify(records, report)
        if report["resets"]:
            row["negative_oracles"] = (unsent_negative_oracles if mode == "unsent" else negative_oracles)(records, report)
        row["mode"] = mode
        row["window"] = window
        rows.append(row)
        print(json.dumps(row), flush=True)
    (args.output/"summary.json").write_text(json.dumps(rows, indent=2)+"\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("server", "peer", "output"):
        p.add_argument(key, type=lambda x: Path(x).resolve())
    p.add_argument("--client-cpu", type=int, default=8)
    main(p.parse_args())
