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


def main(args):
    args.output.mkdir(parents=True)
    rows = []
    for mode in ("plain", "repeat", "stop-ack", "ack-stop"):
        out = args.output/mode
        report = s.run(args.server, args.peer, out, 1024, 64, 32, 64, 1, mode,
                       args.client_cpu, trace=True)
        records = [json.loads(line) for line in (out/"wire.jsonl").read_text().splitlines()]
        row = verify(records, report)
        if report["resets"]:
            row["negative_oracles"] = negative_oracles(records, report)
        row["mode"] = mode
        rows.append(row)
        print(json.dumps(row), flush=True)
    (args.output/"summary.json").write_text(json.dumps(rows, indent=2)+"\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("server", "peer", "output"):
        p.add_argument(key, type=lambda x: Path(x).resolve())
    p.add_argument("--client-cpu", type=int, default=8)
    main(p.parse_args())
