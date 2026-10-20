#!/usr/bin/env python3
"""Compare complete cancellation cycles; run in an isolated network namespace."""
import argparse
import json
import os
from pathlib import Path
import statistics

import stop_batch as s


def main(args):
    s.require(args.pairs > 0, "pairs must be positive")
    s.require(not any(os.environ.get(k) for k in
                     ("LD_PRELOAD", "GRO_AUDIT_COUNTERS", "HFAST_GRO_PRELOAD", "STOP_BATCH_TRACE")),
              "instrumented timing environment")
    args.output.mkdir(parents=True)
    inputs = {k: s.sha(getattr(args, k)) for k in ("baseline", "candidate", "peer")}
    (args.output/"manifest.json").write_text(json.dumps(dict(
        inputs=inputs, args={k: str(v) if isinstance(v, Path) else v
                            for k, v in vars(args).items()}), indent=2)+"\n")
    rows, pairs = [], []
    for pair in range(args.pairs):
        order = ["baseline", "candidate"]
        if (pair + args.reverse) % 2:
            order.reverse()
        results = {}
        for variant in order:
            row = s.run(getattr(args, variant), args.peer, args.output/f"{pair}-{variant}",
                        args.window, args.cancellations, args.batch, args.stop_batch,
                        args.cycles, args.mode, args.client_cpu)
            row.update(variant=variant, pair=pair)
            rows.append(row)
            results[variant] = row
            print(json.dumps({k: row[k] for k in ("variant", "pair", "cycles_per_second",
                             "server_cpu_ns_per_response", "cancellation_seconds",
                             "measured_responses", "measured_resets")}), flush=True)
        b, c = results["baseline"], results["candidate"]
        for key in ("responses", "resets", "measured_responses", "measured_resets"):
            s.require(b[key] == c[key], f"mismatched {key}")
        pairs.append(dict(pair=pair,
            cycle_rate_percent=100*(c["cycles_per_second"]/b["cycles_per_second"]-1),
            cancellation_percent=100*(c["cancellation_seconds"]/b["cancellation_seconds"]-1),
            cpu_percent=(100*(c["server_cpu_ns_per_response"]/b["server_cpu_ns_per_response"]-1)
                         if b["server_cpu_ns_per_response"] else None)))
    s.require(inputs == {k: s.sha(getattr(args, k)) for k in inputs}, "input binary changed")
    summary = dict(inputs=inputs, pairs=pairs, reverse=args.reverse,
                   total_responses=sum(r["responses"] for r in rows),
                   total_resets=sum(r["resets"] for r in rows), errors=0)
    for name in ("cycle_rate_percent", "cancellation_percent", "cpu_percent"):
        values = [p[name] for p in pairs if p[name] is not None]
        summary["median_"+name] = statistics.median(values) if values else None
    (args.output/"results.json").write_text(json.dumps(rows, indent=2)+"\n")
    (args.output/"summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("baseline", "candidate", "peer", "output"):
        p.add_argument(key, type=lambda x: Path(x).resolve())
    p.add_argument("--window", type=int, default=65536)
    p.add_argument("--cancellations", type=int, default=1024)
    p.add_argument("--batch", type=int, default=32)
    p.add_argument("--stop-batch", type=int, default=64)
    p.add_argument("--cycles", type=int, default=64)
    p.add_argument("--pairs", type=int, default=3)
    p.add_argument("--client-cpu", type=int, default=8)
    p.add_argument("--mode", choices=["plain", "repeat", "stop-ack", "ack-stop"], default="plain")
    p.add_argument("--reverse", action="store_true")
    main(p.parse_args())
