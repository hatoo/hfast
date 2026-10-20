#!/usr/bin/env python3
"""Untimed native cancellation, wire-order and exact credit checks."""
import argparse
import json
from pathlib import Path

import stop_batch as s


def main(args):
    args.output.mkdir(parents=True)
    inputs = {k: s.sha(getattr(args, k)) for k in ("server", "peer")}
    cases = [
        (1024, 1, "plain"), (1024, 64, "plain"), (1024, 1024, "plain"),
        (65536, 1, "plain"), (65536, 64, "plain"), (65536, 1024, "plain"),
        (1024, 64, "repeat"), (1024, 64, "stop-ack"), (1024, 64, "ack-stop"),
    ]
    rows = []
    for window, cancellations, mode in cases:
        name = f"w{window}-k{cancellations}-{mode}"
        row = s.run(args.server, args.peer, args.output/name, window, cancellations,
                    32, 64, 2, mode, args.client_cpu)
        rows.append(row)
        print(name, row["responses"], row["resets"], "PASS", flush=True)
    s.require(inputs == {k: s.sha(getattr(args, k)) for k in inputs}, "binary changed")
    summary = dict(inputs=inputs, cases=len(rows), errors=0,
                   total_responses=sum(r["responses"] for r in rows),
                   total_resets=sum(r["resets"] for r in rows),
                   scope="correctness only; not performance confirmation")
    (args.output/"summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("server", "peer", "output"):
        p.add_argument(key, type=lambda x: Path(x).resolve())
    p.add_argument("--client-cpu", type=int, default=8)
    main(p.parse_args())
