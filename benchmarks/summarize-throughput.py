#!/usr/bin/env python3
"""Summarize raw shb measurements without running any new benchmarks."""

import json
import statistics
import sys
from collections import defaultdict

groups = defaultdict(list)
for path in sys.argv[1:]:
    with open(path) as source:
        for line in source:
            run = json.loads(line)
            key = (run["binary"], run["proto"], run.get("st", 1), run["ct"])
            groups[key].append(run)
print(
    "| Binary | Protocol | Server/client workers | Runs | Median req/s | Range | CPU µs/req | Errors |"
)
print("|---|---|---:|---:|---:|---|---:|---:|")
for (binary, protocol, server, client), runs in groups.items():
    rates = [run["rps"] for run in runs]
    errors = sum(run["report"]["requests"]["errors"] for run in runs)
    print(
        f"| {binary} | {protocol} | {server}/{client} | {len(runs)} | "
        f"{statistics.median(rates):,.0f} | {min(rates):,.0f}–{max(rates):,.0f} | "
        f'{statistics.median(run["cpu_us"] for run in runs):.3f} | {errors} |'
    )
