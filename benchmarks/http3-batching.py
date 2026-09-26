#!/usr/bin/env python3
"""Compare two hfast release binaries using shb on Linux.

Example: python3 benchmarks/http3-batching.py /tmp/hfast-before \
    target/release/hfast ../shb/target/release/shb > results.jsonl
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    return (int(fields[13]) + int(fields[14])) / os.sysconf("SC_CLK_TCK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("shb", type=Path)
    parser.add_argument("--duration", default="3s")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--client-cpus", default="8-31")
    parser.add_argument("--port", type=int, default=18443)
    args = parser.parse_args()
    # (server workers, client workers, connections, streams per connection)
    configs = [(1, 1, 1, 1), (1, 4, 16, 16), (1, 4, 16, 64),
               (1, 4, 16, 128), (4, 8, 32, 32)]
    for rep in range(args.runs):
        for st, ct, connections, streams in configs:
            order = ["before", "after"] if rep % 2 == 0 else ["after", "before"]
            for name in order:
                server = subprocess.Popen([
                    str(getattr(args, name).resolve()), "--tcp", "0",
                    "--quic", str(args.port), "--threads", str(st),
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    time.sleep(0.15)
                    if server.poll() is not None:
                        raise RuntimeError("hfast exited during startup")
                    cmd = ["taskset", "-c", args.client_cpus, str(args.shb.resolve()),
                           "--http3", "-t", str(ct), "-c", str(connections),
                           "-p", str(streams), "-j", "--timeout", "2s",
                           f"https://127.0.0.1:{args.port}/", "-z", args.duration]
                    cpu = cpu_seconds(server.pid)
                    run = subprocess.run(cmd, capture_output=True, check=True)
                    cpu = cpu_seconds(server.pid) - cpu
                    report = json.loads(run.stdout)
                    completed = report["requests"]["ok"]
                    print(json.dumps(dict(
                        rep=rep, name=name, st=st, ct=ct, c=connections, p=streams,
                        rps=report["requestsPerSec"],
                        cpu_us=cpu * 1e6 / completed if completed else None,
                        errors=report["requests"]["errors"], report=report,
                    )), flush=True)
                finally:
                    server.terminate()
                    server.wait()


if __name__ == "__main__":
    main()
