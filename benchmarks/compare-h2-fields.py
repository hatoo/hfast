#!/usr/bin/env python3
"""Alternating immutable server comparisons with identical field-block workloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from h2_field_report import validate_report

CASES = {"16k-4k": (16384, 4096, 8192, 8),
         "16k-53": (16384, 53, 512, 8),
         "1m-4k": (1048576, 4096, 256, 8)}


def proc(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().split(") ")[1].split()
    stats = list(map(int, Path(f"/proc/{pid}/schedstat").read_text().split()))
    hz = os.sysconf("SC_CLK_TCK")
    return dict(user=int(fields[11]) / hz, system=int(fields[12]) / hz,
                runtime=stats[0] / 1e9, runqueue=stats[1] / 1e9)


def client(args, port, case, count, stem):
    size, chunk, _, connections = CASES[case]
    chunk = args.write_chunk or chunk
    connections = args.connections or connections
    cpu_file = args.output / (stem + "-client-cpu.txt")
    cmd = ["/usr/bin/time", "-o", str(cpu_file), "-f", "%U %S %e %M",
           "taskset", "-c", str(args.client_cpu), str(args.peer), str(port),
           str(size), str(chunk), str(count), str(connections), str(args.pipeline)]
    with (args.output / (stem + ".json")).open("x") as out, (args.output / (stem + ".stderr")).open("x") as err:
        run = subprocess.run(cmd, stdout=out, stderr=err, timeout=180)
    assert run.returncode == 0, (stem, run.returncode)
    result = json.loads((args.output / (stem + ".json")).read_text())
    validate_report(result, size, chunk, count, connections, args.pipeline)
    samples = sorted(result.pop("latencies_ns"))
    result["quantiles_ns"] = {str(p): samples[min(len(samples) - 1, int(p * len(samples)))]
                              for p in [.5, .9, .99, .999, 1.]}
    result["client_cpu"] = dict(zip(["user", "system", "wall", "maxrss_kb"],
                                    map(float, cpu_file.read_text().split())))
    result["command"] = cmd
    return result


def run(args, variant, case, count, stem):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    cmd = [str(getattr(args, variant)), "--threads", "1", "--tcp", str(port), "--quic", "0"]
    with (args.output / (stem + "-server.log")).open("x") as log:
        server = subprocess.Popen(cmd, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert server.poll() is None
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline
                    time.sleep(.01)
            ready = client(args, port, case, 1, stem + "-ready")
            os.sched_setaffinity(server.pid, {args.server_cpu})
            warm = client(args, port, case, max(16, args.pipeline + 3), stem + "-warm")
            time.sleep(.02)
            before = proc(server.pid)
            result = client(args, port, case, count, stem)
            time.sleep(.02)
            after = proc(server.pid)
            assert server.poll() is None and os.sched_getaffinity(server.pid) == {args.server_cpu}
        finally:
            server.terminate()
            server.wait(timeout=5)
    result.update(variant=variant, case=case, readiness=ready, warmup=warm,
                  server_command=cmd, server_cpu={k: after[k] - before[k] for k in before})
    result["cpu_ns_per_request"] = result["server_cpu"]["runtime"] * 1e9 / result["requests"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["baseline", "candidate", "peer", "output"]:
        parser.add_argument(name, type=lambda value: Path(value).resolve())
    parser.add_argument("--server-cpu", type=int, default=1)
    parser.add_argument("--client-cpu", type=int, default=8)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--pipeline", type=int, default=1)
    parser.add_argument("--write-chunk", type=int)
    parser.add_argument("--requests", type=int, help="requests per connection")
    parser.add_argument("--connections", type=int)
    parser.add_argument("--cases", nargs="+", default=list(CASES), choices=list(CASES))
    args = parser.parse_args()
    assert args.pairs > 0 and 1 <= args.pipeline <= 64
    assert all(value is None or value > 0 for value in [args.write_chunk, args.requests, args.connections])
    assert "LD_PRELOAD" not in os.environ
    assert {args.server_cpu, args.client_cpu} <= os.sched_getaffinity(0)
    args.output.mkdir(exist_ok=False)
    binaries = {name: getattr(args, name) for name in ["baseline", "candidate", "peer"]}
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    (args.output / "manifest.json").write_text(json.dumps(dict(hashes=hashes, cases=CASES,
        options={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}), indent=2))
    rows = []
    for pair in range(args.pairs):
        for i, case in enumerate(args.cases):
            order = ["baseline", "candidate"]
            if (pair + i + args.reverse) % 2:
                order.reverse()
            paired = {}
            for variant in order:
                count = args.requests or (args.pipeline + 3 if args.smoke else CASES[case][2])
                result = run(args, variant, case, count, f"{pair}-{case}-{variant}")
                result["pair"] = pair
                rows.append(result)
                paired[variant] = result
                print(json.dumps({k: result[k] for k in
                    ["variant", "case", "requests", "rps", "cpu_ns_per_request", "quantiles_ns"]}), flush=True)
            for key in ["requests", "sent_bytes", "received_bytes", "application_writes", "peers"]:
                assert paired["baseline"][key] == paired["candidate"][key], (case, key)
    assert hashes == {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    (args.output / "summary.json").write_text(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
