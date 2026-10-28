#!/usr/bin/env python3
"""Verify sparse receive ACK boundaries using independent protected wire probes."""

import argparse
import asyncio
import importlib.util
import json
import math
from pathlib import Path
import socket
import tempfile

from receive_ack import CASES, exercise
from quic_recovery import require

spec = importlib.util.spec_from_file_location(
    "recovery_runner", Path(__file__).with_name("quic-loss-check.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


async def run_case(binary, scenario, *, threads=1, timeout=10):
    report = dict(scenario=scenario, threads=threads, binary=str(binary),
                  readiness={}, workload={}, liveness={}, process={})
    server = None
    with tempfile.TemporaryFile(mode="w+b") as log:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            report["server_port"] = port
            server = await asyncio.create_subprocess_exec(
                str(binary), "--threads", str(threads), "--tcp", "0", "--quic", str(port),
                stdout=log, stderr=log)
            report["process"]["pid"] = server.pid
            await runner.guarded(runner.ready(port, report["readiness"]), server, timeout)
            await runner.guarded(exercise(port, scenario, report["workload"]), server, timeout)
            await runner.guarded(runner.ready(port, report["liveness"]), server, timeout)
            require(report["readiness"].get("closed") and report["liveness"].get("closed"),
                    "readiness/liveness connection did not close")
            require(report["workload"].get("closed") and
                    report["workload"].get("transport_closed"), "workload did not close")
            report["passed"] = True
        except Exception as error:
            report["passed"] = False
            report["error"] = f"{type(error).__name__}: {error}"
        finally:
            if server is not None:
                await runner.stop_process(server, report["process"])
            log.seek(0)
            report["server_log"] = log.read().decode(errors="replace")
    return report


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=runner.executable)
    parser.add_argument("--scenario", choices=CASES)
    parser.add_argument("--threads", type=int, choices=(1, 2), default=1)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        parser.error("timeout must be in (0, 60]")
    return args


async def main(args):
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    for scenario in (args.scenario,) if args.scenario else CASES:
        report = await run_case(args.binary, scenario, threads=args.threads, timeout=args.timeout)
        if args.output:
            with (args.output / f"{scenario}.json").open("x") as out:
                json.dump(report, out, indent=2)
                out.write("\n")
        print(json.dumps(report if not report["passed"] else
                         dict(scenario=scenario, threads=args.threads, passed=True,
                              responses=len(report["workload"]["responses"]),
                              checked_acks=report["workload"]["checked_acks"])), flush=True)
        if not report["passed"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(arguments())))
