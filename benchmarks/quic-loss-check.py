#!/usr/bin/env python3
"""Bounded, untimed QUIC recovery checks with an independent response ledger.

Default: named deterministic impairments. --scenario seeded is exploration,
not a CI gate. See quic-recovery.md for trace/replay and coverage limitations.
"""

import argparse
import asyncio
import json
import math
import os
from pathlib import Path
import socket
import sys
import tempfile

from quic_recovery import SCENARIOS, Relay, connection, replay_plan, require


async def stop_process(process, report):
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), 1)
        except TimeoutError:
            process.kill()
            report["killed"] = True
            await asyncio.wait_for(process.wait(), 1)
    report["exit"] = process.returncode


async def guarded(work, process, timeout):
    task = asyncio.create_task(work)
    exited = asyncio.create_task(process.wait())
    try:
        done, _ = await asyncio.wait((task, exited), timeout=timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        require(exited not in done, f"server exited unexpectedly: {process.returncode}")
        if task not in done:
            raise TimeoutError(f"QUIC case deadline exceeded ({timeout}s)")
        return await task
    finally:
        for pending in (task, exited):
            if not pending.done():
                pending.cancel()
        await asyncio.gather(task, exited, return_exceptions=True)


async def ready(port, report):
    # An actual independent HTTP exchange proves UDP/TLS/HTTP readiness. A
    # port allocation or the server's early startup log does not prove it.
    async with connection(port, report) as client:
        await client.batch("GET", 1)
        await client.ping()
        client.check()
        report["responses"] = client.ledger.finish(1)
    client.check()


async def independent(port, relay, count, report):
    relay.arm("handshake")
    async with connection(port, report) as client:
        await client.ping()
        require(client._quic._handshake_confirmed, "handshake was not confirmed")
        relay.check()
        for method in ("GET", "POST"):
            relay.arm(method)
            await client.batch(method, count)
            # A post-batch PING fence processes delayed duplicate packets before
            # accepting the ledger or arming the next milestone.
            await client.ping()
            client.check()
            relay.check()
        report["responses"] = client.ledger.finish(count * 2)
        report["impairments"] = relay.finish()
        relay.arm("idle")
    client.check()


def validate_native(result, expected):
    requests = result["requests"]
    require(requests["total"] == expected and requests["ok"] == expected and
            requests["errors"] == 0 and requests["connectErrors"] == 0,
            "shb incomplete/error accounting")
    require(result["statusCodes"] == {"200": expected}, "shb wrong status accounting")
    require(result["protocol"] == "HTTP/3", "shb wrong protocol")


async def native(binary, port, relay, count, timeout, report):
    relay.arm("explore")
    command = [str(binary), "--http3", "-t", "1", "-c", "1", "-p", "16",
               "-n", str(count * 2), "--timeout", "2s", "-j",
               f"https://127.0.0.1:{port}/"]
    report["command"] = command
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        report["stderr"] = stderr.decode(errors="replace")
        require(process.returncode == 0, f"shb exited {process.returncode}")
        result = json.loads(stdout)
        report["native_report"] = result
        validate_native(result, count * 2)
        require(all(any(row["direction"] == direction for row in relay.trace)
                    for direction in ("client", "server")), "shb sent no bidirectional traffic")
        report["impairments"] = relay.finish()
        report["scope"] = "shb aggregate accounting only; no independent body ledger"
        relay.arm("idle")
    finally:
        await stop_process(process, report.setdefault("process", {}))


async def run_case(binary, scenario, *, threads=1, count=64, timeout=15,
                   seed=42, loss=0.05, shb=None, replay=None):
    report = dict(scenario=scenario, threads=threads, requests_per_method=count,
                  binary=str(binary), seed=seed, loss=loss,
                  readiness={}, workload={}, process={})
    server = transport = relay = None
    with tempfile.TemporaryFile(mode="w+b") as log:
        try:
            # Hold the server reservation while binding the relay so these two
            # ephemeral endpoints cannot accidentally select the same port.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
                transport, relay = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: Relay(("127.0.0.1", port), scenario, seed, loss, replay),
                    local_addr=("127.0.0.1", 0))
            relay_port = transport.get_extra_info("sockname")[1]
            report.update(server_port=port, relay_port=relay_port)
            command = [str(binary), "--threads", str(threads), "--tcp", "0",
                       "--quic", str(port)]
            report["command"] = command
            server = await asyncio.create_subprocess_exec(*command, stdout=log, stderr=log)
            report["process"]["pid"] = server.pid
            await guarded(ready(port, report["readiness"]), server, min(timeout, 5))
            work = (native(shb, relay_port, relay, count, timeout, report["workload"])
                    if shb else independent(relay_port, relay, count, report["workload"]))
            await guarded(work, server, timeout)
            require(report["readiness"].get("closed"), "readiness close did not complete")
            if not shb:
                require(report["workload"].get("closed"), "workload close did not complete")
            report["passed"] = True
        except Exception as error:
            report["passed"] = False
            report["error"] = f"{type(error).__name__}: {error}"
        finally:
            if server is not None:
                await stop_process(server, report["process"])
            if transport is not None:
                transport.close()
                await asyncio.wait_for(relay.closed.wait(), 1)
            if relay is not None:
                report["trace"] = relay.trace
                if relay.failure:
                    report["relay_error"] = str(relay.failure)
                    report["passed"] = False
            log.seek(0)
            report["server_log"] = log.read().decode(errors="replace")
    return report


def executable(value):
    path = Path(value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {path}")
    return path


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=executable)
    parser.add_argument("--scenario", choices=(*SCENARIOS, "seeded"))
    parser.add_argument("--threads", type=int, choices=(1, 2), default=1)
    parser.add_argument("--requests", type=int, default=64, help="requests per GET/POST batch")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--loss", type=float, default=0.05)
    parser.add_argument("--output", type=Path, help="new directory for complete JSON traces")
    parser.add_argument("--replay-trace", type=Path, help="replay a saved independent case")
    parser.add_argument("--shb", type=executable, help="explicit native client; aggregate checks only")
    args = parser.parse_args()
    if (args.requests < 2 or not math.isfinite(args.timeout) or args.timeout <= 0
            or not 0 <= args.loss < 1):
        parser.error("requests must be >=2, timeout >0, loss in [0,1)")
    if args.shb and (args.scenario not in ("clean", "seeded") or args.replay_trace):
        parser.error("--shb requires --scenario clean or seeded, without replay")
    if args.replay_trace and args.scenario:
        parser.error("--replay-trace and --scenario are mutually exclusive")
    return args


async def main(args):
    replay = None
    scenarios = [args.scenario] if args.scenario else SCENARIOS
    if args.replay_trace:
        saved = json.loads(args.replay_trace.read_text())
        require("native_report" not in saved["workload"], "native replay is unsupported")
        require(saved["requests_per_method"] == args.requests, "replay request count differs")
        replay = replay_plan(saved["trace"])
        scenarios = ["replay"]
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    for scenario in scenarios:
        report = await run_case(args.binary, scenario, threads=args.threads,
                                count=args.requests, timeout=args.timeout, seed=args.seed,
                                loss=args.loss, shb=args.shb, replay=replay)
        if args.output:
            with (args.output / f"{scenario}.json").open("x") as out:
                json.dump(report, out, indent=2)
                out.write("\n")
        if not report["passed"]:
            # Hosted CI retains the complete failure evidence even without artifacts.
            print(json.dumps(report), flush=True)
            return 1
        print(json.dumps(dict(scenario=scenario, threads=args.threads, passed=True,
                              completed=args.requests * 2,
                              independent=not bool(args.shb),
                              impairments=report["workload"]["impairments"],
                              datagrams=len(report["trace"]))), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(arguments())))
