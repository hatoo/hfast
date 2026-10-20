"""Exact accounting and immutable execution for the native cancellation peer."""
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import time


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prime_batches(window, batch):
    require(1 <= batch <= 32 and window >= 64 and window % batch == 0, "invalid window/batch")
    # B sent batches minus one retired batch at every nonzero multiple of 64.
    count = window // batch
    while count - (count - 1) // 64 != window // batch:
        count += 1
    return count


def validate(report, window, cancellations, batch, stop_batch, cycles, mode):
    require(mode in ("plain", "repeat", "stop-ack", "ack-stop"), "invalid mode")
    require(0 < cancellations <= window and window % cancellations == 0, "invalid cancellations")
    require(1 <= stop_batch <= 64 and cycles > 0, "invalid stop batch/cycles")
    require(mode not in ("stop-ack", "ack-stop") or cancellations <= stop_batch,
            "frame order must fit one packet")
    for key, value in dict(window=window, cancellations=cancellations, batch=batch,
                           stop_batch=stop_batch, mode=mode).items():
        require(report[key] == value, f"wrong {key}")
    for key in ("errors", "unexpected_packets", "duplicate_responses", "duplicate_resets"):
        require(report[key] == 0, key)
    require(len(report["cycles"]) == cycles, "missing or extra cycles")
    nb = prime_batches(window, batch)
    nc = (cancellations + stop_batch - 1) // stop_batch
    expected_resets = 0 if mode == "ack-stop" else cancellations
    responses = nb * batch + 1
    packets = nb + nc + 3 + (nc if mode == "repeat" else 0)
    initial = 2 * window
    require(report["initial_stream_limit"] == initial, "initial credit")
    total = 0
    advertised = initial

    def update_credit(completed):
        nonlocal advertised
        if initial + completed - advertised >= window:
            advertised = initial + completed
        return advertised

    for row in [report["warmup"], *report["cycles"]]:
        update_credit(total + responses - 1 - window)
        total += responses
        for key, value in dict(responses=responses, resets=expected_resets, window=window,
                               survivors=window-expected_resets, prime_responses=responses-1,
                               followup_responses=1, sent_packets=packets,
                               received_packets=packets, leftover_datagrams=0,
                               outstanding_responses=0, outstanding_resets=0).items():
            require(row[key] == value, f"cycle {key}: {row[key]} != {value}")
        before = total - 1 - (cancellations if mode == "stop-ack" else
                              0 if mode == "ack-stop" else window)
        require(row["completed_before_reset_ack"] == before, "wrong completed count before reset ACK")
        require(row["credit_before_reset_ack"] == update_credit(before), "early/late reset completion")
        update_credit(total - 1)
        require(row["advertised_stream_limit"] == update_credit(total), "cycle exact stream credit")
        require(row["unadvertised_credit"] == initial + total - advertised, "wrong unadvertised credit")
        for key in ("seconds", "cancellation_seconds", "server_cpu_seconds"):
            require(math.isfinite(row[key]) and row[key] >= 0, f"invalid {key}")
        require(0 < row["cancellation_seconds"] < row["seconds"], "invalid cycle duration")
    require(report["responses"] == total, "wrong total responses")
    require(report["resets"] == (cycles+1)*expected_resets, "wrong total resets")
    require(report["advertised_stream_limit"] == advertised, "wrong final credit")
    return report


def udp():
    lines = Path("/proc/net/snmp").read_text().splitlines()
    for keys, values in zip(lines, lines[1:]):
        if keys.startswith("Udp:") and values.startswith("Udp:"):
            return dict(zip(keys.split()[1:], map(int, values.split()[1:])))
    raise ValueError("missing UDP counters")


def validate_udp(before, after):
    delta = {k: after[k] - v for k, v in before.items()}
    for key in ("InErrors", "RcvbufErrors", "SndbufErrors", "InCsumErrors", "NoPorts"):
        require(delta[key] == 0, f"UDP {key}: {delta[key]}")
    require(delta["InDatagrams"] == delta["OutDatagrams"], "unreceived UDP datagrams")
    return delta


def run(server_binary, peer, output, window, cancellations, batch, stop_batch, cycles,
        mode, client_cpu, trace=False):
    output.mkdir(parents=True)  # Never overwrite an earlier run.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server_command = [str(server_binary), "--tcp", "0", "--quic", str(port),
                      "--threads", "1", "--max-streams", str(2*window)]
    before = udp()
    with (output / "server.log").open("x") as log:
        server = subprocess.Popen(server_command, stdout=log, stderr=log)
        try:
            time.sleep(.2)
            require(server.poll() is None, "server failed to start")
            command = ["/usr/bin/time", "-o", str(output / "peer-cpu.txt"), "-f", "%U %S %e %M",
                       "taskset", "-c", str(client_cpu), str(peer), str(port), str(server.pid),
                       str(window), str(cancellations), str(batch), str(stop_batch),
                       str(cycles), mode]
            (output / "commands.json").write_text(json.dumps(
                dict(server=server_command, peer=command), indent=2) + "\n")
            env = dict(os.environ)
            require("STOP_BATCH_TRACE" not in env, "unexpected transcript environment")
            if trace:
                env["STOP_BATCH_TRACE"] = str(output / "wire.jsonl")
            result = subprocess.run(command, capture_output=True, text=True, timeout=240, env=env)
            (output / "stdout").write_text(result.stdout)
            (output / "stderr").write_text(result.stderr)
            require(result.returncode == 0, f"peer failed: {result.stderr}")
            report = validate(json.loads(result.stdout), window, cancellations, batch,
                              stop_batch, cycles, mode)
            require(server.poll() is None, "server exited during run")
            delta = validate_udp(before, udp())
        finally:
            server.terminate()
            server.wait(timeout=5)
    measured = report["cycles"]
    seconds = sum(row["seconds"] for row in measured)
    responses = sum(row["responses"] for row in measured)
    report.update(udp_delta=delta, measured_responses=responses,
                  measured_resets=sum(row["resets"] for row in measured),
                  seconds=seconds, cycles_per_second=cycles/seconds,
                  responses_per_second=responses/seconds,
                  server_cpu_ns_per_response=sum(row["server_cpu_seconds"] for row in measured)
                  * 1e9 / responses,
                  cancellation_seconds=sum(row["cancellation_seconds"] for row in measured)/cycles,
                  command=command, server_command=server_command)
    (output / "report.json").write_text(json.dumps(report, indent=2)+"\n")
    return report
