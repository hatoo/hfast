#!/usr/bin/env python3
"""Pinned shb measurements; never builds or modifies shb."""

import argparse, json, os, subprocess, time, statistics
from pathlib import Path

CPUS = os.environ.get("HFAST_BENCH_CLIENT_CPUS", "8,10,12,14,16,18,20,22,24,26,28,30")
SHB = "/home/hatoo/shb/target/release/shb"


def cpu(pid):
    s = Path(f"/proc/{pid}/stat").read_text().split()
    return (int(s[13]) + int(s[14])) / os.sysconf("SC_CLK_TCK")


def measure(
    binary,
    proto,
    threads=8,
    duration="5s",
    profile=None,
    correct=False,
    server_workers=1,
):
    port = 18083 if proto != "h3" else 18443
    args = [
        str(Path(binary).resolve()),
        "--threads",
        str(server_workers),
        "--tcp",
        str(port if proto != "h3" else 0),
        "--quic",
        str(port if proto == "h3" else 0),
    ]
    server_cpus = set(range(0, server_workers * 2, 2))
    server = subprocess.Popen(
        ["taskset", "-c", ",".join(map(str, sorted(server_cpus)))] + args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    prof = None
    try:
        time.sleep(0.2)
        assert server.poll() is None
        # Existing hfast pins workers by logical index. Map those workers onto
        # separate physical cores identically for original and modified binaries.
        for tid in Path(f"/proc/{server.pid}/task").iterdir():
            assigned = os.sched_getaffinity(int(tid.name))
            if len(assigned) == 1 and min(assigned) < server_workers:
                os.sched_setaffinity(int(tid.name), {min(assigned) * 2})
        affinity = {
            tid.name: sorted(os.sched_getaffinity(int(tid.name)))
            for tid in Path(f"/proc/{server.pid}/task").iterdir()
        }
        assert all(set(v) <= server_cpus for v in affinity.values()), affinity
        cmd = [
            "taskset",
            "-c",
            CPUS,
            SHB,
            "-t",
            str(threads),
            "-c",
            (
                os.environ.get("HFAST_BENCH_H1_CONNECTIONS", "128")
                if proto == "h1"
                else os.environ.get("HFAST_BENCH_CONNECTIONS", "16")
            ),
            "--batch-linger",
            "1",
            "--timeout",
            "2s",
            "-j",
        ]
        if proto != "h1":
            cmd += [
                "--http2" if proto == "h2" else "--http3",
                "-p",
                os.environ.get("HFAST_BENCH_STREAMS", "128"),
            ]
        cmd += [
            (
                "https://127.0.0.1:" + str(port) + "/"
                if proto == "h3"
                else "http://127.0.0.1:" + str(port) + "/"
            )
        ]
        if correct:
            cmd += ["-n", "3000", "-d", "test body"]
        else:
            cmd += ["-z", duration]
        if profile:
            prof = subprocess.Popen(
                [
                    "/usr/lib/linux-tools/6.8.1-1015-realtime/perf",
                    "record",
                    "-F",
                    "499",
                    "-g",
                    "-e",
                    "cycles:u",
                    "-p",
                    str(server.pid),
                    "-o",
                    profile,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        start = cpu(server.pid)
        t = time.monotonic()
        stderr_file = open("/tmp/hfast-opt/client-stderr", "wb")
        client = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_file)
        # Read client CPU before its exit without introducing polling into the hot path.
        samples = []
        while client.poll() is None:
            try:
                samples.append(cpu(client.pid))
            except FileNotFoundError:
                pass
            time.sleep(0.1)
        out, _ = client.communicate()
        stderr_file.close()
        err = Path("/tmp/hfast-opt/client-stderr").read_bytes()
        assert client.returncode == 0, err
        report = json.loads(out)
        used = cpu(server.pid) - start
        r = dict(
            binary=binary,
            proto=proto,
            p=1 if proto == "h1" else int(os.environ.get("HFAST_BENCH_STREAMS", "128")),
            ct=threads,
            st=server_workers,
            server_affinity=affinity,
            client_affinity=CPUS,
            rps=report["requestsPerSec"],
            server_cpu=used / report["durationSeconds"],
            process_wall_seconds=time.monotonic() - t,
            cpu_us=used * 1e6 / max(1, report["requests"]["ok"]),
            client_cpu=max(samples, default=0) / report["durationSeconds"],
            report=report,
        )
        if correct:
            assert report["requests"]["errors"] == 0, r
        assert list(report["statusCodes"]) == ["200"], r
        return r
    finally:
        if prof:
            prof.terminate()
            prof.wait()
        server.terminate()
        server.wait()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("binaries", nargs="+")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--duration", default="5s")
    p.add_argument("--protocols", default="h1,h2,h3")
    p.add_argument("--threads", default="8")
    p.add_argument("--correct", action="store_true")
    p.add_argument("--profile")
    p.add_argument("--server-workers", type=int, choices=range(1, 5), default=1)
    a = p.parse_args()
    for rep in range(a.runs):
        for proto in a.protocols.split(","):
            for ct in map(int, a.threads.split(",")):
                for binary in a.binaries[:: 1 if rep % 2 == 0 else -1]:
                    r = measure(
                        binary,
                        proto,
                        ct,
                        a.duration,
                        a.profile,
                        a.correct,
                        a.server_workers,
                    )
                    r["rep"] = rep
                    print(json.dumps(r), flush=True)
