#!/usr/bin/env python3
"""HTTP/3 correctness with independent aioquic through a lossy UDP relay."""

import asyncio, random, socket, subprocess, sys, threading, time
from interoperability import h3

server = subprocess.Popen(
    [sys.argv[1], "--threads", "1", "--tcp", "0", "--quic", "18443"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
relay.bind(("127.0.0.1", 18444))
relay.settimeout(0.02)
stop = threading.Event()
drops = [0, 0]


def forward():
    rng = random.Random(42)
    peer = None
    target = ("127.0.0.1", 18443)
    while not stop.is_set():
        try:
            data, source = relay.recvfrom(65536)
        except socket.timeout:
            continue
        if source == target:
            destination = peer
            direction = 1
        else:
            peer = source
            destination = target
            direction = 0
        if rng.random() < 0.05:
            drops[direction] += 1
        elif destination:
            relay.sendto(data, destination)


thread = threading.Thread(target=forward, daemon=True)
try:
    time.sleep(0.2)
    thread.start()
    if "--shb" in sys.argv[2:]:
        import json

        run = subprocess.run(
            [
                "taskset",
                "-c",
                "8",
                "/home/hatoo/shb/target/release/shb",
                "--http3",
                "-t",
                "1",
                "-c",
                "1",
                "-p",
                "16",
                "-n",
                "3000",
                "--timeout",
                "2s",
                "-j",
                "https://127.0.0.1:18444/",
            ],
            capture_output=True,
            check=True,
            timeout=60,
        )
        report = json.loads(run.stdout)
        assert (
            report["requests"]["ok"] == 3000 and report["requests"]["errors"] == 0
        ), report["requests"]
        print(
            "PASS: shb 3000 requests through 5% bidirectional loss, seed 42; drops",
            drops,
        )
    else:
        asyncio.run(h3(18444))
        print(
            f"PASS: aioquic 64 GET + 64 POST through 5% bidirectional loss, seed 42; drops {drops}"
        )
finally:
    stop.set()
    thread.join(timeout=1)
    relay.close()
    server.terminate()
    server.wait()
