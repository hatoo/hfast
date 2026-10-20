#!/usr/bin/env python3
"""Prove timing runs reject missing/duplicated reset packets over real UDP.

The relay uses the untimed plaintext trace only to identify the cancellation
phase. It forwards encrypted datagrams unchanged and injects transport faults.
These failures are expected; positive loss recovery uses reset-accounting-check.py.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import time

import stop_batch as s
from stop_batch_wire import frames


def run(args, mode):
    out = args.output / mode
    out.mkdir()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay, selectors.DefaultSelector() as selector:
        relay.bind(("127.0.0.1", 0))
        relay.setblocking(False)
        selector.register(relay, selectors.EVENT_READ)
        with (out/"server.log").open("x") as log, (out/"stdout").open("x") as stdout, \
                (out/"stderr").open("x") as stderr:
            server = subprocess.Popen([str(args.server), "--threads", "1", "--tcp", "0",
                                       "--quic", str(port), "--max-streams", "2048"],
                                      stdout=log, stderr=log)
            peer = None
            try:
                time.sleep(.2)
                env = dict(os.environ, STOP_BATCH_TRACE=str(out/"wire.jsonl"))
                peer = subprocess.Popen(["taskset", "-c", str(args.client_cpu), str(args.peer),
                                         str(relay.getsockname()[1]), str(server.pid),
                                         "1024", "64", "32", "64", "1", "plain"],
                                        env=env, stdout=stdout, stderr=stderr)
                client, cancel, injected = None, False, 0
                deadline = time.monotonic() + 12
                while peer.poll() is None:
                    s.require(time.monotonic() < deadline, "peer failed to enforce timeout")
                    for _, _ in selector.select(.01):
                        data, source = relay.recvfrom(65536)
                        if source[1] != port:
                            client = source
                            # File writes happen before native UDP sends. Read
                            # complete JSON lines only; no packet is decrypted here.
                            lines = (out/"wire.jsonl").read_text().splitlines() if (out/"wire.jsonl").exists() else []
                            for line in lines:
                                try:
                                    rec = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                if rec["direction"] == "tx":
                                    cancel |= any(ty == 5 for ty, _ in frames(bytes.fromhex(rec["hex"])))
                            relay.sendto(data, ("127.0.0.1", port))
                        else:
                            s.require(client is not None, "server datagram before client")
                            if cancel and mode == "drop":
                                injected += 1
                                continue
                            relay.sendto(data, client)
                            if cancel and mode == "duplicate" and not injected:
                                relay.sendto(data, client)
                                injected += 1
                s.require(peer.returncode != 0 and injected > 0, "fault injection falsely passed")
                s.require(server.poll() is None, "server died during fault injection")
            finally:
                if peer is not None and peer.poll() is None:
                    peer.terminate()
                    peer.wait(timeout=5)
                server.terminate()
                server.wait(timeout=5)
        message = (out/"stderr").read_text()
        expected = "missing response or ACK fence" if mode == "drop" else "noncontiguous packet"
        s.require(expected in message, f"wrong failure: {message}")
        s.require(not (out/"stdout").read_text(), "failed peer emitted success report")
        result = dict(mode=mode, injected_datagrams=injected, expected_failure=expected,
                      peer_returncode=peer.returncode)
        (out/"result.json").write_text(json.dumps(result, indent=2)+"\n")
        return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("server", "peer", "output"):
        p.add_argument(key, type=lambda x: Path(x).resolve())
    p.add_argument("--client-cpu", type=int, default=8)
    args = p.parse_args()
    args.output.mkdir(parents=True)
    rows = [run(args, mode) for mode in ("drop", "duplicate")]
    (args.output/"summary.json").write_text(json.dumps(rows, indent=2)+"\n")
    print(json.dumps(rows), flush=True)
