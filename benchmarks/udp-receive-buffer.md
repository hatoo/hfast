# UDP receive capacity for admission bursts

`--udp-receive-buffer BYTES` optionally enlarges each QUIC worker's socket queue.
The default, 0, keeps the host default. Positive values up to 4194304 are accepted.
Larger existing defaults are preserved. Invalid, missing, negative, and oversized
values exit with usage status 2.

Linux doubles an SO_RCVBUF request for bookkeeping and applies rmem_max; the
largest requested effective limit is 8 MiB per worker. This limit does not reserve
that memory at startup. See [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html).
The server reads the effective size, reports caps and failures, and retains the
host default on failure. If a cap would shrink the default, it closes and replaces
the still-unbound socket. It does not change host settings or force a larger cap.

## Measured scope

WSL2 x86_64, Rust 1.99.1, release/fat LTO/one codegen unit. The frozen baseline
has the production code of master `dfd800a`; its only difference from `6fed8c9`
is tests. Baseline SHA256 starts `b5792af7`, opt-in binary `10821a5f`, fixed shb
`5fb383e9`, fixed native peer `ff3bcade`. Production timing uses no preload.
The candidate runs with `--udp-receive-buffer 4194304`; the baseline uses its
212992-byte host queue. Candidate queues are 8388608 bytes on this host.

Each set alternates three pairs, followed by an independent opposite-order set.
The server has one worker on CPU 0; client producers use CPUs 8, 10, 12 and 14.
Every measured startup uses a fresh server. shb warmups use separate servers.
The table shows median elapsed times, median paired changes, and per-run server
drops. No application errors occurred.

| Workload | Baseline elapsed | Opt-in elapsed | Paired elapsed change | Server drops |
|---|---:|---:|---:|---:|
| shb primary | 0.486 s | 0.149 s | -69.37% | 471–499 → 0 |
| shb confirmation | 0.414 s | 0.163 s | -58.07% | 265–609 → 0 |
| independent primary | 2.429 s | 0.683 s | -71.98% | 411–440 → 0 |
| independent confirmation | 2.541 s | 0.680 s | -74.41% | 410–434 → 0 |

The shb workload is 512 configured connections, depth 16, four client workers,
and exactly 8192 successful requests. Its global request budget does not certify
that every configured connection completes TLS. The independent aioquic fixture
instead requires all 512 handshakes, 16 checked GET/POST responses per peer, and
512 local graceful closes. Four producers prepare 128 Initials each behind a
send barrier, with exactly one buffered Initial per peer. Its fixed initial RTT
is 1 s on both sides of the comparison; its timings must not be compared directly
to shb's. An earlier 0.1 s setup failed that pre-send assertion because PTO fired
while preparing the barrier; it is excluded, with failure evidence retained.

## Costs and default policy

This is burst tuning, not a general throughput or latency improvement.
In the shb startup sets, server CPU/request rose 58.13% and 42.94%, and median
request latency rose sharply even though total completion and high percentiles
improved. The independent complete-peer bursts used 3.61% and 7.21% less server
CPU. These fixtures measure different work distributions and must stay separate.

For 4194304 requests through 512 persistent connections, RPS changed +4.65% in
one set and -7.75% in confirmation. CPU/request rose 13.36% and 13.79%, mean
request latency rose 172.14% and 207.07%, and median request latency rose about
370–377%. The enlarged queue eliminated the measured server drops, but the
sustained-load costs rule out changing the default.

Longer 1-connection runs changed RPS +0.52%/+0.76%; 16-connection runs changed
+0.90%/-1.71%. The bounded native full TLS/HTTP/ACK/close guard changed CPS
+1.26%/+0.40%, with CPU medians about -0.40%. No general gain is claimed for
these guards. Choose queue capacity using the workload's loss, latency and CPU
requirements; kernel queue memory can also increase with occupancy.

## Reproduce the ordinary startup workload

Keep separate immutable release binaries, a fixed shb binary, and identical
compiler flags. Start the chosen server in an isolated network namespace with
loopback enabled, record its socket capacity with `ss -unam`, then run:

```sh
# Baseline server:
/path/to/baseline --tcp 0 --quic 8443 --threads 1
# Candidate server in a separate trial:
/path/to/candidate --tcp 0 --quic 8443 --threads 1 --udp-receive-buffer 4194304
# Fixed client, identical for both trials:
taskset -c 8,10,12,14 /path/to/shb --http3 -c 512 -p 16 -t 4   --batch-linger 1 --timeout 5s -n 8192 -j https://127.0.0.1:8443/
```

Warm up using separate fresh servers, alternate three pairs, and confirm with
reversed order. Preserve complete JSON latency reports and exact status/error
counts; compare `/proc/net/udp` per-socket drops with the namespace UDP counters.
For the sustained guard change only `-n` to 4194304. One-connection guards use
`-c 1 -t 1 -n 262144`; 16-connection guards use `-c 16 -t 4 -n 4194304`.

The final fixed-shb runs, including warmups, completed 104300544 requests with
zero application errors. Independent full-peer runs completed 7168 connections
and 114688 requests including smoke. Native comparisons completed 192000 measured
connections, 195120 including warmups and retirement probes, with every measured
latency retained and no UDP errors.

## Correctness

305 Rust tests pass in debug and release, plus production Clippy and formatting.
Four new unit tests cover bounds/default preservation, socket errors, and four
workers sharing a port with exact datagram accounting. `udp-buffer-check.py`
checks five invalid CLI inputs and nine real-socket modes, each with four workers,
16 full TLS peers and 512 independently checked responses. Modes cover default,
explicit zero, enlargement, cap, shrink rollback, rollback with exactly enough
file descriptors, denied setsockopt, and failed reads before/after enlargement.
The descriptor-limit regression fails on the earlier replacement implementation.

The cap/failure interposer is used only in this correctness fixture, which runs
in CI. The final binary also passes eight protocol/recovery scripts, default
interoperability, and twelve native normal/reordered/duplicate/GRO/fallback cases.
These focused checks do not establish general QUIC loss-recovery correctness.
