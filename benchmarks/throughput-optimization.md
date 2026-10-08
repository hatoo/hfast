# Throughput optimization, 2026-10-08

No commits/pushes; shb source/build is untouched. Starting hfast commit:
`3b2994d90e572f877cb9ed61531458bd7d93e5de`; clean initial worktree.
shb commit `8a1fed933ef4096c8d5a9dc7df83af28b880ae1a`, existing release
SHA256 `22270331bbccb3ccfa0869a81cf786f67860eb9dd0289041b8b9eceb8437a10b`.
Ryzen 9 3950X, WSL2 Linux 6.18.40.1, rustc 1.98.0.

## Method

`benchmarks/throughput.py` starts a fresh server each run, 200 ms startup,
5-second shb interval including connection establishment. Release builds:
opt-level=3, fat LTO, one codegen unit, unchanged compiler flags. One server
worker pins itself to CPU 0. shb affinity is 8,10,12,14,16,18,20,22,24,26,28,30:
separate physical cores, excludes CPU 0's sibling CPU 1. Main comparison uses
8 client workers, 128 HTTP/1.1 connections or 16 HTTP/2/3 connections with
128 streams each, `--batch-linger 1 --timeout 2s`. Calibration checks 4/8/12
client workers. Process CPU is sampled from /proc; percentages are cores used.
CPU/request includes client startup/shutdown wait. No other benchmarks run
concurrently. Three paired repetitions alternate old/new order; meaningful
improvement requires >=3% median throughput with consistent paired direction,
no correctness errors, and confirmation when noise overlaps. Failed proposals
are reverted. This is a local fixed 13-byte-body workload, not an absolute
network throughput claim or proof of a global optimum.

## Initial checks and profiling

55 unit tests pass. Initial 32-connection HTTP/3 calibration produced 4,736–5,888
errors per 5-second run, receive-buffer drops, growing client QUIC stream
bookkeeping and client saturation. These invalid capacity measurements are
preserved in throughput-h3-calibration.jsonl. Six initial TCP calibration runs
are in throughput-baseline.jsonl (calibration aborted on HTTP/3 errors).
16 HTTP/3 connections gives a clean run: 2.70M requests/s, server 0.94 cores,
client 1.51 cores, zero errors. Clean baselines are collected separately.

perf wrapper cannot find a matching WSL package; installed executable
`/usr/lib/linux-tools/6.8.1-1015-realtime/perf` works. Sampling: 499 Hz cycles,
call graph. HTTP/1.1 dominated by kernel read/write paths (kernel symbols not
available). HTTP/2: 57.5% in Conn::drive, including inlined response assembly.
HTTP/3: recv 25.2%, AES/GHASH >30%, flush 12.3%, varint readers 7.1%, clock
calls ~4%, memmove ~2.3%, endpoint hashing ~2%. Profiled rates are not used
as unprofiled baseline comparisons. Profiles reside in /tmp/hfast-opt.

## Attempt 1 — HTTP/2 constant response template — reverted

One copy instead of four response-buffer extensions, then patch both stream IDs.
55 tests passed; independent hyper-h2, aioquic and fragmented/pipelined HTTP/1.1
checks passed; shb 3,000 POSTs per protocol passed. Three paired HTTP/2 runs:
baseline median 4,991,958 (4,723,011–5,027,160); candidate 4,969,933
(4,905,739–5,013,426), −0.44%. CPU/request 0.200 → 0.201 µs. No errors.
No meaningful gain: reverted. Consecutive failed attempts: 1.
Raw results: throughput-a1.jsonl; throughput-a1-correctness.jsonl.

## Attempt 2 — fixed-width QUIC varint loads — reverted

Replace byte-by-byte accumulation with one bounds-checked slice and native
big-endian 1/2/4/8-byte decoding, inline the decoder. Existing width/truncation
and frame tests pass (55 total), all independent interoperability checks pass,
shb 3,000 POSTs per protocol pass. Three paired HTTP/3 runs: baseline 2,782,794
(2,768,131–2,793,081); candidate 2,736,374 (2,730,936–2,746,887), −1.67%;
CPU/request 0.358 → 0.364 µs. All six runs error-free. Reverted.
Consecutive failed attempts: 2. Raw: throughput-a2*.jsonl.

## Attempt 3 — 4 MiB UDP receive queue — reverted

Kernel counters showed receive-buffer drops in the initial calibration. Increase
SO_RCVBUF to 4 MiB per UDP worker (Linux doubles accounting). All 55 tests,
independent interoperability and shb POST checks passed. Three paired HTTP/3
runs at each client size: 4 workers baseline 3,088,083, candidate 3,133,915
(+1.48%); 8 workers baseline 2,728,871, candidate 2,754,769 (+0.95%).
Ranges overlap substantially; all twelve runs error-free. Below meaningful
improvement threshold: reverted. Consecutive failed attempts: 3.
Raw: throughput-a3*.jsonl.

## Attempt 4 — io_uring batch TCP reads and writes — retained

The HTTP/1.1 profile is >99% kernel/unknown kernel addresses. Prototype keeps
readiness polling but submits all ready sockets' Recv operations in one ring
batch, parses completions, then submits their Send operations in one batch.
Two completion barriers guarantee exclusive, stable buffer lifetimes. Both
operations use MSG_DONTWAIT; short sends arm EPOLLOUT and retain pending bytes.
128 ready sockets, 16 KiB distinct receive chunks (2 MiB/worker), io-uring 0.7.15.
Falls back to original worker if ring creation fails. No shb changes. Release
flags unchanged. Existing 55 tests, independent interoperability and shb POST
checks pass. Larger bodies and send backpressure are additionally checked.

## Baseline calibration summary

Eight shb workers; three 5-second runs per protocol:

| Protocol | Median req/s | Server µs/req | Server cores | Client cores | Errors |
|---|---:|---:|---:|---:|---:|
| h1 | 86368 | 11.532 | 0.99 | 1.16 | 0 |
| h2 | 4629516 | 0.215 | 0.89 | 1.57 | 0 |
| h3 | 2691049 | 0.371 | 0.94 | 1.6 | 0 |

Raw: throughput-baseline-clean.jsonl. Four-worker throughput was higher
(HTTP/1.1 118,962; HTTP/2 6,787,107; HTTP/3 3,026,353), demonstrating client
CPU capacity rather than a client ceiling at eight workers. One of the three
four-worker HTTP/3 runs reported 128 errors; none at eight/twelve workers.
Changing client workers also changes batch sizes and per-worker concurrency,
so extra workers are a capacity diagnostic, not interchangeable configurations.
The server uses about a whole core in clean unprofiled runs; client workers use
~1.2–1.6 cores total, with several physical cores spare.

Attempt 4 decision: **kept**, resets consecutive failed count to zero.
Three 5-second HTTP/1.1 pairs: median 98,071 → 100,564 (+2.54%), each pair
positive; CPU/request 10.165 → 9.686 µs. Because median ranges overlap, five
10-second confirmation pairs were required: 86,970 → 103,462 (+18.96%);
CPU/request 11.481 → 9.439 µs (−17.8%). Paired changes +10.71%, −0.64%,
+19.87%, +26.99%, +10.89%. Seven of eight total pairs improved; one small
negative is within observed noise. HTTP/2 three-pair median 4,877,342 →
4,916,832 (+0.81%, effectively unchanged). All runs error-free. 70 KB POST,
40,000 pipelined responses under receive backpressure passed; clippy passes
(after removing redundant borrows and moving test module). HTTP/3 source is
unchanged. Raw: throughput-a4*.jsonl. Original syscall worker retained as a
fallback for systems where io_uring creation fails.

## Attempt 5 — io_uring fixed-file sockets — reverted

Register a sparse 4,096-slot file table, index sockets by their fd, submit
FIXED_FILE entries when registration succeeds, use ordinary fd entries for
higher descriptors or unsupported registration. Unregister before closing,
so fixed references cannot hold dead sockets open. 55 tests, clippy,
independent interoperability including backpressure and shb POST checks passed.
Initial 3-pair medians: HTTP/1.1 a4 99,904 → a5 110,977 (+11.08%);
HTTP/2 4,934,784 → 5,021,669 (+1.76%). One HTTP/1.1 candidate run fell to
86,715, so five longer 10-second pairs are required before a decision.

Attempt 5 decision: **reverted**. Five 10-second HTTP/1.1 pairs give
107,365 → 102,914 (−4.15%); CPU/request 9.085 → 9.463 µs. Initial advantage
was not reproducible. No errors. Consecutive failed attempts since kept a4: 1.
Raw: throughput-a5*.jsonl.

## Attempt 6 — word-at-a-time QUIC padding scan — reverted

The annotated receive profile shows a byte-by-byte padding loop taking 8.9%
of recv samples. Skip all-zero 8-byte words, then scan the tail bytewise;
framing and nonzero bytes are unchanged.

Attempt 6: all 55 tests, independent interoperability/backpressure and shb
POST checks passed. Three HTTP/3 pairs: a4 2,713,378 (2,664,550–2,715,843)
→ candidate 2,781,323 (2,733,554–2,811,855), +2.50%; CPU/request
0.368 → 0.359 µs. All pairs positive and error-free, but below the predeclared
3% meaningful improvement threshold: **reverted**. Failure count: 2.
Raw: throughput-a6*.jsonl.

## Attempt 7 — avoid unused QUIC send timestamps — reverted

Only call Instant::now when oldest_sent or rtt_probe needs initializing.
Previously every ack-eliciting transmit read the clock even when neither
stored the result. Recorded timestamps and timer behavior are unchanged.

Attempt 7: all 55 tests, independent interoperability/backpressure and shb
POST checks passed. Three HTTP/3 pairs: a4 2,770,998 → candidate 2,761,759,
−0.33%; CPU/request 0.359 → 0.361 µs. Zero errors. **Reverted**.
Failure count: 3. Raw: throughput-a7*.jsonl.

## Attempt 8 — persistent UDP receive descriptors — reverted

Box addresses, iovecs and mmsghdr storage so pointers survive object moves,
initialize them once, reset kernel output fields each receive. Retain adaptive
receive limits, truncation checks and timeout behavior. Avoid stack zeroing and
pointer reconstruction for every batch.

Attempt 8: 55 tests, independent interoperability/backpressure and shb POST
checks passed. Three HTTP/3 pairs: a4 2,736,218 → candidate 2,768,637,
+1.18%; CPU/request 0.363 → 0.360 µs. One candidate slower; zero errors.
**Reverted**, failure count: 4. Raw: throughput-a8*.jsonl.

## Attempt 9 — smaller TCP ring batches — reverted

Reduce ready-socket batch and ring capacity from 128 to 64, keeping 16 KiB
chunks. Tests whether faster turnover and smaller scratch working set outweigh
more submissions; workload and worker counts are unchanged.

Attempt 9: 55 tests, independent interoperability/backpressure and shb POST
checks passed. Three pairs: HTTP/1.1 a4 105,295 → candidate 105,841 (+0.52%);
CPU/request 9.300 → 9.307 µs. HTTP/2 5,078,228 → 5,041,003 (−0.73%).
All twelve runs error-free. **Reverted**, failure count: **5**.
Raw: throughput-a9*.jsonl. Optimization search stops as requested, after
nine attempts total, one retained architectural change and five consecutive
unsuccessful attempts following that change. Final verification below does
not introduce additional optimization candidates.

## Final correctness and limitations

Release rebuilt with retained a4 implementation, removing all rejected code.
`cargo fmt --check`, `cargo test` (55 passed), and clippy with warnings denied
pass. Independent clean-path tests pass: fragmented POST+GET pipeline, 70 KB
POST across receive chunks, 40,000 pipelined answers with send backpressure,
64 concurrent hyper-h2 GETs, 64 aioquic GETs and 64 POSTs. The same tests pass
with io_uring_setup denied by a child-only seccomp filter, exercising the
original epoll fallback. shb 3,000 POSTs per protocol also pass.

A newly added stress test with aioquic, 64 concurrent GET/POST streams and a
UDP relay dropping 5% of datagrams each way (seed 42), times out on **both the
original baseline and final binary**. This is a pre-existing custom QUIC
interoperability/loss-recovery limitation, not fixed or introduced by the TCP
optimization. Do not interpret clean-path throughput as full QUIC conformance.
`benchmarks/quic-loss-check.py` preserves this reproducer. The narrower shb
loss case advertised in the old README is also checked separately below.

## Final single-worker comparison

Three alternating 10-second pairs per protocol, same fixed workload and
affinities. Final binary is rebuilt after reverting all failed experiments.

| Protocol | Baseline req/s | Final req/s | Change | Server µs/req before → after | Errors |
|---|---:|---:|---:|---|---:|
| h1 | 90,603 | 95,744 | +5.67% | 11.014 → 10.215 | 0 |
| h2 | 4,776,045 | 4,907,959 | +2.76% | 0.209 → 0.202 | 0 |
| h3 | 2,622,214 | 2,662,836 | +1.55% | 0.381 → 0.375 | 0 |

HTTP/1.1 improved in every final pair (+13.9%, +4.4%, +6.0%). The
HTTP/2 and HTTP/3 median increases are below the meaningful threshold and
within run variation: no separate speedup claimed. Raw: throughput-final.jsonl.

## Four physical server cores

The runner repins existing logical-index worker threads after startup, before
shb starts: workers 0/1/2/3 → CPUs 0/2/4/6. Parent/join threads stay within
that set. shb uses 12 workers on CPUs
8,11,13,14,16,19,21,22,24,27,29,30, one logical CPU per separate physical
core, excluding all server siblings. Mixed even/odd indices spread the TCP
CPU-modulo reuseport selector across all four workers; using only even client
CPU indices with four workers would steer TCP into only two listeners.
Both original and final servers receive exactly the same repinning. Raw
results record all server thread affinity masks.

Three alternating 5-second pairs: 512 HTTP/1.1 connections; 64 HTTP/2/3
connections × 128 streams. HTTP/1.1 median 420,730 → 430,094 (+2.23%),
CPU/request 9.326 → 8.958 µs. HTTP/2 30,023,248 → 31,346,235 (+4.41%),
CPU/request 0.128 → 0.124 µs. All TCP requests return 200 with zero errors.
Ranges overlap: these are scaling validation, not independently confirmed
speedup claims. Raw: throughput-four-cores.jsonl.

The 64-connection HTTP/3 scaling case reports errors on both servers (384
baseline, 1,664 final across three runs). Its raw rates are **not valid clean
capacity evidence** and no speedup is claimed. A separate 32-connection
HTTP/3 scaling comparison follows to reduce receive bursts.

CPU-utilization note: initial raw `server_cpu`/`client_cpu` averages include
shb teardown wall time, which becomes substantial for multi-worker HTTP/2.
CPU/request is unchanged and remains the primary cost metric. The runner now
normalizes core usage to shb's reported measurement duration and records process
wall duration separately. For historical runs, server cores during the measured
interval can be approximated as `cpu_us * rps / 1e6`; cleanup CPU is included,
so this is an upper estimate. Four-core TCP uses approximately 3.8 server
cores; shb CPU remains below its 12-core budget. This denominator correction
does not alter throughput or CPU/request comparisons.

Loss checks: the narrower shb 1-connection/16-stream/3,000-request case through
5% bidirectional loss passes on final (3,000 successes, drops 109/98), but the
original reports 2,984 successes and 16 errors. Random packet ordering changes
the seeded relay's exact drop pattern. Alongside the aioquic timeout on both
versions, this means baseline loss recovery is not reliably correct; do not
claim that the TCP-only change fixes HTTP/3 loss behavior.

The clean four-core HTTP/3 case (32 connections × 128 streams, otherwise
identical) has zero errors in all six runs. Medians: baseline 11,013,689
(10,810,452–11,428,235), final 11,431,374 (10,680,572–11,665,817).
CPU/request 0.358 → 0.348 µs. Ranges overlap and UDP reuseport's connection
assignment varies per restart; no HTTP/3 optimization was retained, so the
+3.79% median difference is **not attributed to a QUIC speedup**.
Raw: throughput-four-cores-h3-clean.jsonl.

Reconstructing measured-interval client CPU usage from the earlier four-core
records gives HTTP/1.1 3.80–4.27 cores, HTTP/2 8.00–9.00, HTTP/3 8.13–9.38,
all below 12 available physical client cores. The single-worker calibration
also confirms that fewer client workers can drive higher rates. The comparison
workloads therefore have client CPU headroom; error-producing HTTP/3 overload
cases were excluded rather than treated as valid throughput wins.

Additional diagnostic record: the aborted initial HTTP/3 calibration with
4 shb workers and 32 × 128 streams completed 6,910,480 requests at
1,378,595 req/s, with 4,736 errors (excluded). A subsequent SHB_DEBUG
3-second diagnosis at 8 workers/32 connections reached 2,342,938 req/s with
2,688 errors; logging makes this unsuitable for speed comparisons. Its raw
report is preserved in throughput-h3-debug.jsonl. Early debug invocations
blocked on the harness's undrained stderr pipe and were terminated; no valid
measurement came from them. The harness now writes stderr directly to a file.

## Reproduction

```sh
cargo build --release
# Save baseline before applying changes; the final comparison alternates order.
python3 benchmarks/throughput.py /tmp/hfast-opt/baseline target/release/hfast \
  --runs 3 --duration 10s > results.jsonl
python3 benchmarks/summarize-throughput.py results.jsonl

# Independent clients are correctness-only; shb is every throughput client.
python3 -m venv /tmp/hfast-interop
/tmp/hfast-interop/bin/pip install -r benchmarks/interop-requirements.txt
/tmp/hfast-interop/bin/python benchmarks/interoperability.py target/release/hfast
/tmp/hfast-interop/bin/python benchmarks/interoperability.py target/release/hfast --epoll
# This reproduces the documented pre-existing loss limitation:
/tmp/hfast-interop/bin/python benchmarks/quic-loss-check.py target/release/hfast

# Four-core clean HTTP/3 comparison:
HFAST_BENCH_CONNECTIONS=32 \
HFAST_BENCH_CLIENT_CPUS=8,11,13,14,16,19,21,22,24,27,29,30 \
python3 benchmarks/throughput.py /tmp/hfast-opt/baseline target/release/hfast \
  --server-workers 4 --threads 12 --runs 3 --protocols h3
```

CPU topology and repinning are specific to this machine's reported adjacent
SMT pairs; adapt affinity masks to another host. WSL2 host scheduling and
loopback networking limit generalization. Baseline/candidate binaries live in
/tmp/hfast-opt during this session; build the original commit in a separate
checkout to reproduce later. Final shb source status remains clean and binary
SHA256 remains identical to the starting value. No commits or pushes were made.

Clean four-core HTTP/3 client utilization: 6.97–7.18 of 12 cores; server 3.87–3.99 of four cores.
