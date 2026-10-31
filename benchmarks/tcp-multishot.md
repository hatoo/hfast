# TCP multishot receive validation

Classified HTTP/1 and HTTP/2 connections use bounded io_uring multishot receives.
Unknown connections retain poll/single-read batches. The worker completes its
read and send batches before changing connection storage or parsing additional
multishot input. A real operation probe falls back to the original worker when
provided buffers or multishot receives are unavailable.

Operation identities use a 24-bit slot index and a 36-bit per-slot generation.
Dispatch checks the complete identity before accessing the connection. Removing
a socket makes its slot reusable with a new generation; an exhausted generation
permanently retires that slot. This avoids hashing, fd-indexed storage and a
global connection-churn generation limit. Capacity exhaustion is checked, never
truncated. Stale completions still return every completed buffer exactly once.

The worker reserves 2 MiB of provided payload and 2 MiB of single-read scratch,
compared with the original worker's 2 MiB scratch. This memory cost is per worker.
There can be at most 2^24 live or permanently retired identity slots per worker.

## HTTP/2 extension: c313, 2026-10-31

Established H2 connections now use the same bounded receive path as H1. Unknown
connections switch only after their classification read retires. Buffer sizes,
slot generations, send barriers and protocol/accounting code are unchanged.
Tests cover byte-by-byte classification, two-buffer exhaustion, split
HEADERS/CONTINUATION, zero stream credit, fragmented WINDOW_UPDATE, stale CQEs,
output-vector borrows and GOAWAY behind partial output.

Immutable hfast `cb0621b` (SHA256 `e491abce`) versus this change (`25c67677`),
with fixed shb `5e8827a` (`d5ad7a0c`). Both server builds use Rust 1.99.1,
release optimization, fat LTO and one codegen unit. One server worker on CPU1;
two shb processes on CPU8/9, each c8/p128/t1, batch1, 134,217,728 requests and
4,194,304 warmup requests. Every request contributes a latency sample. Rates
use a common monotonic interval through both complete reports. The active
server interval remained above 0.978 core, all one-second bins above 0.908,
and active producers below 0.641 core in primary/confirmation runs.

| Phase / pair | Baseline RPS | Candidate RPS | RPS change | Server CPU/request change |
|---|---:|---:|---:|---:|
| primary 0 | 7,166,252 | 7,569,058 | +5.621% | -5.065% |
| primary 1 | 7,028,715 | 7,589,577 | +7.980% | -5.973% |
| primary 2 | 6,933,264 | 7,309,738 | +5.430% | -4.922% |
| primary 3 | 7,370,049 | 7,429,909 | +0.812% | -1.578% |
| confirm 0 | 7,602,827 | 8,002,772 | +5.260% | -5.211% |
| confirm 1 | 7,573,741 | 7,937,711 | +4.806% | -4.804% |
| confirm 2 | 7,805,859 | 8,237,905 | +5.535% | -5.599% |

Median paired throughput gains are **+5.525% primary / +5.260% confirmation**;
server CPU/request medians are **-4.993% / -5.211%**. First identical-binary
controls were -1.204% and +0.191%, both inside the unchanged 3% gate. No control
retry, configuration sweep or statistical-significance claim. This establishes
a gain for this saturated H2 workload. Serial/H1 workloads have correctness
guards, not a new speed claim. Worst-child p99 and p99.9 varied (one primary
p99.9 +20.0%, one confirmation p99 +8.21%); no general latency improvement or
latency equivalence is claimed. Percentiles from separate clients are not pooled.

Separate instrumented AB/BA counts, each with 2,097,152 requests, found:

| Operation | Baseline | Candidate |
|---|---:|---:|
| Input poll SQEs | 16,404 | 16 |
| Single receive SQEs | 16,404 | 16 |
| Multishot receive SQEs | 0 | 16 |
| Send SQEs | 16,388 | 16,388 |
| All SQEs, including teardown | 49,197 | 16,453 |
| All CQEs | 49,197 | 32,841 |
| io_uring_enter calls, first / second pair | 3,095 / 3,081 | 2,059 / 2,058 |

Both variants receive exactly 60,818,848 bytes and send 104,858,096 bytes,
including the client's 17-byte teardown GOAWAY on each of 16 connections.
There are no buffer-exhaustion or EAGAIN completions in these count runs.
They establish operation removal; their timings are excluded from speed claims.
The kernel system-time fraction alone does not identify a kernel hotspot.

Validation: 364 Rust tests in each debug/release profile, fmt, strict production
Clippy, 17 independent H1/H2/H3/TCP invocations, six forced-fallback invocations,
and 16 ordinary native accounting guards pass. The fallback build deliberately
rejects the real multishot probe with MSG_WAITALL. Eleven controller oracle tests
also pass. The replayed qualification/primary/confirmation/control and smoke
reports contain 5,536,615,168 exact requests/latency samples and zero errors.
Reproduce the comparison with [the counted cohort runner](h2-response-cohort.md).
Raw reports, source/binary manifests and count-only instrumentation are retained
in `hfast/optimization-results/c313/` in the optimization workspace.

## Historical HTTP/1 measured workload and scope

Experiment c150, WSL2, 2026-10-14. Immutable default hfast `debbdbd` (production
source identical to `1aa46b9`) versus the H1 slot implementation; fixed shb `39aa8c0`.
Rustc 1.98.0, release optimization, fat LTO, one codegen unit, matching dependency
and compiler fingerprints. One server worker on CPU1 and one client worker on
CPU8; fresh processes, 16,384 warmup requests, alternating pairs and independent
reversed-order confirmation. The client uses batch size 1 and a 5-second timeout.

Concurrent HTTP/1 uses 128 connections and 2,097,152 requests per measured run.
The accepted result is specific to this workload. All six paired throughput
deltas are positive and all six server CPU/request deltas are negative:

| Phase / pair | Baseline RPS | Candidate RPS | RPS change | Server CPU/request change |
|---|---:|---:|---:|---:|
| Primary 0 | 172,888 | 186,057 | +7.617% | -6.967% |
| Primary 1 | 173,421 | 181,316 | +4.552% | -4.642% |
| Primary 2 | 178,628 | 186,850 | +4.602% | -4.614% |
| Confirmation 0 | 173,592 | 185,733 | +6.994% | -6.517% |
| Confirmation 1 | 170,707 | 181,981 | +6.604% | -6.312% |
| Confirmation 2 | 177,254 | 182,037 | +2.698% | -2.857% |

Median paired changes: RPS **+4.602% / +6.604%**, CPU/request
**-4.642% / -6.312%**. Server utilization was approximately 0.98 core; client
utilization increased from 0.90–0.95 to 0.96–0.98 core. This does not establish
maximum server capacity with an unlimited producer.

Other fixed workloads are guards, with inconclusive smaller or mixed effects:

| Workload | Primary RPS | Confirmation RPS | Primary CPU/request | Confirmation CPU/request |
|---|---:|---:|---:|---:|
| Native H1, 128 connections, pipeline 64 | +2.297% | +3.158% | -2.437% | -3.246% |
| Ordinary H1, 1 connection | +0.725% | +0.442% | -2.055% | -2.256% |
| H2, 1 connection, 128 streams | -0.440% | -0.329% | +0.217% | +0.383% |
| H2, 128 connections, 1 stream each | +0.148% | -0.029% | +0.024% | -0.173% |

All 508,821,504 comparison responses, including warmups, succeeded with zero
errors. Paired ordinary request/status/sent/received totals match exactly.
All latency quantiles were retained. Concurrent H1 p99 medians changed
-0.003%/-5.098%, and p99.9 +0.845%/-2.183%. Concurrent H2 p99 medians changed
+1.068%/+0.473%, and p99.9 +3.993%/-1.227%; one H2 pair lost 4.868% throughput.
These mixed tails and WSL noise do not establish latency equivalence or a
general H2 improvement. No failed identical-binary control was rerun, no affinity
sweep was performed, and the engineering acceptance threshold was not lowered.

## Correctness and mechanism evidence

277 debug and 277 release tests passed, as did formatting and strict production
Clippy. Independent fixtures passed 53 invocations: 25 production, 14 with a
deliberately rejected multishot probe, and 14 with only two provided buffers.
Coverage includes mixed H1/H2 at one/two workers, fragmented classification,
churn, EOF, partial sends, backpressure, buffer exhaustion and existing QUIC
interoperability/recovery cases. Slot tests cover 100,000 replacements, exhausted
generations, high fd values and stale positive/terminal completions.

Untimed exact-response audits compared the previous HashMap prototype with the
slot worker. Dispatch counts match: 24,585 lookups for 4,096 serial H1 requests,
and 33,920 for concurrent H2. All hash lookups become direct slot checks; byte,
cancellation, terminal and buffer ledgers match. H2 uses zero connection
multishot operations. A real `Worker::socket` replay over live/stale/reused
identities reduced lookup time by 85.698%/86.191% in two phases, with identical
hit and mutation checksums. This measures user dispatch, not kernel hotspots.

## Reproduce ordinary comparisons

Build immutable baseline/candidate server binaries with matching release settings
and use a fixed shb binary. The runner sets the server affinity after its startup
pin, checks all errors and paired accounting, and retains each full JSON report,
client CPU usage, server scheduler runtime and all commands. Each output directory
must be new. Choose available CPUs before running; the defaults are 1 and 8.

```sh
python3 benchmarks/compare-tcp-slots.py /path/to/baseline /path/to/candidate \
  /path/to/fixed-shb /tmp/tcp-primary
python3 benchmarks/compare-tcp-slots.py /path/to/baseline /path/to/candidate \
  /path/to/fixed-shb /tmp/tcp-confirmation --reverse
```

The original runs used separate user/network namespaces with loopback enabled.
`--pairs 1 --requests 4096 --warmup 1024` checks the runner's accounting quickly;
such a smoke run is not performance evidence. Raw experiment reports, source and
binary manifests, diagnostic scripts and logs are retained locally under
`hfast/optimization-results/c150-*`.
