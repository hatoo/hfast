# HTTP/1 multishot receive validation

Classified HTTP/1 connections use bounded io_uring multishot receives. Unknown
and HTTP/2 connections retain poll/single-read batches. The worker completes its
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

## Measured workload and scope

Experiment c150, WSL2, 2026-10-14. Immutable default hfast `debbdbd` (production
source identical to `1aa46b9`) versus this implementation; fixed shb `39aa8c0`.
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
