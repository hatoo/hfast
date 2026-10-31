# Deferred TCP completion work (c315)

This experiment starts at `37a7140` (the merged H2 multishot implementation).
It keeps every submission and read/send barrier, but asks the kernel to run
completion task work at those barriers with `SINGLE_ISSUER`, `COOP_TASKRUN`
and `DEFER_TASKRUN`. The worker creates, submits and drains its own ring.
Unsupported setup flags (`EINVAL`) select the ordinary ring; other setup errors
remain visible. The independently probed single-receive fallback remains usable.

Every entry requests `GETEVENTS`, including zero-wait entries and the full-SQ
path. The pinned io-uring 0.7.14 `submit_and_wait(0)` does not request that flag
unless another condition requires it. Omitting it can strand deferred work.
The submission tail is published before entry and re-read on `EINTR`.
See [io_uring_setup(2)](https://man7.org/linux/man-pages/man2/io_uring_setup.2.html)
and [io_uring_enter(2)](https://man7.org/linux/man-pages/man2/io_uring_enter.2.html).

The earlier c105 experiment used poll/single-read operations and an underloaded
H2 fixture. Current H2 multishot and a saturated two-producer workload give a
different completion scheduling experiment. Neither the response-template
candidate nor c314's empty-entry guard is included here. No fraction of the
measured kernel CPU is assumed to be avoidable.

## Correctness gates

`cargo test --locked` and `cargo test --release --locked` include real-ring
tests for ordinary/deferred setup, error propagation, zero-wait poll progress,
SQ pressure, CQ overflow, interrupted waits, partial sends and fd reuse.
The multishot tests use the production ring setup, covering classification,
generation tokens, pool exhaustion, republication, cancellation, H2 credit,
fragmented headers, mixed protocols and EOF with queued output. An additional
test repeatedly receives through zero-wait and full-SQ entries, returns each
buffer and retires the final EOF.

Separate compiled variants force setup fallback and multishot-probe fallback.
A compiled mutation omitting zero-wait `GETEVENTS` must fail both the poll and
multishot progress regressions. Production Clippy, formatting, the independent
protocol/TCP checks and ordinary native H1/H2 accounting guards are also required.

## Measurement gates

Use immutable release binaries built with matching Rust 1.99.1, fat LTO and one
codegen unit. Baseline server: `37a7140`, SHA256
`25c676779cfe54a40bd1756cd0428fba17d6538ad73ab5a08ff19d7144a685e6`.
Fixed shb: `5e8827a`, SHA256
`d5ad7a0c6403fe342308f09f638903d6119e787be3ca6156ec00428f2778315e`.

First use separate count-only AB/BA runs to verify the ring flags, GETEVENTS
on zero-wait entries, exact request/byte/operation counts and no unexpected
errors or buffer exhaustion. Instrumented timing is excluded.

Then use the unchanged `h2_response_cohort.py` fixture: CPU1 server, CPU8/9
producers each c8/p128/t1, batch1, 134217728 requests after 4194304 warmup.
Every latency sample and both complete report intervals remain included.
Qualify saturation before four alternating primary pairs. Require independent
reversed confirmation and identical-binary controls before accepting a gain;
the default engineering threshold remains 3%. Retain ordinary H1/H2 results
and tail percentiles without inferring general latency improvements.

## Results

**ACCEPTED for the fixed saturated H2 throughput/CPU workload.** Production and
tests are commit `bac4aa3`; candidate SHA256
`e6fb6d6cccdadc619840351319e8414ee47e369c6a32df434408a964845d9901`.

| Phase/pair | Throughput change | Server CPU/request change |
| --- | ---: | ---: |
| Primary 1 (AB) | +5.578% | -5.737% |
| Primary 2 (BA) | +10.973% | -8.634% |
| Primary 3 (AB) | +4.138% | -4.777% |
| Primary 4 (BA) | +6.984% | -6.527% |
| Primary median | **+6.281%** | **-6.132%** |
| Confirmation 1 (BA) | +6.579% | -7.696% |
| Confirmation 2 (AB) | +5.277% | -5.714% |
| Confirmation 3 (BA) | +6.167% | -6.265% |
| Confirmation median | **+6.167%** | **-6.265%** |

First identical-binary controls are -1.024% and +0.574%, within the unchanged
3% gate. All seven candidate comparisons improve throughput and CPU/request.
The preliminary qualification pair (+5.776%) is kept separate. There was no
control retry or affinity/configuration sweep, and no statistical-significance
claim. No build, trace or protocol test overlapped these timing runs.

All 20 timed cohorts qualify: active server 0.9728–0.9849 cores, producers at
most 0.6512 cores. The minimum one-second server bin is 0.8245; the unchanged
qualification oracle permits this isolated low bin. Replaying all 100 complete
readiness/warmup/measured reports verifies **5,536,483,840 exact requests and
latency samples, zero unexpected errors**, exact wire bytes and CPU clocks.

Separate count-only AB/BA runs each finish 2,097,152 requests with 16,453 SQEs,
32,841 CQEs, 60,818,848 received bytes and 104,858,096 sent bytes. Counts match
exactly, including final GOAWAY bytes; no ENOBUFS/EAGAIN or request errors.
Baseline entry counts are 2066/2066; candidate 2072/2062 (about 15.85–15.93
completions per entry). Traces prove deferred setup and GETEVENTS on every
candidate entry. These counts establish no syscall-frequency reduction or
quantity of avoided task work; instrumented timing is excluded.

374 Rust tests pass in each profile on the candidate and in each profile with
forced ordinary setup. Formatting, strict production Clippy, 17 independent
protocol/TCP invocations, 12 forced-fallback invocations, 11 cohort-oracle tests
and 16 ordinary native accounting guards (163,840 samples) pass. One compiled
no-zero-GETEVENTS mutation fails two distinct progress regressions as intended.

## Limits and ordinary costs

Saturated worst-child p99 falls in all seven pairs, but p99.9 rises in six
(up to 3.981%; the remaining pair falls 2.447%). This is not a general latency
improvement or latency-equivalence result.

Additional fixed ordinary AB/BA guards use CPU1 server/CPU8 client, batch1/t1,
16384 warmup requests and complete reports: serial cases n65536/c1/p1;
H1 concurrent n1048576/c16; H2 low-pipeline n1048576/c1/p16. Their 36 reports
contain 9,175,552 exact requests/samples with zero errors. They are not saturated
cohorts and do not establish general speed or equivalence:

| Guard | Throughput changes, two pairs | CPU/request changes | p99.9 changes |
| --- | --- | --- | --- |
| H1 serial | -5.738%, +3.414% | +3.716%, -4.156% | +10.278%, -14.179% |
| H1 concurrent | +1.438%, +10.221% | -2.237%, -9.808% | +21.819%, -17.752% |
| H2 serial | -0.859%, -2.462% | -2.010%, +0.080% | +4.262%, -3.468% |
| H2 low-pipeline | -0.839%, -2.390% | -1.819%, +1.084% | +2.513%, +3.463% |

H1 results are mixed; the small H2 guard costs are not resolved. No serial/H1
gain or broad kernel-cost reduction is claimed. The local results support only
the saturated H2 acceptance above. Initial test integration failures (a temporary
borrow and a reused signal number) were fixed; failure logs are retained.

Full raw evidence, scripts, source archives and hashes are stored under the
workspace's `hfast/optimization-results/c315/`, especially `performance-gate.json`,
`operation-gate.json`, `native-audit-final.json`, `guard-timing/summary.json`,
`checks-progress.json`, `variants-summary.json` and `validation-ready-v2.json`.
