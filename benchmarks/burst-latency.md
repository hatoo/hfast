# Exact request latency in the native burst fixture

The coordinated native burst fixture can retain every request latency with
`--latency`. Use one or four producers. Without this flag the original reports,
commands and throughput-only mode remain available. The legacy positional peer
mode does not support sampling; use `--producer-cpus CPU` for one sampled producer.
No production hfast or shb code changes are involved.

```sh
python3 benchmarks/build-sparse-ack-peer.py /path/to/shb /new/peer --burst
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' sampled-bursts \
  python3 benchmarks/compare-bursts.py /immutable/baseline /immutable/candidate \
  /new/peer/burst-peer /new/comparison --producer-cpus 8,10,12,14 \
  --batch 18 --datagrams 2 --batches 4096 --cycles 8 --warmup 128 \
  --pairs 3 --latency
```

Repeat with `--reverse` in a new output directory for independent order
confirmation. Both variants must use the same immutable sampling-enabled peer,
workload, buffer request and observed server capacity. For 1024-request bursts,
use the previously validated `--udp-receive-buffer 4194304` on both variants and
check their actual capacities. Do not compare old throughput-only results to
sampling-enabled results as an optimization gain. Sampling adds real clock and
memory work; it changes the workload even though allocation and export are untimed.

## Interval and accounting

Each request starts at the monotonic `Instant` read immediately before the
burst's atomic `sendmsg` submission (including its small ledger checks). Requests
in that GSO message share a send timestamp. Completion gets a fresh clock read
for **each** stream after packet authentication and exact response bytes, stream
membership, offset, body, status and FIN validation. It includes syscall time,
network/server work, next-burst preparation and client decryption/parsing before
that response. It excludes request construction/encryption before submission and
the subsequent ACK/credit fence. This interval differs from shb's ordinary latency.

No per-packet timestamp is reused as a completion time. Missing, duplicate,
unexpected and partial responses cannot create successful samples. The quiet
connection produces no request samples. Warmup (phase 0) and measurement (phases
1 through N) retain separate exact counts and summaries. Existing protocol,
credit, fence, UDP error, socket queue/drop and buffer-capacity gates still apply.

The controller uses `PREPARE phase batches` before starting its wall and CPU
interval. The worker allocates and touches a bounded ledger and reports ready.
The existing `RUN` releases timed work. Its bounded completion report contains
sample metadata, and the worker waits. Only after wall/CPU accounting and delivery
checks finish does `EXPORT phase` permit sorting and writing the samples. The
controller immediately checks metadata, file size/type and its fixed-size header.
Full record validation and percentile calculation occur after all workers stop,
so scanning large files cannot expire an idle connection between measured phases.
Every sample must pass before `result.json` or a comparison summary is produced.

## Bounds and evidence format

The opt-in limits are 4,194,304 samples per worker per phase and 64 measured
phases. All original batch/datagram/batches limits also apply. Counts are checked
before allocation or process launch; requests are never silently subsampled or
split into a different workload. Native ledger storage is 24 bytes/sample (at
most 96 MiB/worker), released before preparing the next ledger. Phase reports
keep the original 65,536-byte bound. Sidecar size is exactly `32 + 24 * count`
bytes. Provision disk space for every warmup and measured phase before a large run.

Each worker exclusively creates `latency-I/phase-P.bin`. All integers are unsigned
64-bit little-endian values. The 32-byte header is magic `HFBSTL01`, phase,
first stream ID and sample count. Each 24-byte record is stream ID, send timestamp
and completion timestamp, in nanoseconds relative to that worker phase's epoch.
Records are sorted by `completion - send` during untimed export. Stream IDs and
timestamps retain the original identities; no precision is discarded.

An independent Python reader checks exact file length, header, stream membership,
uniqueness, timestamps, identical send times within each burst and serial burst
ordering. It rejects zero/reversed durations, invalid phase bounds, truncated or
oversized files, nonregular files and symlinks. A compact membership bitmap and
two timestamps per burst bound validation memory. SHA-256 is recorded for every
validated file and rechecked during percentile calculation.

The final summary merges sorted files using bounded buffers and at most 256 open
measured files (four workers times 64 phases). It retains exact count, sum,
minimum, maximum and nearest-rank p50/p99/p99.9, plus the arithmetic mean. Warmup
has its own summary. Percentiles are over every measured request in the run,
including all producers and phases, rather than averages of worker percentiles.

Failures keep the original exception and existing process/socket diagnostics.
Native failures also attempt a diagnostic `failure-P.bin` export of completed
samples; failure exports never constitute a successful phase. Diagnostic write
errors cannot replace the triggering error. A producer exit during transfer,
bad export or later sample validation failure rejects the entire run. Valid
earlier sidecars and raw report logs are retained.

## Regression coverage and limits

The builder runs the pinned native transport's debug and release suites, including
deterministic injected-clock tests for completion order, phase bounds, missing
responses, duplicates, wrong IDs, partial FIN/body/status and disabled sampling.
`test_burst_latency.py` independently constructs binary exports, corrupts their
identities and timestamps, checks exact merged quantiles and asserts that
preparation/export/scanning remain outside controller wall/CPU measurements.

`burst-latency-check.py` runs one/four producers at 1, 36, 64 and 1024 outstanding
requests with native GRO/GSO and real GRO-denial fallback. It checks observed
capacity at default and explicit receive-buffer settings. It also injects
truncated/oversized exports, wrong phases, duplicate IDs, zero durations, producer
exit and a native invalid export command. All faults must fail without publishing
successful results or losing previous samples. Existing throughput-only/legacy
smoke and failure tests remain in CI.

This tooling establishes sample correctness, not a server speedup or latency
equivalence. Short smoke timings are not performance evidence. The experimental
short-header-budget candidate still needs independent stable-host confirmation
of persistent and ordinary workload tails. This fixture neither resolves WSL
timing uncertainty nor proves general QUIC loss recovery.
