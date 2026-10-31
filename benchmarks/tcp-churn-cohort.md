# Counted TCP churn with independent destination tuples

`tcp_churn_cohort.py` compares two immutable hfast release binaries with one fixed
shb release binary. Eight producers use `127.0.0.1` through `127.0.0.8` on the same
listener port. This separates their destination tuples while exercising one
server worker. Shared-destination connection churn can exhaust a common source
port pool before saturating the server; a high client CPU reading alone does not
identify the work responsible.

```sh
python3 benchmarks/tcp_churn_cohort.py \
  --baseline /absolute/path/to/frozen-hfast-baseline \
  --candidate /absolute/path/to/frozen-hfast-candidate \
  --client /absolute/path/to/frozen-shb \
  --output /absolute/path/to/new-evidence-directory qualification
```

Requires Linux `/proc`, GNU `time`, `taskset`, CPU 1 and CPUs 8–15. Server CPU 1
and producer CPUs 8–15 are fixed. Each producer uses HTTP/1.1, no keepalive,
64 connections, one thread, batch size one, 32,768 warmup requests and 131,072
measured requests. Both binaries must emit the normal 78-byte hfast response;
the fixed five-digit port and one-digit address suffix keep requests at 60 bytes.
Do not use instrumentation or run other benchmarks concurrently.

Every run uses a fresh listener port with no observed destination connections.
All eight destinations first receive an exact-count protocol smoke check. Socket
table observations happen before startup and after measured children finish.
They describe occupancy, not syscall time or the cause of kernel CPU usage.

The common measured interval starts before the first child launches and ends
after every child finishes. The aggregate rate uses that interval and all eight
request counts, not summed individual rates. Each child's URL, destination,
complete command, CPU, errors, status codes, bytes, latency sample count and
latency ordering are validated. GNU time counters and `/proc` task samples are
retained. A separate interval in which all request workers remain alive excludes
report-generation tails; affinity, task identities and monotonic CPU counters
are checked. Failed, missing or stalled children invalidate the cohort. Process
groups are terminated even when their wrapper has already exited.

Qualification requires both common and active intervals of at least 10 seconds,
at least 0.85 server core, and less than 0.90 core for every producer. The tool
records failed qualifications without turning them into regression evidence.
Do not retry a failed qualification unchanged.

`smoke` uses smaller budgets. After qualification, `primary` runs four alternating
AB/BA pairs; `confirm` runs three pairs with reversed starting order; `controls`
runs two identical-baseline pairs. These phases reject any cohort that stops
qualifying. They do **not** automatically establish or accept an improvement:
review independent confirmation, control uncertainty, ordinary workloads and
latency tails before making a performance claim. Compare binaries only within
identical workloads; changing destination assignment is not an optimization gain.
`failure` deliberately fails a measured child and must exit unsuccessfully.
Output paths and report files must be new, preserving earlier evidence.

The dependency-free accounting and Linux cleanup regressions run in CI:

```sh
python3 -m unittest discover -s benchmarks -p test_tcp_churn_cohort.py -v
```
