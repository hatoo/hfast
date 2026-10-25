# UDP_GRO validation with distinct native requests

The server optionally enables Linux UDP_GRO and splits each received aggregate
into disjoint original datagrams before QUIC parsing or decryption. Timer service
counts original datagrams, including malformed input. A denied socket option
retains ordinary UDP delivery. Linux describes the socket ABI in
[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).

Build a fixed native peer from pinned shb Git objects:

```sh
python3 benchmarks/build-sparse-ack-peer.py /path/to/shb /new/peer --burst
```

The builder extracts an archive; neither checkout is modified. Its nine oracle
tests cover missing/duplicate/wrong/incomplete responses, missing/wrong/repeated
fences, prepared stream IDs, quiet-peer accounting and GRO receive counts.
The source and binary hashes and compiler are recorded in its manifest.

Two authenticated connections exercise the default batched receive policy. The
active peer sends eight unique packet numbers containing 32 requests each. All
request plaintext is padded to the same size before encryption, allowing one
UDP_SEGMENT send per burst. Workloads and padding are identical for both servers.
Every HTTP status/header/body byte and FIN must match, and every request must
complete exactly once. A fresh authenticated PATH_CHALLENGE fence follows every
burst and requires exact replenished stream credit. The quiet peer acknowledges
PINGs at each cycle boundary and retains its original stream credit. Packet loss,
reordering, retransmission and key changes use separate independent fixtures.

Use an isolated network namespace for delivery accounting. With GRO disabled,
InDatagrams counts original datagrams; with GRO enabled it counts received
messages. OutDatagrams counts sent messages, including GSO groups. The first
command below verifies these semantics on the actual kernel, with exact bytes,
short tails and 64-segment groups. The peer then requires exact receive counts,
empty server/peer socket queues, zero UDP errors/drops, and complete authenticated
response/fence accounting. A kernel that splits GSO groups differently fails the
strict workload gate; it must not silently change the benchmark accounting.

```sh
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' gro-counts \
  python3 benchmarks/udp-gso-accounting.py
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' gro-audit \
  python3 benchmarks/gro-audit.py /immutable/baseline /immutable/candidate \
  /new/peer/burst-peer /new/audit
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' gro-benchmark \
  python3 benchmarks/compare-bursts.py /immutable/baseline /immutable/candidate \
  /new/peer/burst-peer /new/primary --batch 32 --datagrams 8 \
  --batches 4096 --cycles 16 --warmup 256 --pairs 3 --client-cpu 8
```

Repeat the last command with `--reverse` and a fresh results directory for
independent confirmation of the same workload. The server pins its single QUIC
worker to CPU 0. Report peer and server CPU utilization alongside wall throughput;
preparation, validation and the per-burst fence can limit the producer. These
measurements do not establish maximum server capacity. Ordinary fixed-shb
serial and multiplexed throughput/CPU/all-latency guards remain necessary.
The comparator rejects audit environment variables. Never time the interposer.

## Concurrent native producers

The optional coordinated mode supplies one or four independent native producers.
Each process has one active and one quiet connection and one outstanding burst.
The original positional peer command and `--client-cpu` comparator mode remain
available for reproducing single-producer experiments. The builder also runs
the worker command and four-worker response/fence oracle tests.

`burst_workers.py` owns all namespace UDP and server/process CPU snapshots. After
every worker completes handshake and warmup, it waits for all final ACKs to be
consumed and checks every socket queue. It then releases one timed phase to all
workers. At each phase boundary, all response bytes/FINs, contiguous packet
numbers, stream IDs, exact replenished credit, authenticated fences and quiet
connections must pass before it samples global counters once. Per-worker totals
are summed; overlapping process or namespace measurements are never added.
Workers retain their sockets until the controller finishes the last audit.

The controller records warmup separately, the common wall interval, each worker's
burst duration and response/delivery ledger, and server and per-worker user/system
CPU time. The common interval includes command dispatch, report validation and
final ACK/queue checks. `/proc` CPU accounting has clock-tick resolution, so short
smoke phases must not be interpreted as performance measurements. Phases time out
after 60 seconds; worker failure, partial output, missing/duplicate work or drops
fail the entire run, retain logs and terminate the remaining processes.

```sh
python3 -m unittest discover -s benchmarks -p test_burst_workers.py -v
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' concurrent-smoke \
  python3 benchmarks/burst-worker-check.py /immutable/hfast /new/peer/burst-peer \
  /new/concurrent-smoke
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' producer-utilization \
  python3 benchmarks/burst_workers.py /immutable/hfast /new/peer/burst-peer \
  /new/four-producers --client-cpus 8,10,12,14 --batches 8192 --cycles 4
```

The bounded smoke covers one/four producers, one/eight request datagrams, native
GRO and real ENOPROTOOPT fallback, plus the original peer mode. It may share
client CPUs on small CI machines and explicitly labels results as smoke data.
Performance runs require distinct client CPUs apart from server CPU 0. Compare
utilization with a separate `--client-cpus 8` run using the same server. Different
producer counts are different workloads, not evidence of an optimization gain.

For future candidate comparisons, add `--producer-cpus 8,10,12,14` to
`compare-bursts.py`. Both servers use GRO by default in this mode;
`--baseline-without-gro` and `--candidate-without-gro` install the denial wrapper
explicitly. Keep every workload setting fixed, alternate order and repeat with
`--reverse`. Preserve the ordinary shb throughput, CPU and latency guards.
Concurrent success does not establish general QUIC loss-recovery correctness or
remove the existing WSL measurement uncertainty.

Both controllers accept `--udp-receive-buffer BYTES` (0 through 4194304).
The default 0 leaves the server command unchanged. A positive value is passed
identically to both compared servers, including legacy mode and GRO denial.
The request is in `manifest.json`; an exclusive `receive-buffer.json` (or
`*.receive-buffer.json` in legacy mode) records the live server socket before
warmup. Results include before/after observations with stable process, socket
and namespace identities and effective receive capacity. All observations are
outside measured phases. Linux reports doubled SO_RCVBUF accounting; a capacity
below twice the request is explicitly marked `below_doubled_request`, which may
mean a host cap or a request the server could not apply. Missing or changed
evidence stays unavailable with a null effective capacity.

The comparator excludes unequal or unavailable effective capacities, including
capacity changes between pairs. Different receive buffers define different
workloads; they cannot establish an optimization gain. For example, add
`--udp-receive-buffer 4194304` to an otherwise fixed comparison only after a
baseline guard succeeds at that setting. Keep the request and observed capacity
fixed in the reversed confirmation. This option changes no production default,
client buffer, host setting, protocol validation or loss/queue gate.

Failed concurrent runs preserve `manifest.json`, raw stdout/stderr for each
worker, and `failure.json`/`failure.txt` before the controller kills workers.
The JSON includes initial, last-success and failure namespace counters; full and
partial reports; PID/command/exit state; and live, process-owned socket inodes,
FDs, diagnostic cookies, capacities, queues and drop counters. Socket deltas
require stable identities. The baseline socket snapshots run before the first
measured phase; failure snapshots run only after an error. Successful phase
timers, request bytes and accounting gates are unchanged.

`run-failure.json` retains the server snapshot before its teardown. If a native
worker exits first, its stderr contains a `burst_failure` JSON record with the
original error, phase, partial peer ledgers and its still-owned socket counters
and raw UDP table. Native per-socket drops come from `getsockopt(SO_MEMINFO)` on
the still-owned descriptor. A namespace-wide `/proc` walk may repeat an inode
while other sockets are added or removed; that raw table remains diagnostic
context and is not used to infer the native socket's drop count. Short or failed
socket-option reads and changed capacity remain unavailable, never zero loss.
Failure in the first connection's handshake may occur before
any native peer can be retained; missing/exited/reused/unreadable identities are
explicitly unavailable, never inferred to have zero drops. Snapshots are not
atomic. A positive drop count does not establish the sole cause of a failure.
Diagnostics use exclusive file creation; diagnostic errors cannot replace the
original exception or skip cleanup of sibling processes.

The bounded negative oracle injects exit, malformed/truncated output and real
receive-queue overflow with one/four producers and GRO/fallback. It verifies
counter/identity retention before teardown, exact overflow attribution, original
errors, reaped children, and native failure records. Its failed workloads and
the ordinary smoke's timings are not performance evidence:

```sh
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && exec "$@"' burst-faults \
  python3 benchmarks/burst-worker-fault-check.py /immutable/hfast /new/peer/burst-peer \
  /new/burst-faults
```

A fixed-server check on 2026-10-15 used accepted hfast `d2de04a` (binary SHA256
`bfe08e14e13415208af7e0fdd6bc600414a434adcbca10aa3a4613f9dcf663dc`), rustc
1.98.0 and the pinned native transport above. With 32 requests/datagram, eight
datagrams/burst, 256 warmup bursts and four phases of 8,192 bursts per producer,
the order was one/four/four/one producers on CPU 8 or CPUs 8,10,12,14.

| Producers | Measured requests/run | Requests/s in the two runs | Server cores |
|---|---:|---:|---:|
| 1 | 8,388,608 | 1,768,892 / 1,760,233 | 0.496 / 0.493 |
| 4 | 33,554,432 | 5,851,952 / 5,850,994 | 0.996 / 0.992 |

All 84,541,440 responses including warmups passed, with zero errors or pending
work. Each producer used 0.985–0.999 cores. Four producers can keep the unchanged
server worker busy under this workload. These are different offered loads, not a
baseline/candidate optimization comparison or proof of an avoidable kernel cost.

The audit interposer counts actual receive calls, entries, original datagrams,
bytes and GSO sends. It runs baseline, candidate and denied-GRO candidate using
immutable production binaries, and checks its counts against the native peer.
It makes no throughput claim. All evidence paths use exclusive creation.

Independent protocol coverage, in the Python environment with
`interop-requirements.txt` installed:

```sh
python benchmarks/gro-interop.py /immutable/candidate /new/native
python benchmarks/gro-interop.py /immutable/candidate /new/denied --without-gro
python benchmarks/gro-interop.py /immutable/candidate /new/gso --gso
python benchmarks/gro-interop.py /immutable/candidate /new/gso-denied --gso --without-gro
```

Use separate network namespaces if suites run concurrently. The denial wrapper
installs and probes an actual ENOPROTOOPT seccomp rule for UDP_GRO only. The GSO
transport wrapper groups already-encrypted bytes, verifies their exact segment
boundaries and requires actual grouped sends. It leaves each independent
fixture's loss, recovery, key, patterned-body and credit assertions intact.
Passing these cases does not establish full QUIC recovery or security coverage.

The otherwise serial late-response ACK fixture starts with two concurrent,
authenticated PINGs, giving the transport distinct datagrams to group without
relying on incidental handshake timing. Both PING acknowledgements must arrive
before response withholding starts. The original late-ACK/retry/credit checks
and the requirement to observe actual GSO sends remain intact. Failed fixture
logs are also printed into CI output.

## c142 measurements (2026-10-14)

Accepted only for the controlled GSO workload. Baseline hfast `5217970`, pinned
shb peer/client `48b2d7e`, rustc 1.98.0, release fat LTO/one codegen unit. Production
binaries contain no audit code. Server CPU 0; peer CPU 8. Each measured run performs
16,777,216 requests after 65,536 warmup requests. Six alternating pairs split into
primary and independent reversed confirmation use identical workloads.

| Phase/pair | Baseline requests/s | GRO requests/s | Baseline CPU ns/request | GRO CPU ns/request | RPS change | CPU change |
|---|---:|---:|---:|---:|---:|---:|
| primary/1 | 1,473,716 | 1,532,468 | 369.55 | 305.18 | +3.987% | -17.419% |
| primary/2 | 1,519,388 | 1,562,112 | 345.71 | 320.08 | +2.812% | -7.414% |
| primary/3 | 1,560,188 | 1,622,803 | 348.69 | 292.66 | +4.013% | -16.068% |
| confirmation/1 | 1,608,513 | 1,707,539 | 349.88 | 284.31 | +6.156% | -18.739% |
| confirmation/2 | 1,652,061 | 1,672,896 | 337.96 | 297.43 | +1.261% | -11.993% |
| confirmation/3 | 1,591,119 | 1,721,620 | 346.30 | 293.25 | +8.202% | -15.318% |

Median RPS +3.987%/+6.156%, CPU/request −16.068%/−15.318%; all six pairs
improve. Server utilization 0.468–0.563 cores, peer 0.997–1.000 cores including busy
waiting. This controlled producer/fence workload does not measure maximum server
capacity. Every run sends exactly 592,160 logical datagrams; all response bytes,
FINs, authenticated fences, queues and delivery counters pass with zero errors.

An untimed 72-burst audit receives the same 665 original datagrams in 665 baseline
messages versus 161 GRO messages; successful receive calls 302 -> 158. Denied-GRO
fallback receives 665 messages in 303 successful calls. All 18,432 responses/variant
are exact. Logical server output 659/643/659 is counted independently, so changed
ACK/batching behavior is included rather than assumed identical.

Ordinary guards hold the accepted shb binary fixed: H3 c1/p1/t1, 262,144 requests
and c16/p64/t4, 4,194,304 requests, each with 16,384 warmup requests, timeout 5s, batch-linger 1us,
client CPUs 8,10,12,14 and one server worker. Three alternating pairs per phase.

| Phase/workload | Median RPS change | Median CPU/request change | Median p50 change | Median p99.9 change |
|---|---:|---:|---:|---:|
| primary/c1p1 | -1.156% | +2.196% | +1.216% | -1.093% |
| primary/c16p64 | +7.913% | -7.303% | -5.052% | -21.303% |
| confirmation/c1p1 | +0.751% | +0.588% | -0.260% | -0.903% |
| confirmation/c16p64 | +1.334% | -1.258% | -2.219% | -20.063% |

Ordinary serial rates/latencies have mixed signs; multiplexed RPS improves in
five of six pairs. Small serial CPU costs (+2.196%/+0.588% medians) remain
unresolved in WSL2. These guards establish neither ordinary speedups nor exact
equivalence. All latency quantiles are retained in the local raw evidence; no
failed identical-binary controls were retried and no thresholds were relaxed.
Targeted gains are supported by repeated CPU savings and independent syscall
counts, not by interpreting noise as an ordinary improvement.

255,983,616 total production comparison responses including warmups, zero errors.
249 debug and 249 release tests, fmt/strict production Clippy, nine native oracle
checks, ten real-kernel accounting cases and 56 independent protocol invocations
all pass. Protocol invocations include native/ENOPROTOOPT and real GSO transport
with both modes. Unit tests include maximum 64-segment groups, short/empty tails,
metadata/address/payload truncation, buffer reuse, peer-mode transitions and
invalid-datagram timer fairness. Complete source/binary/command manifests and
raw results are preserved locally as `hfast/optimization-results/c142-*`.
