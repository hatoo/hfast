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
