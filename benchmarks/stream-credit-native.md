# Native complete-upload credit fixture

This localhost fixture sends actual POST bodies with a pinned shb TLS/packet
protection implementation. It is a bounded manual transport driver, not shb's
production io_uring/HTTP scheduler and not a general-purpose QUIC client. Server
production source is unchanged. It supports exactly the fixed HTTP/3 response
used by hfast and the independent oracle; it fails on unsupported frames or key
updates rather than treating them as successful requests.

Build from Git objects, preserving both checkouts (Python 3.12+, Rust and Linux):

```sh
python3 benchmarks/build-stream-credit-peer.py /path/to/shb /tmp/credit-peer
python3 benchmarks/stream-credit-peer-check.py /tmp/credit-peer/stream-credit-peer \
  /tmp/credit-check --server /path/to/hfast
```

The builder pins shb `eabad04e72a0d684da06e096077cc47aca595bbc`, runs transport
and ledger tests in debug/release plus strict Clippy, and freezes a release binary
with source hashes, compiler and commands. Existing output directories are refused.
The check script requires `benchmarks/interop-requirements.txt`; it saves complete
peer JSON, stderr and server logs, including failures. It uses ephemeral UDP
ports and bounded child cleanup. `--streams 1 8 32` and `--threads 2` select
server correctness cases; `--only-server` skips already-run independent oracles.

Each upload has one static QPACK POST header block and one DATA frame. A 1 KiB
scratch buffer generates every body byte as `x`; complete bodies are never
allocated. There are at most 64 outstanding data/control/PING work items and
128 retained packet copies per item. Connection and stream byte limits are
checked before every new byte; retransmissions do not consume fresh credit.
All packet/byte intervals and credit histories have explicit limits. Exhausting
a bound fails the run without discarding history.

Every request byte, including framing, must be acknowledged before request FIN.
Completion additionally requires the FIN's ACK and exact status/header/body bytes
and response FIN. Reordered fragments and matching transport duplicates are
allowed; a second logical HTTP response, conflicting bytes, extra bytes or an
early response fails. Each completed request retains its latency even when a
later response fails. Output includes every stream's byte ranges, FIN states,
limits, packet counts and latency, plus all intended and deliberately suppressed
ACK intervals. Handshake and close are outside request latency. The elapsed
batch duration includes the configured credit/recovery schedule and control work.

UDP evidence is collected before traffic and after completion, with the peer's
elapsed duration frozen before end diagnostics. No diagnostic read is added to
the upload I/O loop. The peer reports its live socket inode, effective SO_RCVBUF,
and before/after `/proc/self/net/udp` drop counts (including the handshake).
The harness matches every server worker's `/proc/PID/fd` socket inode against
`udp`/`udp6`. Linux [SOCK_DIAG](https://man7.org/linux/man-pages/man7/sock_diag.7.html)
adds each socket's identity cookie and actual receive capacity; cookies prevent
an inode reused by a replacement socket from appearing to be a clean interval.
Per-socket deltas and namespace UDP counter deltas are saved in `*.udp.json`
before terminating the server, including on failure. Multiple workers sharing a
port are counted separately; other processes on that port are excluded.

Counters unavailable due to permissions, unsupported diagnostics, disappearance,
counter reset/wrap or a changed socket set are explicitly `unavailable`, never
zero. This invalidates a clean benchmark result. Recovered uploads with kernel
drops retain their completed counts and latency samples but also fail validation.
Intentional protocol loss schedules remain separate from unexpected kernel loss.
Namespace totals may include unrelated traffic: use a private network namespace
for attribution experiments. Snapshots are not atomic; inconsistent evidence is
rejected. Socket drops alone do not identify the kernel's reason for every drop
or establish a throughput gain.

The independent tests force overflow by filling an undrained small UDP receive
buffer, reconcile every sent datagram with delivery or loss, and identify the
dropping socket among reuseport workers. They also cover IPv4/IPv6, process
ownership, missing evidence and hostile parser inputs. Run them after the wire
checks to include the real successful-ledger mutation oracle:

```sh
STREAM_CREDIT_VALID_ROW=/tmp/credit-check/ordinary.stdout \
  python3 -m unittest discover -s benchmarks -p test_udp_accounting.py -v
```

ACKs use checked [RFC 9000 range arithmetic](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.1).
The encoder partitions the entire intended range set into packet budgets without
bridging gaps or dropping ranges. Live ACK payloads are at most 500 bytes;
independent aioquic decoding also checks 33/64/255/1100-byte budgets at all varint
width boundaries. ACK delay is deliberately zero: this fixture does not measure
RTT or congestion control. The sender uses a fixed flight window and 50 ms retry
interval, not production congestion control.

Schedules:

- `ordinary`: immediate cumulative ACKs, full concurrent uploads.
- `loss`: discard two authenticated credit packets before applying their frames
  or recording delivery; subsequent credits must restore progress.
- `reorder`: hold those two packets until all bodies are acknowledged, then
  deliver them in reverse order twice. Old limits cannot reduce current credit.
- `sparse`: suppress up to 256 authenticated ACK-only packet ACKs to create real
  gaps, and withhold credit ACKs. Pause each upload upon its first credit update.
  Once every stream has received ten distinct packet copies of its latest stable
  credit limit, acknowledge all withheld packets and require a PING ACK fence.
  Resume and complete every body. The report retains the credit history at this
  release barrier as well as subsequent history. Every withheld credit is
  eventually ACKed; the explicitly suppressed ACK-only gaps remain gaps.
- `pto`: stop all client transmission on the first credit update. Already-sent
  bytes may increase that limit; wait for a distinct packet repeating the latest
  limit during transmit silence, then resume. This proves timer-driven credit
  recovery in this schedule, not general QUIC loss recovery. This assertion is
  hfast-specific: aioquic may send only a PING probe during transmit silence.
  The hfast cases exercise it; the independent aioquic matrix uses the other
  four schedules.

Independent aioquic checks verify every POST byte, complete request FIN, flow
blocking/resumption and the union of ACK ranges observed on the wire. Negative
servers omit body ACKs, request-FIN ACKs, responses or response FINs; send early,
wrong or duplicate logical responses; and fail after one successful request to
check retained partial counts and latency. All must fail explicitly.

These are correctness fixtures. A c214 performance claim still requires a separate
untimed coverage audit, frozen equal-work alternating/reverse comparisons and
ordinary production H1/H2/H3 latency/throughput guards. Include every upload byte,
FIN, response and sample; do not report this manual driver's rate as production
shb throughput. WSL timing noise and broader QUIC recovery limitations remain.

## Coordinated complete uploads

`concurrent_uploads.py` starts exactly two independent producer processes and
connections. Both finish TLS and report readiness before either receives `start`.
No HTTP request or body is sent before that barrier. Each terminal report includes
process CPU time and Linux `CLOCK_MONOTONIC` start/end timestamps, observed only
at the upload-loop boundaries. TLS, the barrier wait and socket diagnostics are
outside that interval; per-request latency collection is unchanged. The controller
uses earliest native start through latest native finish for aggregate throughput,
retains both producers' samples, and rejects non-overlapping or inconsistent
intervals. It never sums rates or overlapping durations.

Producers retain their live sockets until the controller sends `exit`. The
controller checks each process's inode/cookie/capacity/drop evidence and records
one shared server delta and one namespace interval covering TLS through final
close. Every successfully received localhost datagram is reconciled against the
sum of both peers' sends and receives. `OutDatagrams` is recorded separately:
Linux UDP segmentation can count one send there but several delivered datagrams
in `InDatagrams`. Unavailable evidence, any unexpected drop, a missing/failed
producer, or an inconsistent ledger rejects the entire run. All raw output and
partial completed counts/samples remain on disk, with bounded child cleanup.

Run the strict stress matrix in a private network namespace:

```sh
unshare -Urn sh -c 'ip link set lo up && exec "$@"' concurrent \
  python3 benchmarks/concurrent-upload-check.py /path/to/hfast \
  /tmp/credit-peer/stream-credit-peer /tmp/concurrent-upload-check
```

The default matrix covers 1/8/32 streams **per producer**, all five schedules,
and 16,842,759 bytes per upload. `--threads 2 --without-gro --streams 8` exercises
worker sharing and fallback receive delivery. The script labels its results as
correctness smoke tests, permits producers to share a CPU on small CI hosts,
and reports recovered uploads separately when strict benchmark validation fails.
It never retries a failed case, increases socket buffers, or discards loss.

CI exercises native debug/release tests, independent controlled wire oracles
(including a complete producer alongside a late corrupted response), aggregate
clock/ledger mutations, real single-producer buffer overflow, and either child
exiting, stalling or emitting malformed/oversized output. The high-pressure
two-producer stress matrix is explicit: it can expose host queue loss and is
unsuitable as an unconditional clean-throughput CI assertion. Existing full-upload
single-producer protocol checks remain required.

The native sender busy-polls/yields while waiting, so near-100% producer CPU
occupancy alone does **not** demonstrate a client bottleneck or lack of throughput
headroom. Server CPU counters cover the controller interval through terminal
reports (excluding TLS) and have kernel tick granularity; short runs may report
zero ticks. Neither CPU evidence nor these fixture changes establish an hfast
speed improvement. Timing acceptance still requires clean, qualified workloads
and independent confirmation, including ordinary and fragmented-upload latency.
