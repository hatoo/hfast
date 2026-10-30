# Sustained response-credit workload

This experimental fixture extends the published single-wave response-credit
oracle with bounded live waves and batched packets. It changes no production
server/client source. It is a workload generator, not evidence that a server
optimization is faster. Keep the original `response-credit-peer-main.rs` and
its independent trace checks available.

Build from immutable shb Git objects and save an immutable binary:

```sh
python3 benchmarks/build-response-credit-sustained.py /path/to/shb /new/build
python3 -m unittest discover -s benchmarks -p 'test_response_credit*py'
python3 benchmarks/response-credit-sustained-interop.py \
  /new/build/response-credit-sustained /new/interop
unshare -Urn sh -c 'ip link set lo up && exec "$@"' credit-waves \
  python3 benchmarks/response-credit-sustained-check.py \
  /immutable/hfast /new/build/response-credit-sustained /new/qualification \
  --count 2097152 --window 512 --schedule byte --cpu 8
```

All artifact directories must be new. Interoperability uses the existing pinned
`interop-requirements.txt` environment. The builder runs debug/release tests,
strict Clippy, and saves compiler/source/binary hashes. A shared build cache may
be supplied with `NATIVE_PEER_TARGET_DIR`; saved binaries remain independent.
The native CLI takes `PORT COUNT WINDOW SCHEDULE MODE TIMEOUT_SECONDS`, optionally
`--trace` and/or `--controlled`. The controller supplies the latter flag.

Schedules are separate workloads: `byte` grants 1,2,...,25; `two-byte` grants
2,4,...,24,25; `two-fragment` grants 1 then 25; `full` grants 25 immediately.
The two-fragment allocation experiment cannot be compared to the two-byte case
as if they were the same workload. Each later grant requires the preceding
byte prefix and its grant ACK. At most 32 requests or grants share one packet;
ACKs are batched after a receive drain, without changing any grant generation.

The wave ledger retains at most 512 active stream records and up to 4,194,304
samples. Stream IDs always increase. Admission requires sufficient real
MAX_DATA and MAX_STREAMS credit; stale credit cannot revoke a newer limit.
Retirement requires every literal response byte, valid FIN, original first-send
and completion timestamps, request ACK, and final grant ACK. Retired stream
frames still undergo byte/FIN validation and cannot complete a new slot.
Response connection credit is explicitly advertised as `25*COUNT + 3`, including
server SETTINGS, so sustained responses cannot silently exhaust a fixed 1 MiB
receive window. The request-side byte ledger also includes five control bytes.

Each outstanding packet batch retains every original/retry packet number until
an authenticated ACK covers a copy. These identities and receive/ACK histories
survive wave retirement. A response never acknowledges its request. There are
at most 64 live batches, 128 copies per batch, and 16,384 disjoint ACK intervals;
exhaustion fails explicitly. New grants wait if all batch slots are occupied.
The fixture uses a 50 ms retry timer, a fixed connection/key phase, localhost,
and explicit deadlines. It is not a general-purpose QUIC implementation.

With `--trace`, bounded transcripts retain every sent work item and received
STREAM frame for an independent Python set/byte oracle. Without it, the peer
still validates every byte/FIN and retains every sample, while omitting only
per-frame/per-work traces. It emits all samples after measurement. No latency
sampling, overwritten history, stream-ID reuse, per-wave TLS restart, or
per-wave process startup is used.

Controlled runs use `ready/start`, `stopped/report`, and `done/exit` barriers.
The server CPU and socket snapshots are taken at `stopped`, before the large
sample report is serialized. Peer process CPU and monotonic clocks bracket
only the complete workload interval. The controller records exact process/socket
identities, affinities, actual receive buffers, drops, and namespace datagrams.
Both sockets request 4 MiB; observed host capacity is the authority. Private
network namespaces are required for exact datagram accounting. Controller report
assembly is bounded and linear in the report size, outside measurement.

The independent aioquic fixture checks serialized TLS limits and QPACK, actual
wire grant generations and ACK unions, delayed original ACKs after retries,
late old ACK/FIN frames during a new wave, blocked and reordered connection/
stream credit, loss/reordering/sparse ACK schedules, and stream-ID width changes.
Hostile cases must fail rather than infer completion or ACKs. The standalone
wave tests include 1,024 generations per schedule and exact allocation/sample
checks. Compiled mutations of ACK gates, retired identity, timestamps, packet
copy retention and retry scheduling must fail the appropriate model/wire tests.

Qualification requires a continuous interval of at least ten seconds, complete
counts/samples, zero unexpected errors/drops, and both process CPU intervals.
Busy-spinning peer CPU alone does not prove the peer is the bottleneck. Establish
server saturation before using this fixture for a server speedup claim; report
an unsaturated result as a workload limitation. Then freeze peer/workload and use
alternating immutable server binaries plus separate confirmation. WSL throughput
noise and broader QUIC recovery limitations remain.

CI runs both Rust profiles, strict lints, independent multi-wave/fault peers,
report negative controls, and native 1,024-request/512-slot runs for each grant
schedule. It retains reports and socket evidence as an artifact. CI runs are
correctness gates; their durations are not a performance acceptance test.
