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

The wave ledger retains at most 4096 active stream records and up to 4,194,304
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
exhaustion fails explicitly. Request admission and new grants wait if all batch slots are occupied. A large
wave resumes at its next unsent request after authenticated ACKs free slots;
first-send timestamps and the all-request-ACK gate are preserved.
The fixture uses a 50 ms retry timer, a fixed connection/key phase, localhost,
and explicit deadlines. It is not a general-purpose QUIC implementation.

With `--trace`, bounded transcripts retain every sent work item and received
STREAM frame for an independent Python set/byte oracle. Without it, the peer
still validates every byte/FIN and retains every sample, while omitting only
per-frame/per-work traces. It emits all samples after measurement. Failed reports
also retain live byte/FIN/ACK state and timestamps, including complete responses
whose request or grant ACK has not arrived. No latency
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

## Aggregate connection-credit mode

Pass `--connection-credit` to the peer or native controller to exercise repeated
MAX_DATA wakeups. In this mode `byte`, `two-byte`, and `full` mean connection
increments of 1, 2, and 25 bytes respectively; `two-fragment` is unsupported.
The existing stream mode, including its ordinary `full` control, is unchanged.
Workloads with different credit scopes or increments are separate comparisons.

Initial MAX_DATA is exactly 3 for the server control stream. Bidirectional stream
credit is 25. Each wave's requests must all be acknowledged before its first
connection grant. A grant advances only after every previously granted unique
byte arrives and an authenticated ACK covers a retained copy of the preceding
grant. Retries retain the same cumulative limit. Final short increments stop at
the wave boundary; retirement also requires the final connection grant ACK.

`response-credit-connection.rs` keeps bounded live stream masks and cumulative
byte/credit/ACK totals. QUIC flow control charges each stream's highest offset,
including gaps and frames the fault harness deliberately discards. Separately,
delivered unique bytes gate further grants. Overlaps and retransmissions consume
no new credit. The ordinary wave ledger still validates literal response bytes,
FINs, request identity and every latency sample. The aggregate ledger starts
from the reserved three-byte control prefix. The driver authenticates that prefix
and its bootstrap ACK before starting a wave or reporting aggregate totals. A
failed bootstrap reports the actual control count and no aggregate ledger.

Traced reports include ordered connection events. An independent Python set
oracle checks grant/ACK/unique-byte order, highest-offset credit, wave identity,
and parity with the received-frame and retained-flight transcripts. Untraced
reports retain all samples and cumulative ledgers without the event history.
The independent aioquic suite verifies actual serialized transport parameters,
MAX_DATA generations, delayed original request/grant ACKs, and rejects over-credit
bytes, forged ACKs of an intentionally unsent grant, missing ACKs/FINs and corrupt
bytes. These checks qualify a workload; they establish no throughput improvement.


## Window boundaries and bounded traces

The peer admits windows 1 through 4096. The native controller explicitly sets
server stream capacity to `max(1024, WINDOW)`; record that configuration when
comparing runs. CI retains 1/16/512 cases and adds 511/513/1024 windows with
`2*WINDOW+1` responses for each aggregate increment, plus 4096-window controls
with 4097 responses in both ordinary full-credit and aggregate 25-byte mode.
The independent aioquic server also exercises 513/1024/4096 and final short waves.
These are correctness qualifications, not native performance comparisons.

Traced workloads are checked before opening a socket. Let N be request count,
W the window, K=ceil(N/W), and G the sum of ceil(25*wave_size/step) over waves.
A conservative transcript allowance includes 26 frames per response (one frame
per byte plus a separate FIN). The per-table bound is `2*(53*N+2*G+2*K+8)+4096`
in aggregate mode and `2*(26*N+8)+4096` in stream mode, with a minimum of 131072
to preserve the prior allowance for small hostile/withheld-ACK cases. The factor two allows
retries/duplicates, and 4096 extra events allow control/PING traffic. Every table
remains capped at 1,048,576 entries. Larger traced workloads fail before transport;
untraced runs retain the existing 4,194,304-sample limit. Arbitrary loss can still
exhaust a transcript: that is an explicit failed run, never evidence silently
omitted from a successful report. This is an event bound, not a byte/RSS bound.

For example, aggregate byte grants at N=2049/W=1024 have a 426218-event bound;
N=4097/W=4096 with 25-byte grants has a 454790-event bound. N=8193/W=4096 byte
grants exceed the cap and are rejected. Reports include `trace_limit`; the
independent validator derives the expected bound and checks each transcript.
Tests cover upper-limit rejection, runtime exhaustion without overwriting prior
evidence, duplicate credit, partial waves, and process exits/deadline cleanup.
