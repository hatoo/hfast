# HTTP/3 stream receive credit

This document records the c94 repair and its original costs. This branch's
experimental c95 layout and measurements are in
[Sparse stream-credit recovery](sparse-stream-credit.md).

Previously each stream had a fixed 16 MiB receive limit. hfast waits for request
FIN before answering, so larger request bodies stalled even though received
data is immediately discarded. The c94 repair sends MAX_STREAM_DATA as offsets
advance. It applies to client bidirectional and unidirectional streams.

The stream table and request slots keep their existing layout. Credit state is
allocated lazily when a still-open stream consumes half of its initial window.
A pending queue supplies frames without scanning the request table. Only limits
that fit in an outgoing packet authorize further data; queued increases do not.
Connection credit and final-size checks still apply independently. Stream and
connection byte limits saturate at QUIC's largest variable-length integer.

Updates survive PTO and packet-threshold loss, including sparse ACK ranges.
An ACK for an obsolete limit cannot acknowledge a newer one. Each extended
stream retains at most eight packet numbers for its latest limit; forgetting an
older copy can cause an extra retransmission, but cannot invent delivery. FIN
and RESET_STREAM cancel the stream's credit state. The existing receive state
continues to validate its final size. STOP_SENDING affects the response direction
and does not cancel the request's receive credit.

This follows the receive-credit and retransmission rules in
[RFC 9000 Sections 4.2 and 13.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3).
It does not establish that other QUIC recovery limitations are resolved.

## Reproduce the correctness checks

```sh
CARGO_INCREMENTAL=0 cargo test --locked
CARGO_INCREMENTAL=0 cargo test --release --locked
CARGO_INCREMENTAL=0 cargo build --release --locked
python -m pip install -r benchmarks/interop-requirements.txt
python benchmarks/stream-credit-check.py target/release/hfast
```

The independent aioquic client sends two concurrent 16,842,759-byte POST bodies
per connection. It waits for every byte of each encoded request to be ACKed
before sending FIN, then checks status 200, the exact response body, and the ACK
of FIN. This prevents a response after an early FIN from concealing missing
request data. hfast intentionally does not interpret the body's content.

The three connections exercise ordinary delivery, repeated credit-packet loss
until the sender blocks, and delivery of obsolete credit packets in reverse
order with duplicates after recovery. Each connection then completes eight
additional GET/POST requests. The fixture is part of required CI.

Baseline 30b137401746eab4fc9670550e143ce313e489b2 stalls at exactly 16,777,216
bytes sent and acknowledged, with an encoded request end of 16,842,787 and no
response. The fixed server completes all six large requests and 24 followups.
Unit regressions additionally cover partial packet room, independent connection
credit, FIN/RESET before and after updates, STOP_SENDING, retired duplicates,
encrypted replay, sparse ACKs, late ACKs, varint boundaries, and 100 consecutive
lost transmissions with bounded history.

## Costs and scope

On x86-64, Request and StreamSlot remain 16 bytes. Connection grows by one
optional pointer (8 bytes). A connection with extended receive windows allocates
a 96-byte StreamCredits container, hash-table entries with 96-byte Update values
plus keys and table overhead, and an 8-byte pending stream ID per queued update.
All credit state is released once the last extended stream reaches FIN/RESET.
Small requests allocate no receive-credit state. ACK handling visits the map of
extended streams only while some credit is in flight; the request table is never
scanned for this purpose. These costs are correctness overhead, not speed gains.

The local full debug and release suites pass 205 tests each, including 17 new
regressions. All 14 independent interoperability scripts pass. Production strict
Clippy and formatting pass. Strict all-target Clippy still reports the baseline's
two unused H2 test assignments and one UDP test type-complexity warning; these
unrelated tests are unchanged.

No end-to-end throughput improvement is claimed. Ordinary GET/POST comparisons
use matched production builds, immutable binaries, fixed shb 71ce291, warmup,
three alternating pairs, and three reversed confirmation pairs. WSL's previously
recorded limitations on small timing comparisons remain in effect.

| Workload (one connection/worker) | Primary median RPS change | Reversed confirmation |
|---|---:|---:|
| GET, p128, 1,048,576 requests | -1.462% | +0.299% |
| 65,543-byte POST, p8, 256 requests | -5.518% | -0.426% |

These results establish neither a speed gain nor equivalence. All 12,684,480
control and warmup requests succeeded without errors. Each GET run has 8,192
warmup requests; each POST run has 16. Both production servers use rustc 1.98.0,
`cargo build --release --locked`, full LTO, and one codegen unit, with identical
compiler, feature and dependency fingerprints. Server affinity is CPUs 0,1 and
the fixed shb client uses CPU 2. Controls retain normal reporting and timestamps.

With fixed shb 71ce291 and four 16,842,759-byte POSTs (p1), the baseline has zero
successes and four 3-second request timeouts; the repair has four successes and
zero errors with a 10-second timeout ceiling. Different timeout ceilings are
used solely for this stall regression; it is not a throughput comparison. The
independent fixture above uses the same body and deadlines for both servers.
