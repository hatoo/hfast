# Sustained native receive-credit cancellation

This diagnostic exercises `StreamCredits::remove` and late-ACK cancellation in
the real hfast UDP event loop. It provides an independent plaintext audit and
a native fixed-work timing mode. The pinned manual shb
packet/TLS driver is shared with `stop-batch-peer-main.rs`; production hfast and
shb source, socket sizes, windows, timers and flush scheduling are unchanged.

Build in a new output directory:

```sh
python3 benchmarks/build-receive-credit-cancel.py /path/to/shb /tmp/cancel-peer
CANCELLATION_PARENT_NETNS=$(readlink /proc/self/ns/net) unshare -Urn sh -c \
  'ip link set lo up && exec "$@"' cancellation \
  /path/to/interop-venv/bin/python benchmarks/check-receive-credit-cancel.py \
  /path/to/hfast /tmp/cancel-peer/receive-credit-cancel-peer /tmp/cancel-results
```

Use the dependencies in `interop-requirements.txt`. The builder pins shb Git
objects, runs debug/release tests and strict Clippy, and freezes a release peer
with hashes of every source and fixture input. Existing result directories are
refused. `--cohorts 16 64 256` and `--modes inline separate survivors late-ack`
select bounded cases. `--warmup 2 --cycles 18` advances stream IDs through 20
cohorts on one connection. Audits permit at most 64 total cohorts; native runs
permit at most 8,192. Both phase counts must be positive. A shell records the outer network namespace before
`unshare`; the controller requires a different namespace, process-owned socket
identities/cookies, available drop counters and zero UDP errors.

Each aborted request has correctly encoded POST HEADERS and a DATA frame
declaring a body that ends at stream offset 8 MiB. Only the 23-byte prefix and
two body bytes are sent. The large gap is intentional and never completed.
RESET_STREAM's final size accounts for that gap in QUIC flow control; **it is
not uploaded body data or a completed HTTP request**. This is a sparse aborted
upload workload, not a claim about ordinary full-body upload traffic.

Staging ends one byte below hfast's unchanged half-window credit threshold.
Each staging packet must be authenticated and acknowledged before proceeding;
normal connection-credit updates permit cohorts larger than the initial
connection window divided by 8 MiB. The threshold crossing consumes just one
additional byte of credit per staged stream. At most eight 1200-byte datagrams
are submitted in a UDP_SEGMENT aggregate. The kernel's actual GRO and receive
batch boundaries decide which updates remain queued until cancellation.

- `inline`: all threshold crossings precede all resets in one GSO aggregate.
- `separate`: an authenticated processing fence separates crossings and resets.
- `survivors`: cancel alternating entries first; observe surviving limits, then
  cancel the remaining entries after a fence.
- `late-ack`: acknowledge three later ACK-only packets before acknowledging the
  original limit packets, in the same authenticated payload. This queues and
  cancels retries before the server flushes. No server timer is disabled.

The shared manual peer enforces advertised byte/stream limits and exact ACK
coverage. It is **not a production congestion controller** and does not retry
lost fixture packets: packet gaps, duplicates, unexpected outputs and timeouts
fail closed. Its burst is bounded to eight datagrams; normal hfast recovery
remains enabled. This diagnostic therefore does not qualify lossy throughput,
production-client capacity or general QUIC recovery.

Cancelled streams require exactly one matching server reset with zero response
final size. Two later GETs must complete with the exact HTTP response and FIN;
their individual latency samples are retained separately from cancellation
latencies. Each cancellation sample retains its stream ID and runs from the
cohort's crossing-burst start until its authenticated reset is checked. The
whole cancellation interval and whole cycle interval are recorded separately.
Cumulative flow/credit and authenticated fences are retained for every cycle,
along with each sample’s stream ID. Every original packet and terminal reset/response is fenced by
an authenticated ACK. The peer stays alive while the controller snapshots both
sockets, then sends an authenticated close. Cleanup is bounded on every path.
Native datagram counters include TLS and each GSO segment. Linux `InDatagrams`
counts receive messages, including one per intact GRO aggregate. Namespace
delivery must equal both directions' native datagram counts plus the final close,
minus the GSO segment excess. Authenticated packet fences require every segment
separately. This gate requires intact GRO delivery and fails on a host that
splits aggregates. Observer runs independently reconcile actual receive-message
and segment counts. `OutDatagrams` is recorded separately.

`receive_credit_cancel.py` independently decodes plaintext using aioquic and
QPACK using pylsqpack. It reconciles transmitted bytes, sparse high-water offsets,
reset final sizes, exact advertised credit, successful and cancelled counts,
and response/retirement fences. Fifteen transcript/report mutations per
sustained case must
fail for their named reason: omitted/duplicate reset, wrong final sizes,
premature success, missing final fence, omitted cancellation, counting holes as
uploaded bytes, missing latency, and incorrectly claiming timing qualification.
These are offline negative controls; they do not claim independent TLS coverage.

For untimed coverage, a disposable server observer may emit `C411_CREDIT`,
`C411_RECEIVE` and `C411_RX` JSON records. The controller checks accepted receive
state against the independent transcript. Missing observer records are reported
as unavailable, never zero cancellations. Observer counters cannot be used as
timing evidence. The c411 experiment keeps the exact observer patch and source
manifest under `optimization-results/c411/`; it is not part of production code.

Queue exposure alone does not establish a throughput gain. Use the timing
controller only after the audit confirms the relevant queue exposure:

```sh
CANCELLATION_PARENT_NETNS=$(readlink /proc/self/ns/net) unshare -Urn sh -c \
  'ip link set lo up && exec "$@"' cancellation \
  /path/to/interop-venv/bin/python benchmarks/compare-receive-credit-cancel.py \
  /path/to/baseline /path/to/candidate /tmp/cancel-peer/receive-credit-cancel-peer \
  /tmp/cancel-primary --order ABBAABBA --warmup 32 --cycles 2048
```

Run independent confirmation into a fresh directory with `--order BAABBAAB`.
Each variant uses the same release peer, fixed work, affinity (server CPU 2,
peer CPU 4 by default), and normal transport settings. The controller checks
hashes before and after. Do not compare different modes/cohort sizes as a gain.
Rates are **sparse cancellations per second**, including staging, retirement
fences and two successful GETs per cycle, not completed upload RPS.

Warmup runs natively on the same connection. Python then snapshots process CPU,
resident/anonymous memory and sockets outside the timed interval, releases one
start barrier and blocks until the native producer finishes all cycles. Native
CLOCK_MONOTONIC/process CPU timestamps bracket only these cycles. JSON output
and all Python checks happen afterward; trace logging is disabled. The native
peer bounds sent-packet and cumulative flow snapshots, clearing them only after
a final authenticated fence. MAX_DATA is checked against the acknowledged
packet's flow snapshot, because earlier grants can arrive after a later send.
All terminal outcomes, bytes, stream credit and every latency sample are checked
inside the producer and again through compact cumulative receipts afterward.
Plaintext audits additionally verify each cycle’s exact ACK/credit tuple.

The external server CPU interval includes small barrier/report overhead; its
0.01-second process ticks have a conservative two-tick uncertainty. Peer CPU
uses the native process clock. Pre/post resident-memory readings include
allocator retention and do not prove a queue-only memory change or peak RSS.
The indexed runtime candidate has a known larger slot representation; these
measurements must retain that tradeoff. Large/small, ordinary H1/H2/H3 and tail
guards still apply before publishing a runtime performance improvement. WSL
small-effect/tail limitations and general hfast recovery limitations remain.
`timing_qualified: false` means host/acceptance qualification is external; it is
never silently promoted merely because a run completed without errors.
