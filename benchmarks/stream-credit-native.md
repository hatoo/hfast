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
