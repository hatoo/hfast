# HTTP/3 response flow control

The previous server decoded the peer's transport parameters but sent whole
responses and SETTINGS without enforcing their byte limits. It also ignored
MAX_DATA/MAX_STREAM_DATA updates and opened its control stream with a zero
unidirectional stream allowance. On baseline `074d9f6`, independent aioquic
1.3.0 closes with FLOW_CONTROL_ERROR for a 1-byte response window, a 4-byte
connection window, or a 1-byte control window. A zero uni-stream allowance
produces STREAM_LIMIT_ERROR. These are actual advertised QUIC limits, not
application read-buffer sizes.

The repair charges connection credit for fresh bytes on all outgoing streams,
including SETTINGS. Stream offsets and limits are capped at the fixed payload
lengths, with compile-time size checks. Ordinary replies retain their complete
single-frame path. Credit-fragmented replies keep exact byte ranges and up to
eight packet numbers per range, so retries consume no new credit and a late
ACK can cancel a queued retry. Completion requires every range, including FIN,
to be acknowledged. STOP_SENDING resets at the actual highest sent offset.

Blocked responses leave the ready queue. An increasing stream grant wakes only
that stream; increasing connection credit visits the connection-blocked set.
Zero, duplicate, or decreasing limits cannot revoke credit. SETTINGS separately
waits for stream-count, stream-byte, and connection-byte credit. The relevant
requirements are [RFC 9000 section 4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1)
and [section 4.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6).

Run the independent fixture with:

```sh
python -m pip install -r benchmarks/interop-requirements.txt
cargo build --release --locked
python benchmarks/response-credit-check.py target/release/hfast
```

Its nine cases cover zero and tiny stream windows, sparse grants to 32
requests, connection exhaustion including SETTINGS, zero control credit,
zero uni-stream allowance, cancellation after four response bytes, dropped
response fragments, dropped credit updates, reordered duplicate packets, and
GET/POST followups. It checks authenticated frame offsets, every response byte,
single delivered FINs, reset final sizes, and the serialized transport parameters.
Automatic client window growth is disabled; intentional grants retain aioquic's
delivery callbacks and recovery. Baseline fails the same fixture at response
offset 25 with a stream limit of 1. The repaired server passes 599 initial
responses, one intentional cancellation, and 72 followups.

The `sparse-acks` case starts 512 responses with one byte of receive credit
each. It loses two response packets, replays delayed duplicate packets, and
then grants three increments to each of four widely separated streams while
the other 508 remain blocked. PING/ACK traffic and stale grants accompany
each increment, including one lost grant. A final dense refill completes all
512 responses with exact bytes and one delivered FIN each. It runs in the
existing required response-credit CI step and can be selected with
`--case sparse-acks`. This is correctness coverage, with no rate measurement.

Validation on Rust 1.98.0: 214 debug tests, 214 release tests, all 16 independent
protocol fixtures, formatting, and strict production Clippy pass. Strict
all-target Clippy still reports the three existing test lints (two H2 unused
assignments and UDP type complexity); this change does not suppress them.

Deterministic x86-64 measurements keep Request, StreamSlot and whole-response
flight records at 16 bytes each. Connection grows from 2520 to 2600 bytes.
After warmup, 1000 ordinary cycles at 1/32/128 streams retain zero allocations,
zero heap growth and the same ready-loop visits as baseline. With 128 blocked
responses, 1000 idle send attempts visit zero responses and allocate nothing;
one stream grant visits one response. Fragmented responses allocate bounded
range/history state, and ACK/PTO processing currently scans those entries.

Matched release binaries with fixed shb `443f9d7` completed 12,684,480 GET/POST
requests including warmups, with zero errors. Three alternating pairs and three
reversed confirmation pairs gave median RPS changes of +3.036%/+2.861% for GET
and +0.105%/+4.436% for 65,543-byte POST. These short WSL controls are mixed and
do not establish a throughput gain, regression, or equivalence. This is a
correctness repair; broader QUIC loss/congestion-control limitations remain.
