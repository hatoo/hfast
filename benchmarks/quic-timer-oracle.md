# QUIC endpoint timer regression tests

`src/quic/endpoint/tests/timers.rs` checks the endpoint's timer dispatch against
an independent logical schedule and authenticated QUIC traffic. The production
`tick` still reads the clock once and performs the same full scan, snapshot of
due addresses, strict idle-expiry comparison, and timeout/flush sequence. Its
private `tick_at` helper lets tests supply exact instants without sleeping.

Run the focused tests in both profiles:

```sh
cargo test --locked quic::endpoint::tests::timers
cargo test --release --locked quic::endpoint::tests::timers
```

The normal CI debug and release suites include these tests automatically.

## Contracts

- Empty and quiet endpoints; idle survival at exactly 30 seconds, removal one
  nanosecond later, and a distinct connection when the address is reused.
- Two reproducible 4,096-step schedules mixing admission, deadline changes,
  cancellation, receive-time refresh, authenticated close, expiry and reuse.
  A separate `BTreeMap` model predicts the surviving peers and timer dispatch
  counts using only the input schedule. It never queries production deadlines
  to decide what should happen.
- Simultaneous deadlines on several peers, including idle expiry taking
  precedence over PTO and a timer due one nanosecond after the current tick.
- Actual transmission arming PTO, no dispatch before the exact deadline, and
  retransmission flushed by the endpoint when the deadline is reached.
- An authenticated ACK resetting backoff and shortening a remaining flight's
  deadline even though processing that ACK produces no output.
- Receive-key retirement with no outstanding PTO, both before and after
  flushing the pending receive; key retirement must not trigger recovery.
- A lost response retransmitted at PTO and a late ACK of its original packet
  retiring the request exactly once and cancelling the retry's timer.

The authenticated cases complete the test TLS handshake and send encrypted
packets through endpoint receive/flush/tick. Emitted packets are collected from
the UDP socket, authenticated using the client's keys, and checked for packet
number, key phase, expected response bytes/offset/FIN, or ACK-only contents.
Control retransmission is compared with the original frames. The peer helper
is shared with the existing key-update tests and is compiled only for tests.

The long schedule and simultaneous-deadline case seed real transport timers
without creating outstanding packets. They test dispatch and lifecycle, not
loss-recovery throughput. The separate authenticated cases exercise real flight
state. These tests neither establish that all QUIC recovery limitations are
fixed nor claim a performance improvement.

Semantic mutation checks during development remove transport dispatch, change
idle expiry to `>=`, postpone transport dispatch after backoff reset, and omit
the recovery flush. Each must compile and fail a relevant test; an unmodified
control must pass. The isolated mutation sources and logs are retained with
the optimization experiment rather than added to the production build.
