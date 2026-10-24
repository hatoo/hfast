# Independent QUIC recovery oracle

`quic-loss-check.py` is an **untimed correctness check**. It runs an independent
aioquic HTTP/3 client through a UDP relay and retains a ledger for every requested
stream. Each response must have exactly one status 200, the exact 13-byte
`Hello, World!` body and one FIN. Unknown streams, resets, duplicate headers,
extra or truncated bodies, missing FINs and late response events fail the case.
Completed streams stay in the ledger until the connection closes.

Install the pinned `interop-requirements.txt`, then run:

```sh
python -m unittest discover -s benchmarks -p test_quic_recovery.py -v
python benchmarks/quic-loss-check.py target/release/hfast --output /tmp/quic-recovery
python benchmarks/quic-loss-check.py target/release/hfast --threads 2
HFAST_GRO_BINARY="$PWD/target/release/hfast" python benchmarks/quic-loss-check.py \
  benchmarks/without-udp-gro.py --threads 2
```

The binary argument is explicit; no CPU or source-checkout path is hard-coded.
Server, relay and clients use ephemeral loopback ports. Before impairments begin,
a separate handshake and exact GET response prove server readiness. Server exits,
workload deadlines, QUIC shutdown and process termination are bounded; a process
that ignores SIGTERM is killed and reaped. Each case defaults to 64 GETs followed
by 64 POSTs on one connection. One/two-worker tests exercise the server's existing
CID routing; they do not guarantee an even distribution across workers.

The default suite has eight named schedules:

| Scenario | Impairment |
| --- | --- |
| `clean` | No injected impairment |
| `client-initial-loss` | Drop the first client Initial datagram |
| `server-initial-loss` | Drop the first server Initial datagram |
| `client-loss` | Drop the first two client short-header datagrams of each batch |
| `server-loss` | Drop the first two server short-header datagrams of each batch |
| `bidirectional-loss` | Apply both batch loss schedules |
| `reorder` | Hold the first short-header datagram in each direction until the next one overtakes it, for each batch |
| `duplicate` | Deliver the first short-header datagram in each direction twice, for each batch |

The request schedules are armed after a confirmed handshake and between completed
GET/POST batches. A PING fence follows each batch. Per-direction ordinal schedules
do not depend on which direction's callback runs first. Every intended impairment
must actually occur; a reorder with no overtaking datagram fails. Initial packet
types and short headers are visible on the wire. The relay **does not identify
encrypted STREAM/ACK frames**; these are datagram-level schedules, not assertions
that a particular response or credit frame was dropped. The existing CRYPTO,
control, credit, stream and response recovery fixtures provide that focused
coverage and remain in CI.

`--output` creates a new directory (existing evidence is never overwritten) with
one JSON report per case. Reports include readiness and per-stream response
ledgers, missing stream IDs on failure, process exit status, server logs and every
received datagram's phase, direction, ordinal, length, SHA-256, action and delivery
references. A held datagram is referenced by the later delivery that releases it.
Failures print the full report so CI logs also retain the trace.

Seeded random loss is a separate exploratory mode, excluded from the default CI
suite. Each direction has its own RNG. Both directions must experience loss:

```sh
python benchmarks/quic-loss-check.py target/release/hfast \
  --scenario seeded --seed 42 --loss 0.05 --output /tmp/quic-seeded
python benchmarks/quic-loss-check.py target/release/hfast \
  --replay-trace /tmp/quic-seeded/seeded.json --output /tmp/quic-replay
```

Replay applies saved actions at each phase/direction/ordinal and requires the same
packet kind, length and number of eligible datagrams. It fails on divergence;
there is no fallback that silently applies actions to different packetization.
Encrypted bytes and packet timing can differ between connections, so replay does
not promise identical ciphertext or a reproducible arbitrary recovery failure.
A failed exploratory trace still needs minimization before changing production.

An optional native-client check requires an explicit path:

```sh
python benchmarks/quic-loss-check.py target/release/hfast --scenario seeded \
  --shb /absolute/path/to/shb --requests 1500 --output /tmp/quic-native
```

This requires exactly 3,000 successes and zero errors in shb's report. It checks
aggregate accounting only and cannot substitute for the independent response
ledger. It is not a throughput benchmark. Native replay is unsupported.

`test_quic_recovery.py` checks exact fragmented responses, missing/duplicate/
truncated/wrong responses, schedule independence, exact hold/copy delivery,
missing impairments, replay divergence and callback error propagation. Live
aioquic fault servers also exercise wrong status/body, truncation, extra data,
stream reset, missing response and missing FIN. Process tests cover startup exit,
startup timeout, forced termination and socket release.

These bounded scenarios strengthen recovery coverage. Passing them does not
establish general QUIC loss recovery or any performance improvement. Normal UDP
delivery with GRO enabled is not proof that the kernel coalesced packets; the
existing `gso-fixture.py`/`gro-interop.py --gso` checks cover actual UDP_SEGMENT input.
