# Experimental sparse stream-credit recovery

c95 replaces the full extended-stream map scan during ACK/PTO processing with
a vector of outstanding credit flights. A retained map entry stores the desired
and advertised limits, pending status, and a flight index. Packet history lives
in the vector until acknowledgement. ACK compaction and FIN/RESET swap removal
maintain the indices. Supersession reuses membership, and each flight still
retains at most eight packet numbers. Pending FIFO and packet budgets are kept.

This is an experimental tradeoff. Sparse recovery work falls sharply, while
singleton and several dense cases cost more CPU. No end-to-end throughput
improvement has been established, and this runtime change is not a merge
candidate without further performance validation.

## Correctness

The full debug and release suites pass 209 tests each. Four added tests cover
36,000 seeded events against an exhaustive delivery model, compaction followed
by removal, supersession/retransmission membership, and pending FIFO/packet room.
The model checks sparse and late ACKs, packet-threshold loss, PTO, bounded copy
history, advertised limits, pending updates and removal after every event.
Existing connection tests cover FIN/RESET, STOP_SENDING, connection credit,
encryption/replay and offset limits. Formatting and strict production Clippy pass.

All 14 existing independent protocol fixtures pass. The added delayed-FIN
fixture passes on both the unchanged baseline and candidate: it retains eight
acknowledged 8,388,625-byte bodies, appends another 16,842,759 bytes to stream 0,
and verifies ordinary delivery plus forced credit loss, reversed duplicates,
all request-byte ACKs before FIN, all FIN ACKs, and exact responses. Both modes
finish with eight further GET/POST requests. It is a correctness fixture, not a
throughput benchmark.

```sh
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python -m pip install -r benchmarks/interop-requirements.txt
python benchmarks/sparse-stream-credit-check.py target/release/hfast
```

## Mechanism and costs

Baseline: `7cffde6281f69dcd40b7661a08212d58c652c53a`. Native replay compiles the
actual stream-credit, frame and wire modules with rustc 1.98.0, opt-level 3, fat
LTO and one codegen unit. Only the enclosing Connection is replaced by its
unchanged loss-threshold constant. A 64-byte window constructs equivalent
credit states without sending huge bodies; this does not change either server.
Repeated stale ACKs measure traversal, timeout cases include retransmission,
and cycle cases include update/write/ACK. Setup is outside the timed region.

With one flight among 65,536 retained streams, ten ACK calls drop from 9,831,013
Callgrind instructions to 1,506. Corresponding traversal changes from 65,536
map entries per call to one flight. At 128 retained streams the reduction is
92.41%. These are subsystem instruction counts, not requests per second.

Three alternating pairs and three pairs in reverse order use identical work
counts and CPU 2. Selected process CPU changes (negative means less time):

| Replay | Retained streams | Primary median | Confirmation median |
|---|---:|---:|---:|
| Sparse ACK | 128 | -92.28% | -91.94% |
| Sparse full cycle | 128 | -68.68% | -68.67% |
| Dense full cycle | 1 | +47.89% | +48.72% |
| Dense full cycle | 128 | +48.98% | +51.26% |
| Dense full cycle | 4,096 | +30.74% | +29.99% |
| Dense full cycle | 65,536 | -24.09% | -17.09% |
| Dense timeout/retransmit | 65,536 | +80.47% | +74.08% |

Large sparse candidate runs are very short, so instruction counts provide the
stronger evidence there. Dense ACK and dense cycle timing can improve at the
largest map size despite more instructions; that does not establish a network
gain. All measured steady-state operations allocate zero times after setup.

On x86-64 the container grows from 96 to 112 bytes. Update shrinks from 96 to
32 bytes and Flight is 80 bytes. Request, StreamSlot and Connection layouts are
unchanged; small requests still allocate no credit state. The vector retains
capacity after ACKs. With all streams previously in flight, allocator auditing
of the replay (including the common output buffer) finds:

| Retained streams | Baseline live requested bytes | Candidate live requested bytes |
|---|---:|---:|
| 1 | 485 | 549 |
| 128 | 30,096 | 23,952 |
| 4,096 | 962,576 | 765,968 |
| 65,536 | 15,400,976 | 12,255,248 |

At 65,536 streams setup allocations rise from 32 to 47, while peak requested
bytes fall from 22,282,272 to 12,255,248. These numbers exclude allocator metadata
and the stack-resident replay container. Production allocates that container
in a Box. The first ID-only prototype retained 104-byte Update values and added
more dense ACK lookup work; it was superseded, and its evidence is retained.

## Reproduce the subsystem replay

Use separate production targets and save immutable binaries before comparing.
The same script can build from either source tree:

```sh
python benchmarks/stream-credit-replay.py /path/to/tree /tmp/credit-replay \
  --deps /path/to/production-target/release/deps
taskset -c 2 /tmp/credit-replay ack-sparse 4096 10000
valgrind --tool=callgrind --collect-atstart=no --toggle-collect=c95_work \
  --callgrind-out-file=/tmp/credit.callgrind /tmp/credit-replay ack-sparse 4096 10
```

Modes are `ack-sparse`, `ack-dense`, `timeout-sparse`, `timeout-dense`,
`cycle-sparse`, and `cycle-dense`; arguments are retained streams and iterations.
The output includes CPU time, allocation counts, and state sizes. Include
singleton, dense and full-cycle cases when evaluating the sparse gains.

## Server comparisons

The immutable baseline and candidate use matching production compiler/profile,
features, rustflags and dependency fingerprints. The fixed shb client is
`71ce291b6244c70e7d35ef97960f407c2de9a99f`. Server CPUs are 0,1 and client CPU 2.
GET p128/n1,048,576, 65,543-byte POST p8/n256, and 16,842,759-byte POST p8/n16
use one connection/worker and identical 10-second timeouts. Each has warmup,
three alternating pairs, then three reversed pairs. These workloads and the
independent fixture retain normal accounting; small WSL timing differences
remain inconclusive without independent confirmation.

| Workload | Primary median RPS change | Reversed confirmation |
|---|---:|---:|
| GET | -1.174% | -1.525% |
| 65,543-byte POST | -2.192% | -2.530% |
| 16,842,759-byte POST | -16.668% | +109.621% |

All 12,684,768 measured and warmup requests succeed with zero request or connect
errors. Large-body pairs range from -43.64% to +185.44%; neither an improvement
nor a regression can be inferred from that series. No identical-binary retries,
affinity sweeps, changed workloads or relaxed thresholds were used. The runtime
candidate is **AWAITING_PERFORMANCE_VALIDATION**. Its dense subsystem costs are
real tradeoffs and must be included in any future decision. Further validation
requires a stable host and an independent delayed-FIN throughput workload, plus
ordinary and dense controls; correctness success alone is insufficient.
