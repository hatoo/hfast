# Lazy cached QUIC packet keys (c188)

`KeyUpdates` used to derive a future `PacketKeySet` during every handshake and
immediately after each authenticated key update. Most benchmark connections
never use those future keys. It now prepares the pair when phase selection first
needs it, caches it across authentication failures, and consumes it on a genuine
transition. Retained old receive keys do not prepare another generation.

The cache bounds forgery work to one preparation per active generation. Each
packet still makes one AEAD attempt. Active keys, packet numbers, ACKs, stream
accounting, old-key expiry and the cumulative integrity limit are unchanged.
`Secrets::next_packet_keys` advances secrets exactly when it prepares a pair.

## Validation

- 298 tests pass in both debug and release; four new regressions exercise all
  three AEADs. Existing tests also cover phase wraps, duplicates, lost transitions,
  retransmission, Finished gating and packet-number generation boundaries.
- Independent aioquic key-update checks pass for 3 AEADs × 3 CID lengths × clean,
  loss and reorder/forgery modes: 162 updates and 5,238 exact responses.
- Ticket policy, general interoperability, CRYPTO/control/stream recovery,
  response recovery and response-credit scripts pass, as do 12 native
  connection-churn smoke cases. These are focused recovery fixtures, not a
  claim of unrestricted QUIC loss-recovery correctness.
- Production Clippy with warnings denied and formatting pass. Two pre-existing
  HTTP/2 test unused-assignment warnings remain.

## Fresh full-connection measurements

Base: `2877ff86cd512a2f36c20a425bf79486867318d7`, including the accepted no-ticket
policy. Rustc 1.99.1, locked dependencies, O3/fat LTO/one codegen unit; WSL2.
Immutable server binaries: baseline `81d5c4ad`, candidate `b5792af7`. Separate
Cargo targets prevent cross-worktree cache reuse. Fixed native peer `ff3bcade`
uses shb transport revision `12e95af17ef6015020776ab65996bef9531099e0`.

Server CPU 0; four producers on CPUs 8/10/12/14; 4,000 measured + 64 warmup
connections per producer. Three alternating pairs per schedule, then three
independent opposite-order confirmation pairs. Each connection validates full
TLS, HTTP reply, ACK and close. No concurrent build/profiling load.

| CRYPTO schedule | CPS primary / confirmation | Server CPU/connection primary / confirmation |
|---|---:|---:|
| Normal | +1.429% / +1.859% | -1.626% / -2.016% |
| Reverse | +2.387% / +1.396% | -2.016% / -1.215% |
| Overlap/duplicates | +2.397% / +1.119% | -2.236% / -1.278% |

All 18 pairs improve CPS and reduce server CPU. There are 585,360 exact
connections including warmup/retirement, zero errors, and all 576,000 measured
latency samples are retained. Server use is 0.906–0.920 cores and peers
0.960–1.004 cores; exclusive server saturation is not inferred.

Acceptance uses the documented exception for gains below the default 3%:
consistent native pairs plus separate TLS CPU confirmation and deterministic
resource savings. Actual production TLS processing removes six allocations
and 1,888 allocation bytes per connection. Independent TLS CPU probes improve
23/24 pairs; every schedule median improves in both orders (1.97–8.13%).
Certificate signature-length variation explains fractional byte differences in
whole-handshake allocation totals. CPU builds contain no audit allocator.

## Costs and limits

The first forged changed-phase packet pays the deferred preparation: six
allocations/1,888 bytes and roughly 2.1 microseconds extra for AES-128,
5.5 microseconds for AES-256, and 1.8 microseconds for ChaCha20. Cached forgeries
allocate zero bytes. The full connection has not gained an additional key
preparation: the work formerly happened unconditionally at the handshake.

Separate encrypted-request/response/ACK probes measure server receive CPU.
Genuine first-update medians range from -2.80% to +2.55%; 64-update runs from
-3.00% to +1.81%, with no consistent regression across confirmation. These are
cost guards, not throughput wins. Tails vary: the AES-256 first-update p99 in
confirmation is 9.18→14.02 microseconds (primary 10.29→9.41). No key-update
latency-equivalence claim is made.

Fixed-shb ordinary H3 guards (`5fb383e9`) validate 202,506,240 exact requests and
zero errors. Serial RPS is -0.374%/-0.099%; multiplexed +2.452%/+1.351% in
primary/confirmation. Tails remain variable: serial p99 +17.900%/-1.755%,
multiplexed p99.9 -6.903%/+11.670%. No ordinary speedup or latency-equivalence
claim is made. A current-shb master smoke adds 143,360 exact requests/zero errors.

## Reproduction

Build base and candidate with `cargo build --release --locked` in separate
worktrees and `CARGO_TARGET_DIR`s, then copy read-only binaries. Build the fixed
peer with `benchmarks/build-crypto-churn-peer.py` at the revision above. With
loopback up inside an isolated network namespace, run this for each of
`normal`, `reverse`, and `overlap-duplicates`:

```sh
python benchmarks/compare-crypto-churn.py BASE CANDIDATE PEER UNIQUE_OUTPUT   --mode normal --connections 4000 --warmup 64 --pairs 3   --client-cpus 8 10 12 14
```

Repeat once using `--candidate-first` and a new output directory. The controller
checks exact accounting and keeps every latency. Correctness commands are
`cargo test --locked`, `cargo test --release --locked`, and
`python benchmarks/key-update-check.py CANDIDATE` (dependencies are pinned in
`benchmarks/interop-requirements.txt`). Local c188 records retain full manifests,
probe sources, commands, raw samples and allocation/transition-cost evidence.
