# Avoid discarded TLS session tickets

The QUIC transport does not deliver post-handshake CRYPTO. After the client's
Finished, `pump_tls` queues rustls output in Handshake and `recv` immediately
retires that space. The previous production configuration nevertheless derived,
encoded and cached two session tickets per connection. Configure zero tickets,
ignore RFC 9149 ticket requests, and disable session storage.

The production-config regression observed two cache puts and zero remaining
CRYPTO output after authenticated `recv` on the baseline. Independent aioquic
clients received no ticket, resumed no session and completed all requests under
normal delivery, first-flight loss and reversed coalesced handshake packets.
The candidate preserves this externally visible behavior.

Run correctness checks with:

```sh
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python -m pip install -r benchmarks/interop-requirements.txt
python benchmarks/tls-ticket-check.py target/release/hfast
```

Seven production-config Rust tests cover disabled storage, no generation even
with a functioning counted cache, a request for 255 tickets, malformed Finished,
out-of-order/duplicate Finished, authenticated responses/ACKs and a coalesced
Finished/application datagram. The fixture replaces only the generated
certificate so the client uses ordinary certificate verification. Existing
recovery and key-update tests continue to apply.

## Measurements: c187, 2026-10-21

WSL2, rustc 1.99.1, the locked dependency graph, O3/fat LTO/one codegen unit.
Baseline is master `589a7c7`, frozen SHA256
`2f52a71ec11a59274e82bcba9a00bf1e6447c546314984a6741adf4f357e5d89`.
Candidate SHA256 is
`81d5c4ad918a84b008b5c39f81f637b64ed9ba72018109716f4e2b4b3170bada`.
Independent build targets and source manifests prevent cross-worktree cache
reuse. No builds or correctness workloads ran during timing.

Actual-source allocation probes use the production TLS configuration and a
shared cache, warmed with 256 connections before counting 256 more. They remove
exactly 35 allocations per connection: 132→97 for whole flights, 140→105 for normal
fragments, 144→109 for reverse fragments, 166→131 for overlaps/duplicates.
Allocated bytes fall by approximately 1922 per connection; signature lengths
vary. Session-storage puts fall from 2 to 0. This allocation result alone is not
a throughput claim.

The fixed native `crypto-churn-peer` has SHA256
`ff3bcade8f9e0a39f4105f33bf3f79bf74651ff89ed2af3bf1ea4d55bdbb5532`.
For each schedule, four producers on CPUs 8/10/12/14 offer 4000 measured and 64
warmup full TLS/HTTP/ACK/close connections each to one server on CPU 0. Three
alternating pairs are followed by three reversed-order confirmation pairs.
Use a fresh isolated network namespace and output directory for each command:

```sh
python benchmarks/compare-crypto-churn.py BASELINE CANDIDATE PEER OUTPUT \
  --mode normal --connections 4000 --warmup 64 --pairs 3 \
  --client-cpus 8 10 12 14
```

Repeat with `reverse` and `overlap-duplicates`; confirmation adds
`--candidate-first`. Retain all output and complete latency arrays.

| Schedule | Connections/s change, primary / confirmation | Server CPU/connection change |
|---|---:|---:|
|Normal|+2.315% / +1.221%|−2.789% / −3.150%|
|Reverse|+1.255% / +1.643%|−2.390% / −2.381%|
|Overlap/duplicates|+2.391% / +1.330%|−1.905% / −1.899%|

All 18 native pairs improve throughput (+0.949% to+2.875%) and reduce server CPU.
585360 total connections, including warmup and retirement, completed exactly;
there were zero unexpected errors and all 576000 measured latency samples were
retained. Server utilization ranged 0.904–0.930 cores; exclusive server saturation
is not established by that observation.

A separate uninstrumented real TLS processing probe measures server CRYPTO
reassembly/TLS input/output/key processing, excluding client work and connection
setup. With a warmed shared cache, 2048 measured handshakes per run and three
pairs plus reversed confirmation, CPU medians change −6.334/−3.189% whole,
−5.107/−7.112% normal,−2.232/−4.979% reverse,−4.198/−5.048% overlap. 23/24 pairs
reduce CPU. This is supporting mechanism evidence, not network throughput.

Ordinary fixed-shb HTTP/3 guards use serial c1/p1/t1 and multiplexed c16/p64/t4,
three alternating pairs plus three reversed pairs, exact request/error/status
checks and all latency statistics. Serial RPS medians change +0.364/+0.155%;
multiplexed −0.400/+1.839%. CPU medians are 0/−0.408% and +0.349/−1.874% respectively.
Tail results remain variable: multiplexed p99.9 medians +4.479/+9.509%, with
individual changes from −22.099% to+79.226%; p99 medians +1.580/−5.074%.
No steady-request speedup or latency-equivalence claim is made.

The fresh-connection result is accepted under the smaller-gain exception to
the default 3% threshold: eighteen consistent native pairs, lower CPU in every
native pair, independent TLS CPU confirmation and deterministic work removal.
The measured benefit is scoped to fresh connections; the ordinary tail
uncertainty is retained above. Raw records and source/probe manifests are kept
locally under `optimization-results/c187/`, outside the source commit.
