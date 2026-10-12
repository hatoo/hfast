# Complete-response ACK membership

`Connection::on_ack` receives descending ACK ranges and an ascending response
ledger. A reverse range cursor visits each range once as the ledger advances,
replacing a fresh linear membership search for each response. It keeps the same
inclusive ACK boundaries, packet loss threshold, retry identities and stream
credit. Generated full-scan oracle tests exercise duplicates, sparse ranges,
wrapped storage, PTO, late originals and packet-number boundaries.

## Native workload

The native peer fills 65,536 complete HTTP/3 responses before acknowledging them
in 256 ranges. Requests arrive in batches of 32; a separate batch-16 check is also supported.
Every batch fits in one packet in both directions; a split invalidates the run.
Every 64 batches, an ACK of the oldest response packet keeps recovery progressing.
PINGs create 255 authenticated ACK-only packet gaps. The final sparse ACK covers
all outstanding responses plus received older packets, excluding those gaps.
Re-ACKing an older authenticated packet is permitted; no PN is invented.

Whole-cycle rate includes filling the window, PING gaps, the sparse ACK and a new
exact HTTP response that fences ACK processing. ACK-to-response latency is
reported separately. Every received stream ID, status/header/body byte, offset
and FIN is checked. Missing, duplicate, reordered, retransmitted or malformed
responses fail the fixture. The final response ACK/PING is delivered outside the
timed interval; exact MAX_STREAMS credit and the server's ACK of every client
packet are required. These strict no-loss performance fixtures supplement the
independent aioquic loss/reordering/recovery tests; they do not establish general
QUIC loss recovery.

The peer uses a pinned shb Git archive for TLS/packet protection, with a benchmark
entry point and explicit manual ACK scheduling. The working checkout is untouched.
It uses busy receive on a separate CPU to avoid a client scheduler wakeup for
every round trip. Ordinary server behavior is measured separately with fixed shb.
The peer's six tests include omitted responses and a 256-range wire/set oracle.

Build the fixed peer (Rust, Python 3.12+, a local shb Git repository containing the
pinned commit, and Linux are required):

```sh
python3 benchmarks/build-sparse-ack-peer.py /path/to/shb /tmp/sparse-ack-peer
```

Use release servers built with identical compiler, dependencies, flags and profile
settings. Preserve them as separate immutable files. Do not overlap timing with
builds, tests or instrumentation. Choose an available client CPU different from
the server's CPU 0. Each run includes a full warmup cycle before measured cycles:

```sh
python3 benchmarks/compare-sparse-acks.py /path/to/baseline /path/to/candidate \
  /tmp/sparse-ack-peer/sparse-ack-peer /tmp/ack-primary --client-cpu 8
python3 benchmarks/compare-sparse-acks.py /path/to/baseline /path/to/candidate \
  /tmp/sparse-ack-peer/sparse-ack-peer /tmp/ack-confirmation --client-cpu 8 \
  --reverse
```

The comparator alternates three pairs, checks equal response/packet/range counts,
records input hashes before and after, and refuses to overwrite prior evidence.
CPU accounting from `/proc` has tick granularity; a short correctness smoke may
report zero CPU. Rates from CI's identical-binary smoke are not performance claims.
This workload deliberately isolates a large delayed-ACK window, and its rates
must not be described as ordinary small-GET throughput.

## c134 measurements (WSL2, 2026-10-12)

Matched release binaries: baseline `d710d80` (`7a720c0a` SHA-256 prefix), cursor
candidate `5b11b27` (`46cce47c`), native peer `33ec2502`. The production cursor
source here exactly matches the measured candidate. Rust 1.98.0, fat LTO, one
codegen unit, locked dependencies and no extra RUSTFLAGS. Each run measures 32
complete cycles after one full warmup; three alternating pairs per phase.

| Fixed workload | Paired whole-cycle RPS changes | Median RPS | Median server CPU/request |
| --- | --- | ---: | ---: |
| Batch 32, primary | +4.131%, +3.887%, +2.829% | +3.887% | -8.642% |
| Batch 32, reversed confirmation | +2.536%, +3.475%, +4.457% | +3.475% | -6.875% |
| Batch 16, reversed sensitivity check | +1.072%, +0.004%, +3.940% | +1.072% | -5.944% |

The first confirmation changed the batch size to 16 and was inconclusive for
throughput. One subsequent reversed confirmation kept the original batch-32
workload fixed; all six batch-32 comparisons improved, and both phase medians
exceeded 3%. The accepted gain is confined to that controlled workload. Batch 16
has no reliable throughput gain established, despite its consistent CPU saving.
No identical-binary controls or CPU-affinity sweeps were repeated.

Across these three phases, 39,537,234 responses (including warmups) passed exact
wire/count/credit checks with zero unexpected errors, losses or duplicates.
Every paired cycle has exactly 65,536 outstanding responses and 256 ACK ranges,
with matching sent/received workloads. ACK-fence latency falls about 92–93%; that
localized metric is separate from the full-cycle rates above.

Ordinary fixed-shb guards completed 26,935,296 successful requests with
zero errors and exact status/latency fields. Median RPS changes were
-0.352% at c1/p1 and
-0.826% at c16/p64 (mixed multiplexed pairs).
These small WSL effects establish neither an ordinary gain nor equivalence; a
small cost remains possible. No ordinary measurements were repeated.
