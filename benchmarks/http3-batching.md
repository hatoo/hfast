# HTTP/3 response batching

Measured 2026-09-26 with local shb (`8a1fed9`, `target/release/shb`). The
baseline includes the working tree's existing recvmmsg/sendmmsg changes, not
just the last hfast commit. Both hfast binaries use `cargo build --release`.

The change processes a receive batch before generating output, queuing each
connection once. Requests from several packets can share an encrypted response
packet and an ACK. The established receive path also avoids a redundant hash
lookup. There is no wait to fill a batch: pending output is sent before the next
receive. HTTP/1.1 and HTTP/2 code is unchanged.

## Results

Median of three 5-second runs, alternating before/after order each repetition.
Each run starts a fresh server; the measured interval includes client handshakes.
All measured requests returned 200 with zero reported errors.

| Server threads | shb threads | Connections × streams | Before req/s | After req/s | Change | Server CPU µs/req, before → after |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 × 1 | 11,384 | 11,471 | +0.8% | 37.941 → 37.829 |
| 1 | 4 | 16 × 16 | 1,199,187 | 1,187,767 | −1.0% | 0.832 → 0.840 |
| 1 | 4 | 16 × 64 | 1,990,915 | 2,518,243 | +26.5% | 0.499 → 0.395 |
| 1 | 4 | 16 × 128 | 2,228,105 | 3,000,524 | +34.7% | 0.448 → 0.332 |
| 4 | 8 | 32 × 32 | 8,861,715 | 9,251,173 | +4.4% | 0.397 → 0.384 |

The benefit is clearest at higher stream concurrency on a saturated server
worker. Low concurrency is effectively unchanged. The four-worker result has
wide overlapping ranges (before 8.76–9.37M, after 8.44–9.34M req/s), so its
small median increase is not evidence of a reliable speedup. UDP reuseport
randomly distributes connections among workers.

Raw per-run measurements are in [http3-batching.csv](http3-batching.csv).

## Environment and reproduction

Ryzen 9 3950X, 16 cores / 32 logical CPUs, WSL2 kernel
`6.18.33.2-microsoft-standard-WSL2`, Rust 1.98.0. hfast pins workers starting at
CPU 0; shb is restricted to CPUs 8–31. Both endpoints use loopback on the same
machine, so these are relative results for this workload, not network capacity
measurements. CPU time is the change in process-wide `/proc/PID/stat` user plus
system ticks during the shb invocation, divided by successful requests. The
short runs and tick granularity limit precision.

Save the original release binary before applying the change, then build the
changed binary and run:

```sh
python3 benchmarks/http3-batching.py /tmp/hfast-before target/release/hfast \
  ../shb/target/release/shb --duration 5s --runs 3 > /tmp/hfast-results.jsonl
```

The script uses port 18443; choose a free port with `--port`. Adjust
`--client-cpus` for other machines. For the 16 × 128 case, the equivalent commands
are:

```sh
./target/release/hfast --tcp 0 --quic 18443 --threads 1
taskset -c 8-31 ../shb/target/release/shb --http3 -t 4 -c 16 -p 128 \
  -z 5s -j --timeout 2s https://127.0.0.1:18443/
```

A second experiment combined only consecutive packets from the same peer. It
improved the 16 × 64 and 16 × 128 cases by about 12% and 16% respectively
(three 3-second runs), less than combining the whole receive batch, so it was
not retained.

## Validation

- `cargo test`: 55 tests passed, including shared ACKs across received packets,
  interleaved peers, repeated batches, and closing a queued connection.
- `cargo clippy --all-targets -- -D warnings`: passed.
- shb GET and POST: 3,000 successful HTTP 200 responses per case on each of
  HTTP/1.1, HTTP/2 and HTTP/3; zero reported errors.
- A UDP relay independently dropping each datagram with probability 5% in both
  directions (seed 42): both baseline and changed binaries completed all 3,000
  HTTP/3 requests with status 200 and zero reported errors, using one connection
  and 16 streams. This checks recovery, not throughput improvement under loss.
