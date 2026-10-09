# UDP segmentation without padding (c47/c48, 2026-10-09)

Consecutive datagrams to the same peer can share one `UDP_SEGMENT` send message.
Each original buffer becomes an iovec; all segments except the last must have
identical lengths. The last may be shorter. Grouping stays inside the existing
eight-datagram send batch, preserving payloads, ordering and flush timing.
A short `sendmmsg` result is translated back to original datagram indexes.
Unsupported segmentation retries only the unsent suffix as ordinary datagrams,
and disables segmentation for that endpoint. Other send errors still propagate.

This targets per-message transmit work in the networking stack. It does not
reduce the wire datagram count or change the number of batch flushes.
[Linux documents the UDP_SEGMENT interface](https://man7.org/linux/man-pages/man7/udp.7.html).

## Measurements

AMD Ryzen 9 3950X, WSL2 kernel 6.18.40.1, rustc 1.98.0
(88d9e12ae), release opt-level 3, fat LTO, one codegen unit.
Baseline hfast: `6f7d454f695b0a3d6996663d87fd67bdbd604532`.
Fixed shb throughout; its source tree is identical at `9503fe9` and `6655fa7`.
Only hfast changes between each baseline/candidate pair.

One server worker pinned to CPU 2; four shb workers on CPUs 8,10,12,14;
16 connections, 64 streams, 13-byte responses, batch linger 1, timeout 2s.
Every run starts a fresh server. Each series has two separate 5s warmups,
then five alternating pairs. Confirmation starts in the opposite order and
uses 20s runs. The two durations are compared only within their own series.
There are no overlapping builds, tracing or other benchmark runs.

| Series | Duration/run | Baseline median req/s | Candidate median req/s | Difference |
|---|---:|---:|---:|---:|
| Initial comparison | 10s | 2,737,054 | 2,857,241 | +4.39% |
| Independent confirmation | 20s | 2,758,366 | 2,866,159 | +3.91% |

The preceding identical-binary controls passed: CV 0.76%, median absolute
paired difference 0.88%, maximum 2.21%. Their apparent median difference was
-0.47%, not an optimization result. The control limits were CV <= 3%, median
absolute pair <= 2%, maximum <= 5%; the candidate threshold was a median gain
of at least 3%, all pairs positive, plus independent confirmation.

All ten candidate pairs favored segmentation. Paired differences:

- 10s: +4.76%, +4.93%, +2.67%, +3.40%, +3.16%.
- 20s: +2.67%, +3.91%, +3.54%, +5.63%, +5.44%.

Every warmup, control and comparison had zero request or connection errors;
all completed requests had status 200. These results establish a gain for this
server-limited loopback workload, not for every network or concurrency level.
Request counting and latency sampling in the fixed client are unchanged.

A separate traced 10,000-request correctness run observed 43 successful
`sendmmsg` calls with 176 messages carrying 330 original datagrams: 154 messages
used UDP_SEGMENT and two iovecs. Every segment size and returned message length
matched the original buffers; no short sends or errors occurred. Tracing was
outside the timing series and supplies no throughput evidence.

Immutable measured binaries (SHA256):

- hfast baseline: `98c82cf707b8c64442a28b36e2ffdd13947a71671c0c58ba059f7dcd09b1bf61`
- hfast candidate: `c9a6a736506c26aaae6eff3223eac5ae55fc04b17e88db3f3f210a72fbbc6fb0`
- fixed shb: `7501eab93c3cb013fea0b230b2c98583c5b825b2f972b433ba9f4e44e4d40f82`

## Reproduction and correctness

Build both revisions with the same compiler and `cargo build --release --locked`,
and save distinct binaries before switching revisions. For each server, start
`hfast --threads 1 --tcp 0 --quic 18443`. After its worker has started, set
**all** its thread affinities to CPU 2 (it initially pins its own worker to CPU 0):

```sh
for thread in /proc/"$server_pid"/task/*; do
    taskset -pc 2 "${thread##*/}"
done

taskset -c 8,10,12,14 "$shb_binary" --http3 -t 4 -c 16 -p 64 \
    --batch-linger 1 --timeout 2s -j -z 10s https://127.0.0.1:18443/
```

Stop that server before starting the next run. Verify thread affinities,
retain each JSON report, and alternate the binary order. Run identical-binary
controls first with the limits above. Use 5s for warmups and 20s for confirmation.
The session's raw reports, hashes and driver are retained in the local
`hfast/optimization-results/c48-*` evidence archive.

Validation: all 61 Rust tests pass in debug and release. New tests cover
segment lengths, empty datagrams, destination boundaries, payload identity,
UDP size limits, partial sends, interruptions, error propagation and endpoint
reuse. A real-kernel test disables checksums to force segmentation fallback
after a successfully sent prefix, and checks that no packet is replayed.
Independent hyper-h2/aioquic checks pass for HTTP/1.1, HTTP/2 and HTTP/3,
including bodies and TCP backpressure, both normally and with forced epoll.
The CI workflow runs these unit and interoperability checks.

The pre-existing HTTP/3 loss-recovery limitation remains: the independent
seeded 5% loss relay times out for both baseline and the initial candidate.
This change does not claim to repair loss recovery.
