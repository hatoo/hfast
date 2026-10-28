# Sparse receive ACK regression fixture

This is an untimed correctness check of hfast's bounded receive history. It
changes no production Rust or Cargo input and makes no performance claim. The
local bounded-allocation candidate remains experimental and is not included.
The existing native sparse-ACK workload tests acknowledgement of server response
packets; this fixture instead tests the ACKs generated for received client packets.

Pinned aioquic 1.3.0 supplies TLS, packet protection, incoming packet/ACK parsing,
PATH_RESPONSE validation and HTTP/3 decoding. No hfast wire or crypto code is
imported. After a completed GET and PING fence, automatic client sends and timers
pause while a fixed sequence of authenticated PING/PATH_CHALLENGE packets is sent.
Each new packet number has one protected byte string. Duplicate probes replay
that exact string, including the challenge, rather than reusing a nonce with a
different payload. The client registers the outstanding challenge with aioquic.

Every probe needs a new authenticated server packet containing its PATH_RESPONSE
and exactly one ACK. A missing response times out; an unchanged ACK alone cannot
prove that an old or discarded probe arrived. ACK ranges must match a separate
set-and-sort model, with at most eight disjoint inclusive ranges. Only observed,
matching ACK/response evidence advances the model. Until eight separated probes
displace handshake history, the probe portion is checked exactly; from that point
the entire ACK must match, including after merges free a slot. The packet-number
ledger is reserved above the normal sender, and automatic sends during the probe
phase fail the check. Ordinary aioquic transmission then resumes for an exact POST
response and final PING fence.

Eight scenarios cover:

- Ascending sparse overflow, discarded oldest disjoint arrivals and duplicates.
- Extending the oldest range on either side before any eviction decision.
- Bridging the two oldest ranges, reclaiming a slot and later overflowing again.
- Reverse sparse arrivals and older disjoint probes outside the retained window.
- One-, two-, three- and four-byte packet-number truncation boundaries, including
  wrap, old arrivals and exact replays. Wide anchors keep each initial jump inside
  the reconstruction window. Every constructed packet is independently decrypted
  locally before transmission, and every resulting server ACK names the full PN.

All 139 probes require exact ACK evidence, including old/discarded and duplicate
ACK-eliciting packets whose range contents do not change. Each case requires two
workload responses with exactly status 200, the full `Hello, World!` body and FIN,
plus one readiness and one fresh-connection liveness response. A default run thus
accounts for 32 HTTP responses. Callback errors propagate; normal closure does
not erase earlier failures. Deadlines, cancellation of protocol handles/waiters,
UDP transport closure and terminate/kill/reap bound failure cleanup.

```sh
python -m pip install -r benchmarks/interop-requirements.txt
python -m unittest discover -s benchmarks -p test_receive_ack.py -v
python benchmarks/receive-ack-check.py target/release/hfast --output /tmp/receive-ack
python benchmarks/receive-ack-check.py target/release/hfast --threads 2
HFAST_GRO_BINARY="$PWD/target/release/hfast" python benchmarks/receive-ack-check.py benchmarks/without-udp-gro.py --threads 2
```

`--scenario` selects one case. `--timeout` bounds each readiness/workload/liveness
stage (default 10 seconds); individual probe replies have a two-second deadline.
`--output` must be a new directory. Reports retain each probe's PN, width, token,
wire hash, replay flag, independently decoded server packets, expected/observed
ACKs, response counts/hashes, errors and process status. TLS secrets are never
exported. CI retains these artifacts on both success and failure.

Negative tests reject missing/extra/wrong ACKs, stale or mismatched receive fences,
lost ACK obligations, malformed ranges, restored evicted history, forged packets,
wrong/truncated/extra HTTP replies, missing FIN, callback errors and silent/exited
servers. Local sensitivity checks also run isolated Rust source mutants that
evict the oldest range before duplicate/neighbor classification, or discard every
packet below the oldest range before checking whether it extends that range.
Ordinary readiness succeeds; the corresponding exact wire ACK checks must fail.

The eight-range retention policy and immediate ACK/PATH_RESPONSE pairing are
intentional regression expectations for this server, not general QUIC conformance
rules. Duplicate challenges exercise its current receive path, not a claim of
replay suppression. The fixture does not measure allocation, throughput, CPU or
latency; it does not establish that general QUIC loss recovery is fixed. Serial
probes also do not establish coverage of actual GRO/GSO batching.
