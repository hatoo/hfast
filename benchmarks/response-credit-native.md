# Native response-credit correctness fixture

This fixture supplies the real UDP path missing from the ordinary burst peer,
which advertises 1 MiB per response stream. It tests 1, 2 and 25-byte initial
windows and monotone grants for the server's literal 25-byte HTTP/3 response.
It changes neither production binary. It makes no throughput claim.

Build from immutable published shb `3a13d87922f9fd92e19ea2de8c3375dcd7a48e11`:

```sh
python benchmarks/build-response-credit-peer.py /path/to/shb /new/peer-output
python -m unittest discover -s benchmarks -p test_response_credit_reports.py -v
python benchmarks/response-credit-peer-interop.py /new/peer-output/response-credit-peer /new/interop-output
sudo unshare --net sh -c 'ip link set lo up && exec "$@"' response-credit \
  python benchmarks/response-credit-native-check.py \
  /absolute/path/to/hfast /new/peer-output/response-credit-peer /new/native-output
```

The builder extracts Git objects, runs debug/release tests and strict Clippy,
then saves a read-only release binary with compiler/source/binary hashes.
It never reads the shb working tree. `NATIVE_PEER_TARGET_DIR` may name a shared
build cache. Python interoperability requires `interop-requirements.txt`.
All output directories must be new. `--cpu` selects the native peer CPU.
Use a private network namespace for exact namespace datagram accounting;
unprivileged `unshare -Urn` also works where enabled.

The native check covers 1/8/32/512 requests at each initial limit. Eight-request
cases additionally withhold response ACKs, generate sparse ACK ranges, lose two
authenticated response packets plus one outgoing grant, and replay delayed
packets twice in reverse order. All requests retain independent first-send and
complete-response-plus-FIN timestamps. Matching retransmissions add no second
sample. A reordered FIN is retained but cannot complete across missing bytes.

The TLS transport parameters advertise the actual small bidi/uni byte limit
and zero server uni streams. Before measurement the peer reliably grants one
uni stream and three bytes on stream 3, sends its SETTINGS/QPACK preludes, and
waits for exact server SETTINGS bytes and an ACK. Requests begin only after
that bootstrap and, in controlled mode, the parent's `start` command. The parent
collects the terminal report while the exact socket is still alive, then sends
`exit`. Controller reads, I/O loops, and cleanup all have bounded deadlines.

Each request and each increasing stream grant retains all packet copies until
any copy is ACKed. The next grant waits for both receipt of the current byte
prefix and an ACK of the preceding grant. No request/grant is treated as ACKed
because a response arrived. A final PING fence is ACKed after all reliable work
and response ACK release. Histories fail rather than discard evidence: at most
512 requests, 2048 pending work records, 128 copies per record, 131072
packet/frame records and 16384 ACK intervals. Retries use a fixture-specific
50 ms timer. This bounded localhost driver is not a general QUIC client.

`response_credit_reports.py` independently reconstructs bytes, FINs, frame
counts, duplicate counts, every grant generation and ACKed packet copies from
the retained transcript. Negative report tests reject lost intervals, corrupt
bytes/FINs, duplicate success, missing samples, missing grants/ACKs and unavailable
or nonzero drop evidence. `response-credit-peer-interop.py` independently checks
serialized TLS limits, decodes request QPACK, observes wire grants and ACK unions,
and checks the start barrier using pinned aioquic 1.3.0. Hostile servers send
wrong bytes, premature FIN, excess bytes, omit responses/FINs/grant ACKs, or
violate stream credit. Each must produce a bounded explicit failure.

Both processes request a 4 MiB receive buffer and record actual kernel capacity.
The peer drains receives between groups of 16 sends and waits for request/grant
ACKs whenever 64 reliable work records are outstanding. A capped buffer is not reported
as the requested size. Peer and server socket inode/cookie/capacity/drop evidence
and namespace counters must be available and clean; the exact receive-datagram
count must match peer send/receive counters including TLS and intentional loss.
Per-process CPU times and every latency sample are retained. Kernel drops are
never relabeled as intentional fixture loss.

These are short, trace-retaining correctness workloads. Per-frame tracing and
ACK scheduling can make the peer the limiting component. They do not establish
that a server optimization improves sustained throughput. A later comparison
needs an immutable peer, sustained workloads, server/peer CPU evidence, matched
baselines, alternating runs and separate confirmation; fragmented-history
candidates remain experimental until those gates pass.
