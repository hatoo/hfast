# Native response cancellation workload

This fixture measures complete cycles with a fixed, fully sent response window.
It exercises `Connection::stop_sending` with sparse cancellation sets while the
server still retains response delivery state. It does not estimate ordinary HTTP
throughput or model a large queue of unsent responses.

`build-stop-batch-peer.py` extracts shb commit
`48b2d7e2ca138ea9f69190cd3ae4112058fb56d7` into a new output directory and adds
benchmark-only packet seal/open methods. Neither working checkout is modified.
The resulting native peer uses real TLS and authenticated UDP packets with fixed
QPACK requests. Its manual ACK schedule bypasses the normal client scheduler.
Both server variants must use this same frozen peer.

```sh
python3 benchmarks/build-stop-batch-peer.py ../shb /tmp/stop-peer
python3 -m unittest discover -s benchmarks -p test_stop_batch.py -v
unshare --user --map-root-user --net sh -c 'ip link set lo up && exec "$@"' native-stop \
  python3 benchmarks/stop-batch-check.py \
  /absolute/hfast /tmp/stop-peer/stop-batch-peer /tmp/stop-smoke
```

Use a peer CPU distinct from hfast's worker CPU 0 (`--client-cpu`, default 8).
CI uses CPU 1. A network namespace isolates UDP counters from unrelated traffic.
Every output directory must be new; existing evidence is never overwritten.

Each measured cycle:

1. Sends batches of 32 requests, checking every response ID, byte, offset, FIN and
   packet number. It acknowledges one oldest response batch every 64 request
   batches to maintain timer progress. Priming finishes with exactly the selected
   live window, including any replacement requests this ACK schedule requires.
2. Cancels evenly spaced streams, at most 64 stops per packet. It requires exactly
   one reset per selected stream with the original error and final response size.
   It does not acknowledge the resets while cancellations are being sent.
3. ACKs all responses and resets, requires a fresh exact HTTP response, and sends
   two ACK/PING fences to retire that response and any credit update. Every fence
   and all priming requests are included in complete-cycle timing. Cancellation
   latency is reported separately and includes its first follow-up response.

Responses already received before cancellation remain counted as wire responses;
resets have separate counters. Missing, duplicate, unsolicited, split, truncated,
or reordered output fails the run. Every sent application packet must be ACKed.
The final socket must be empty and namespace UDP errors must remain zero.
Stream-credit checks account for hfast's half-window advertisement threshold.
Typically one completed fence's credit remains unadvertised; it is accounted for
explicitly, not mistaken for a missing response or a missing reset.

The correctness matrix covers windows 1,024/65,536, cancellation sets 1/64/1,024,
repeated stops with changed errors, and STOP-before-ACK / ACK-before-STOP frame
ordering. The ordering fixtures use one stop packet so the first ACK cannot
retire a later cancellation set. The timing fixture intentionally rejects network
loss; it is not a general QUIC recovery client.

Independent checks use the pinned aioquic/pylsqpack dependencies:

```sh
python3 -m pip install -r benchmarks/interop-requirements.txt
# Run each command inside its own network namespace as above.
python3 benchmarks/stop-batch-wire-check.py \
  /absolute/hfast /tmp/stop-peer/stop-batch-peer /tmp/stop-wire
python3 benchmarks/stop-batch-fault-check.py \
  /absolute/hfast /tmp/stop-peer/stop-batch-peer /tmp/stop-faults
python3 benchmarks/reset-accounting-check.py /absolute/hfast
python3 benchmarks/response-credit-check.py /absolute/hfast
```

The wire checker independently parses authenticated plaintext transcripts with
aioquic and decodes request headers with pylsqpack. It checks response/reset ACK
completion, frame order, sparse IDs, and credit, and rejects deliberately missing,
duplicated, unsolicited or corrupt resets. This is an independent plaintext
oracle, not an independent TLS audit. The fault relay drops or duplicates actual
encrypted reset datagrams and requires the native timing peer to fail without
printing a success report. Existing independent protocol fixtures cover positive
reset loss recovery, partial/unsent responses, and receive-side completion.

```sh
# Same immutable release compiler/flags; fixed server CPU 0 and peer CPU 8.
# Run each comparison in a fresh network namespace.
python3 benchmarks/compare-stop-batches.py BASELINE CANDIDATE \
  /tmp/stop-peer/stop-batch-peer /tmp/stop-primary \
  --window 65536 --cancellations 1024 --cycles 64 --pairs 3
python3 benchmarks/compare-stop-batches.py BASELINE CANDIDATE \
  /tmp/stop-peer/stop-batch-peer /tmp/stop-confirmation \
  --window 65536 --cancellations 1024 --cycles 64 --pairs 3 --reverse
```

One warmup cycle precedes each measured run. The comparator alternates order,
verifies identical counts and immutable input hashes, and records total server
CPU from `/proc/PID/stat`. Short runs can have quantized CPU measurements.
Transcripts and other instrumentation are prohibited during timing. Ordinary
fixed-client CPU and all reported latency metrics remain a separate publication
gate for any optimization evaluated with this fixture.
