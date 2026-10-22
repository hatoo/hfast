# Fixed work on every persistent QUIC peer

A global request budget can finish without every configured connection completing
TLS. This fixture checks each connection independently before timing, then gives
every peer the same number of request rounds. It is a benchmark/test fixture;
neither production binary is changed and no speedup is claimed.

`build-crypto-churn-peer.py SHB OUTPUT --persistent` extracts pinned shb revision
`12e95af17ef6015020776ab65996bef9531099e0` into a new directory, installs the native
workload and probe methods, runs focused debug/release tests and Clippy, then
freezes a release binary and source/compiler manifest. The normal churn builder
mode remains available. Build outside any measurement interval.

Each of one or four producer processes owns 1–128 sockets. It establishes full
TLS and HTTP/3 control streams on **all** sockets and completes warmup before
reporting ready. The controller verifies every peer and the namespace UDP ledger
before releasing the common start barrier. Each round sends one datagram per
peer containing 1–32 fresh requests, receives exact status/body/FIN for every
stream, and sends an ACK/PING fence whose acknowledgement must arrive before the
next round. All peers remain open through timing and detailed-report validation.

Each response has a latency sample, measured from immediately before sealing its
request datagram until response validation. Requests sharing a datagram share a
start timestamp. Samples are retained in completion order separately for each
peer, including warmup. Small completion reports delimit controller time/CPU;
the full sample arrays are serialized only after that interval. Producer times
are also retained. This timing includes request fences and client receive order;
it is a distinct workload from shb's ordinary reported latency/throughput.

The fixture rejects missing or repeated responses, altered bytes, missing FIN,
incomplete TLS, missing ACKs, packet gaps/reordering/duplicates, peer replacement,
partial counts and missing latency samples. It does not retry missing packets.
An error invalidates the run and retains partial reports and failure diagnostics.
After measurement every socket sends an authenticated close. The controller
checks consumption using an exact UDP delivery ledger and empty socket queues;
the aioquic interoperability fixture independently verifies peer closes too.
This does not establish general QUIC loss-recovery correctness.

Run in an isolated network namespace; unrelated traffic invalidates the ledger.
For example (use a virtual environment with `interop-requirements.txt`):

```sh
python benchmarks/build-crypto-churn-peer.py ../shb /tmp/persistent-build --persistent
python -m unittest discover -s benchmarks -p test_persistent_peers.py -v
python benchmarks/persistent-peer-interop.py /tmp/persistent-build/persistent-peer /tmp/persistent-interop
unshare -Urn sh -c 'ip link set lo up && exec "$@"' check \
  python benchmarks/persistent-peer-check.py /absolute/hfast \
  /tmp/persistent-build/persistent-peer /tmp/persistent-smoke --full
```

The default smoke matrix covers 1 and 16 peers, windows of 1 and 8, GRO and
fallback delivery. `--full` adds 512 peers with an explicit 4 MiB server receive
buffer request. A 512-peer burst can overflow the host-default queue even after
TLS; the full fixture therefore declares the larger capacity, without changing
the host or hfast default. CI runs the bounded default matrix and independent
positive/negative wire tests in the required `ci` job. Its timeout allows for the
additional native debug/release build; existing checks remain enabled.

For performance work call `persistent_peers.run` with immutable binaries,
distinct available client CPUs (e.g. `[8, 10, 12, 14]`), `smoke=False`, and fixed
`count`, `rounds`, `window`, `warmup` and `receive_buffer`. hfast pins its single
worker to CPU 0. Output directories must be new. Use alternating comparisons and
independent confirmation with identical workloads. Changing a window or buffer
defines a separate workload/policy; it does not itself prove an optimization.
Keep syscall tracing separate from timing: tracing changes batching and latency.
