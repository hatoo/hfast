# Bounded HTTP/2 sparse-to-empty workload

This test-only peer qualifies xdp-http's recovery from sparse stream storage.
It keeps hfast's production files unchanged. The builder archives fixed revision
`d66a790f895f80c76ea8c1cedadb84dd7958fde5` into a new directory, injects a bounded
gate, runs debug/release tests and Clippy, then freezes the release binary.
Source, compiler and binary hashes are recorded in its manifest. Each build has
its own Cargo target directory. Existing output directories are rejected.

```sh
python benchmarks/build-h2-drain-peer.py . /absolute/new/output
python benchmarks/check-h2-drain-peer.py /absolute/new/output/h2-drain-peer /absolute/new/interop
python benchmarks/check-h2-drain-peer.py /absolute/new/output/h2-drain-peer /absolute/new/interop-t2 --threads 2
```

Use the resulting binary through the benchmark runner's explicit `--hfast`
option. Do not replace a shared server binary or repoint the development runner.
Both clients under comparison must use the same peer, concurrency, request,
response body, CPU placement and latency configuration. This fixture is not a
production server improvement or evidence of an xdp-http throughput gain.

## Causal gate

The first response's headers are encoded in their ordinary HPACK order, but its
13-byte body is held. After 96 more requests, the peer advertises zero concurrent
streams. The corresponding SETTINGS ACK is distinguished from the initial ACK
by a bounded FIFO count. TCP order then proves all earlier requests have arrived.
Each response finishes using its normal connection and stream credit. Only after
all bodies are queued does a unique opaque PING go out. Its matching ACK proves
the client parsed the complete drain while new streams were disabled. The peer
then restores the original stream limit and serves ordinary requests.

The held response has its own credit and offset outside the sorted pending
queue. Shrinking windows, partial grants, reset and cancellation cannot append
an old stream out of order or resurrect its body. Wrong/early PING ACKs cannot
open the gate; duplicate SETTINGS ACKs and post-pause requests fail visibly.
The gate is 32 bytes per connection, holds only one body descriptor and caps
pre-barrier requests at 1024. It performs no sleep, clock sampling or logging.
Finite client deadlines govern stalled peers; one-stream workloads deliberately
cannot reach the 97-request gate and must be used only as negative cases.

The generated connection layout is exactly 104 bytes on 64-bit systems. Its
fixture-specific assertion is separate from the unchanged production 72-byte
layout test, which the builder compiles and executes independently. Production
unit tests run with the gate absent; ten dedicated gate tests install it
explicitly. Network qualification exercises the actual release fixture.

Independent hyper-h2 tests verify every response's headers, complete body and
END_STREAM, fragmented input/output, partial credit, cancellation, timeout and
GOAWAY. On PING reception, both the independent request ledger and hyper-h2's
open-stream count must be zero. Normal and resumed traffic must finish exactly
256 requests. Expected negative cancellations are reported explicitly.

Before timing, separate diagnostic xdp-http builds must prove every connection
promotes to sparse storage, empties under the pause, ACKs the PING and resumes
in the expected mode. Exclude instrumentation from all timed client builds.
This workload induces one bounded sparse phase followed by ordinary traffic;
it is not representative of permanently dense or continuously sparse traffic.
