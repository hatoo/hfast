# Repeated HTTP/2 initial-window settings

This native peer measures complete response cohorts while a client repeats its
existing `SETTINGS_INITIAL_WINDOW_SIZE`. The `blocked` case opens each stream
with zero body credit, sends 1,024 separate unchanged settings, then grants
13 bytes to finish every response. The `ordinary` guard starts with 13 bytes
of stream credit and sends no repeated settings. Compare identical modes and
parameters between servers; they are different workloads.

The peer validates every SETTINGS ACK, exact response headers, all body bytes,
END_STREAM, a final PING barrier and EOF. Each successful response contributes
one latency sample. Blocked samples include the intentional credit withholding.
One complete connection warms up before the peer prints `warmup-complete` and
waits for one byte on stdin. Measured time includes all subsequent connections,
requests and protocol checks; sample serialization and sorting follow timing.
Samples are retained as little-endian `u64` nanoseconds in the requested file.

Build the peer once and hold it fixed for both immutable release servers:

```sh
rustc --edition=2024 -C opt-level=3 -C lto=fat -C codegen-units=1 \
  benchmarks/h2-unchanged-settings-peer.rs -o /tmp/h2-settings-peer
cargo build --release --locked
# Start one server; hfast pins its sole worker to CPU 0.
target/release/hfast --tcp 18080 --quic 0 --threads 1
```

In another shell, choose a separate CPU available on the host:

```sh
printf x | taskset -c 2 /tmp/h2-settings-peer \
  18080 16384 256 512 blocked /tmp/settings-baseline.samples
```

Arguments are `port streams batch connections blocked|ordinary samples-file`.
Use a new sample filename for each run, alternate baseline/candidate servers,
repeat independently in reversed order, and also run the ordinary guard. Keep
the compiler settings and CPU placement fixed. Avoid concurrent builds/tests
and compare server CPU as well as request rate. Small WSL timing changes need
stronger evidence; a speedup here applies to repeated equal settings on pending
responses, not to HTTP/2 traffic generally.
