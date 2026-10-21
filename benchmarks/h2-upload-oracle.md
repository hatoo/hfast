# Native HTTP/2 upload accounting

The standalone Rust peer sends 1 MiB of DATA across 16 POST streams, followed
by a GET and a unique PING, on each connection. It enforces the 65,535-byte
connection window and checks all 32 returned credit grants and 17 responses.
Padding and the pad-length byte count toward uploaded bytes and flow control.
Every response must contain the expected status, headers, body and END_STREAM.

A cycle completes after the final PING ACK and clean EOF. The peer half-closes
its request direction after validating the PING ACK and continues reading, with a
timeout, until EOF. Checking only bytes already buffered after the PING can
miss delayed extra output and incorrectly report a successful cycle. Both
immediately buffered and later extra bytes are rejected. Missing output, failed
reads and any protocol mismatch terminate the peer without a timing result.

Build and run the independent checks:

```sh
python -m pip install -r benchmarks/interop-requirements.txt
rustc --edition=2024 --test benchmarks/h2-upload-peer.rs -o /tmp/h2-upload-tests
/tmp/h2-upload-tests
rustc --edition=2024 --test -O benchmarks/h2-upload-peer.rs -o /tmp/h2-upload-tests-release
/tmp/h2-upload-tests-release
rustc --edition=2024 -O -C lto=fat -C codegen-units=1 \
  benchmarks/h2-upload-peer.rs -o /tmp/h2-upload-peer
cargo build --release --locked
python benchmarks/h2-upload-oracle-check.py /tmp/h2-upload-peer \
  --server target/release/hfast
```

The Python scripted server decodes the client's HPACK independently, validates
every request frame, body byte, padding byte and stream boundary, and tracks
connection credit independently of the Rust oracle. It exercises ordinary and
fragmented padded exchanges over multiple connections. Its 24 fault cases
include absent, zero, excessive, duplicated, malformed and wrong-stream credit;
corrupt or incomplete responses; premature, wrong or absent fences; truncation;
resets; GOAWAY; and extra output after a valid fence. Each fault must produce the
expected diagnostic, a failing exit status and no success JSON. The delayed
extra-output case waits for the client's write EOF after it has validated the
PING ACK, so the extra bytes arrive after that read. No sleeps are used.

The same command checks both server worker configurations with padded/unpadded
payloads and 53-byte/16-KiB writes. It validates exact wire-byte, response, grant,
fence and EOF counts and retains every cycle latency. `--case delayed-after-fence`
runs one scripted fault in isolation; omit `--server` to run only scripted cases.
These short CI runs establish correctness, not performance improvements.

The peer can also be invoked directly:

```sh
/tmp/h2-upload-peer 127.0.0.1:8080 4 16384 0
# Arguments: address, connection cycles, write chunk size, padding bytes (0..255).
```

It deliberately checks hfast's fixed response encoding, SETTINGS and credit
batching policy. It is not a general HTTP/2 client. Counts include whole DATA
payloads, including padding; timings include connection setup, upload, responses,
the final fence and EOF. The EOF boundary changes the workload compared with
older peers that stopped at a PING; never compare those timings as a speedup.
For performance use identical immutable peers, workloads and release settings,
warmup, alternating comparisons, independent confirmation and CPU/latency guards.
The existing hyper-h2 fixtures provide separate protocol interoperability checks.
