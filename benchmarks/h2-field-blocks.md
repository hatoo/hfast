# HTTP/2 field-block workload and regression tests

This fixture sends valid, exact-size, non-Huffman HPACK field blocks through
HEADERS/CONTINUATION frames of at most 16 KiB. It checks hfast's fixed response
bytes, stream order, END_STREAM, a final PING and EOF after half-close. It is a
correctness and benchmark tool; changes between fixture modes are not evidence
of a server performance improvement.

Build and independently validate it:

```sh
cargo test --locked
cargo test --release --locked
cargo build --release --locked
python3 -m venv /tmp/hfast-interop
/tmp/hfast-interop/bin/pip install -r benchmarks/interop-requirements.txt
rustfmt --edition 2024 --check benchmarks/h2-field-peer.rs
rustc --edition=2024 -D warnings --test benchmarks/h2-field-peer.rs -o /tmp/h2-field-tests
/tmp/h2-field-tests
rustc --edition=2024 -D warnings --test -O benchmarks/h2-field-peer.rs -o /tmp/h2-field-tests-release
/tmp/h2-field-tests-release
rustc --edition=2024 -D warnings -O -C lto=fat -C codegen-units=1 benchmarks/h2-field-peer.rs -o /tmp/h2-field-peer
/tmp/hfast-interop/bin/python benchmarks/h2-field-check.py target/release/hfast --peer /tmp/h2-field-peer
```

The independent hyper-h2 oracle decodes each request, checks exact field lengths
and stream IDs, and withholds replies until each full or short group arrives.
It tracks connection and stream flow control, including runs exceeding the
initial connection window. Faults cover corrupt, missing, duplicated, reordered,
truncated and unfinished responses, incorrect or missing PING replies, and extra
bytes after the fence. Failed clients must exit unsuccessfully without a JSON
benchmark result, with the expected failure reason. Live tests use both 16 KiB
and 1 MiB fields, pipelines 1/8/64, three active connections, short final groups,
and exact per-connection byte, credit and latency-sample counts.

Rust tests cover every byte split of a 16 KiB frame, error timing, continuation
and control ordering, queued partial output, truncated fields, and actual
io_uring output draining after half-close. Opaque payload and ignored flag
variants preserve hfast's existing parser behavior; the hyper-h2 cases provide
independent valid-protocol coverage.

Run the native peer against an hfast TCP port:

```sh
/tmp/h2-field-peer 8080 16384 65536 8192 8 64 > samples.json
```

Arguments are `port block_bytes write_chunk requests_per_connection connections
[pipeline=1]`. Blocks range from 32 bytes to 1 MiB; pipelines range from 1 to 64.
The original five-argument invocation keeps pipeline 1. Each connection owns one
reusable request buffer and at most 64 outstanding timestamps; it never builds
a pipeline-sized copy of the payload. Each request timestamp precedes its first
write and ends only after its exact response has been read. Samples are retained
in connection-ID order, then request order (stream IDs 1, 3, 5, ...), including
all final short groups. Elapsed time covers request delivery and completion;
setup and final fences remain outside the timed interval.

At group boundaries the peer returns connection credit after consuming at least
32768 response bytes. Even a full group needs only 64 * 13 bytes, so the peer
cannot exhaust the initial 65535-byte window before sending the next update.
Each new stream has sufficient default stream credit for its 13-byte response.
The JSON includes per-peer request/sample/field-byte and complete wire ledgers.
`application_writes` counts `write_all` calls, not kernel syscalls. TCP can merge
or split writes; a write chunk does not promise a particular receive boundary.

Compare immutable release server binaries with the same final workload:

```sh
python3 benchmarks/compare-h2-fields.py /abs/hfast-baseline /abs/hfast-candidate \
  /tmp/h2-field-peer /tmp/h2-fields-primary --cases 16k-4k 1m-4k \
  --pipeline 64 --write-chunk 65536 --server-cpu 1 --client-cpu 8
python3 benchmarks/compare-h2-fields.py /abs/hfast-baseline /abs/hfast-candidate \
  /tmp/h2-field-peer /tmp/h2-fields-confirmation --cases 16k-4k 1m-4k \
  --pipeline 64 --write-chunk 65536 --server-cpu 1 --client-cpu 8 --reverse
```

Select available CPU IDs. The Linux runner records hashes, commands, warmups,
all raw latency samples, per-run CPU time, server scheduler runtime and runqueue,
and alternates server order. It checks every peer and reconciles paired wire
counts. `--requests`, `--connections`, `--pairs` and `--smoke` bound a run. Case
names describe the historical defaults; the recorded options and commands are
authoritative when write chunk or count overrides are present.

Keep the client binary and all workload options identical between server
variants. Independent confirmation, zero unexpected errors, correctness tests,
and improvement beyond uncertainty are required before accepting an optimization.
WSL throughput noise and a client delivery ceiling can leave comparisons
inconclusive; allocation or copy-count evidence alone is not a throughput gain.
