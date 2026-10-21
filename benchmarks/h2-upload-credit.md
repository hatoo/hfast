# HTTP/2 request connection credit

Run the independent regression fixture with the locked client dependencies:

```sh
cargo build --release --locked
python -m pip install -r benchmarks/interop-requirements.txt
python benchmarks/h2-upload-credit-check.py target/release/hfast
python benchmarks/h2-upload-credit-check.py target/release/hfast --threads 2
```

The server discards request bodies after sending its constant response. It must
still replenish incoming connection credit: advertising a large stream window
does not change the initial 65,535-byte connection window. The receive ledger
counts complete DATA payloads, including padding, and returns the accumulated
bytes once at least 32 KiB has been consumed. It retains at most 32,767 bytes
between grants and never grants more than it has consumed. Zero-length frames
and non-DATA frames do not earn credit. Response windows remain independent.

The fixture uses hyper-h2 to enforce advertised windows, decode HPACK, check
every response byte and validate stream completion. Unique PING fences follow
the uploaded bytes, so the server's early response cannot be mistaken for
completion of the upload. Cases cover a 1 MiB body followed by 17 more streams
on the same connection, exact credit boundaries, padding-only and single-byte
DATA, blocked response stream and connection windows, fragmented delivery,
delayed final payload bytes, EOF with queued credit, and malformed/overrun DATA.
Existing `h2-data-check.py` additionally covers CONTINUATION interleaving and
large response backlogs at EOF. Both TCP worker configurations run in CI.

The old implementation fails the credit oracle. Comparing its stall with a
progressing server is correctness evidence, not a throughput measurement.
The existing generous per-stream limit (2^31-1 bytes) is unchanged; this fix
does not add per-stream receive bookkeeping or otherwise expand stream-state
validation. The parser's existing tolerance for oversized DATA remains; the
overrun oracle checks the connection ledger independently of that limitation.

Protocol basis: [RFC 9113 DATA accounting](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.1)
and [flow-control windows](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1).
