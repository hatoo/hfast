# HTTP/3 critical stream closure

`critical-stream-check.py` uses pinned aioquic 1.3.0 to verify the encrypted
server response to closing client control, QPACK encoder and QPACK decoder
streams. It requires application CONNECTION_CLOSE `0x104`, following
[RFC 9114 section 6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)
and [RFC 9204 section 4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2).
Unknown types and absent/incomplete type headers remain tolerated.

Each fresh connection completes and validates two responses before closing a
stream. All its type bytes must be acknowledged before FIN/reset. Critical
cases require a peer-decrypted application close and retain the prior two
completions. Harmless cases complete two further responses after an identical
observation interval. Every status, complete 13-byte body and latency sample is
checked; this is correctness evidence, not a performance benchmark.

The matrix covers all four legal varint widths for all three critical types and
both terminal modes, plus unknown/empty/partial headers. Six additional cases
drop the first authenticated application close before aioquic processes frames,
records its packet number or schedules an ACK. Recovery must deliver the same
protected packet, number and close code. This exercises small PTO probes against
the server's bounded closing state. The probe and loss hooks use pinned aioquic
internals; the protocol engine, TLS, encryption and HTTP response decoder remain
independent of hfast. Empty QPACK writes after termination are elided because they
put no bytes on the wire and aioquic otherwise rejects its own H3 no-op writes.

```sh
python -m pip install -r benchmarks/interop-requirements.txt
python -m unittest discover -s benchmarks -p test_critical_stream.py -v
python benchmarks/critical-stream-check.py /absolute/hfast --output /new/results
python benchmarks/critical-stream-check.py /absolute/hfast --threads 2 --output /new/t2
```

`--observe` records the original behavior using the same 30 ordinary cases;
it does not make missing critical closes acceptable in candidate validation.
It omits the six injected-loss cases, which require an actual close to drop.
CI runs all 36 candidate cases with one/two workers and with UDP GRO denied,
and retains JSON reports even when the gate fails. Binary hashes must match
before/after. The separate failure controls reject wrong/missing closes, missing
prefix ACKs, extra/incomplete completions, body/sample mismatches and failed
loss injection or recovery. `passed` is true only for a complete matrix.

Rust tests additionally cover sparse/reordered/overlapping prefixes, terminal
before type, duplicate/late frames, invalid final sizes and receive credit,
stream limits, both key phases, queued same-packet responses, prior valid work,
rate limits and the unchanged closing deadline. Type storage is exactly nine
bytes per advertised stream (72 bytes for eight), with no stream payload
reassembly or allocation. Closing packet state is allocated only on rejection.
General QUIC loss-recovery limitations are not claimed fixed by these tests.
