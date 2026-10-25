# Coalesced QUIC receive regression fixture

This is an untimed correctness check. It changes no server production behavior
and makes no performance claim. The local receive-header-reuse optimization is
still experimental and is not included here.

Ordinary handshakes do not require a particular coalesced layout. This fixture
uses pinned aioquic 1.3.0 for TLS, AEAD/header protection, independent packet
parsing, QUIC recovery and HTTP/3 decoding. Before sending, it checks the exact
packet boundaries, packet-relative PN offsets, tokens, plaintext, packet numbers
and authentication outcomes of each constructed datagram. No hfast wire or
crypto code is imported. Internal aioquic hooks are limited to outgoing layout,
reserved probe packet numbers, retained outgoing test keys and its qlog oracle.

The nine scenarios cover:

- Eighty authenticated Initial PINGs across token lengths 0/1/63/64/255,
  length-varint widths 1/2/4/8 and PN widths 1/2/3/4, followed by ClientHello.
  Every probe and ClientHello must appear in independent Initial ACK evidence.
- Unavailable Handshake/0-RTT spaces and a forged Initial preceding ClientHello.
  Valid Initials must be ACKed; the forgery must not be ACKed.
- All 20 insufficient protection-sample lengths, each followed by an
  authenticated Initial. Every valid successor must be ACKed.
- Initial / Handshake Finished / short request in exactly one datagram, with
  Finished and the request at nonzero offsets. A second variant inserts packets
  in the retired long-header spaces plus 0-RTT before the short request.
- Truncated header/token, oversized length and invalid CID suffixes after a
  retired-space packet on an established connection. The baseline removes this
  connection without a close frame: a new PING must remain unanswered for 350ms
  after a successful initial response/fence. A fresh connection must still work.
  This records existing endpoint behavior, not a general QUIC conformance claim.

All successful cases require exact status 200, full `Hello, World!` body and FIN,
a second POST response and final PING ACK fence. The first request and Finished
must each be transmitted once: recovery cannot hide failure of the tested
coalesced packet. Malformed cases retain their completed first response and fence
before injecting the error. Every case also has independent readiness/liveness
requests, a deadline, bounded subprocess cleanup and transport cleanup. The
default suite accounts for 14 workload responses and 18 readiness/liveness
responses. No request latency or throughput is measured.

Packet rules are described in [RFC 9000 section 12.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2)
and [RFC 9001 section 5.4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2).
Sample bounds are relative to an individual packet. All injected Initial
datagrams are at least 1200 bytes; padding is inside an authenticated packet.
Large coalesced test datagrams are not a throughput workload or a PMTU policy.

```sh
python -m pip install -r benchmarks/interop-requirements.txt
python -m unittest discover -s benchmarks -p test_coalesced_receive.py -v
python benchmarks/coalesced-receive-check.py target/release/hfast --output /tmp/coalesced
python benchmarks/coalesced-receive-check.py target/release/hfast --threads 2
HFAST_GRO_BINARY="$PWD/target/release/hfast" python benchmarks/coalesced-receive-check.py benchmarks/without-udp-gro.py --threads 2
```

`--scenario` selects one case, `--cid-length` selects 0/8/20-byte client CIDs,
and `--timeout` bounds each readiness/workload/liveness stage (default 10s).
`--output` must be a new directory. JSON retains decoded layout metadata, ACK
sets, response hashes/counts, fences, errors and process status even on failure;
it never exports TLS secrets. The shared response ledger's separate negative
tests reject wrong/extra/truncated bodies, status errors, missing FIN and resets.

Six Rust encrypted unit regressions additionally cover every malformed header
prefix, packet-number wrap/reorder/replay and preserved preceding ACK state.
Neither suite establishes that historical general loss-recovery limits are fixed.

Sensitivity was checked against an isolated release mutant that adds the packet's
datagram start to the packet-relative PN offset in `recv_packet`. The ordinary
readiness request still succeeds. `initial-widths` then fails its missing-ACK
check, and `finished` fails because the first request had to be retransmitted.
Thus ordinary eventual HTTP success cannot satisfy this fixture. The unmodified
release server passes both cases and all nine scenarios in the worker/GRO/CID
matrix; production release binaries before and after adding these tests match.
