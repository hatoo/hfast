# Bounded UDP receive descriptor initialization

`ReceiveBatch::receive_with` initializes only the active adaptive prefix of its
iovec, message-header and GRO-control arrays. The unused stack tail remains
`MaybeUninit`; only initialized entries become a slice passed to the synchronous
receive operation. Pointers remain valid through the call and output decoding.

The payload buffers, singleton recvmsg path, batching policy, errors, GRO parsing,
truncation checks, datagram accounting and timer cadence are unchanged.

Run `cargo test --locked quic::udp` and the equivalent release command. The six
`receive_prefix_tests` cases cover initialized inputs, partial/full/zero outputs,
errors and reuse, truncation, singleton transitions, kernel delivery, and rejection
of a callback count beyond the initialized prefix. The five model tests can also
run under Miri in a small crate importing the actual udp.rs and locked libc.

This is an experimental optimization. Deterministic instruction counts must be
qualified across full encrypted receive/flush cycles; they do not establish
server throughput or kernel CPU savings. End-to-end acceptance requires matched
immutable-server comparisons with each fixed client, exact completion/error/latency
accounting, and independent confirmation above measurement uncertainty.
