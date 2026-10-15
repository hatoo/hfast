# Native CRYPTO connection churn

This workload checks whether CRYPTO reassembly costs matter across full TLS and
HTTP/3 connections. It does not modify either production binary. The builder
extracts shb `12e95af17ef6015020776ab65996bef9531099e0` from Git objects into a
new directory, installs the workload, tests it, and freezes the resulting peer.
The manifest records the source, compiler, commands, and executable hash.

```
python benchmarks/build-crypto-churn-peer.py /path/to/shb /tmp/crypto-peer
python -m unittest discover -s benchmarks -p test_crypto_churn.py -v
python benchmarks/crypto-churn-interop.py /tmp/crypto-peer/crypto-churn-peer /tmp/crypto-interop
unshare --user --map-root-user --net sh -c 'ip link set lo up && exec "$@"' smoke \
  python benchmarks/crypto-churn-check.py /path/to/hfast \
  /tmp/crypto-peer/crypto-churn-peer /tmp/crypto-smoke
```

The peer fragments each Initial and Handshake TLS flight into chunks of at most
96 bytes (at least three chunks). `normal` preserves byte order; `reverse`
releases the prefix last; `overlap-duplicates` repeats the highest range eight
extra times and overlaps the withheld prefix. Each range occupies a fresh QUIC
packet number in its epoch. TLS bytes are checked before serialization, and the
independent aioquic server decrypts them and checks actual ranges, overlapping
bytes, packet numbers, full TLS completion, exact request headers, and closes.
Neither encrypted packet replay nor TLS resumption is used.

One or four producer processes each retain one UDP socket. Every connection
must finish TLS, receive exactly one status-200 response with the expected
headers/body and FIN, complete an ACK fence, and send an authenticated close.
The next handshake uses fresh keys at the same address. A separate final
handshake verifies replacement of the last measured connection. Thus at most
one server address per producer can remain, even during teardown. There are no
concurrent connections within a producer. Loss, unexpected response frames,
packet reordering or duplication, and incomplete work fail the run. This is a
controlled loopback fixture, not a general QUIC recovery test.

The controller owns global UDP counters, checks exact aggregate receive delivery
including closes, checks error counters and empty socket queues, and rejects any
failed producer. Every connection latency is retained. Server and producer CPU
are accompanied by partial connection/request/TLS counts and all completed
latency samples when a connection fails; the failed attempt has its own elapsed
time. Warmup and retirement failures are labeled separately. CPU measurements
are `/proc` user/system counters over the same coordinated phase; server CPU
sampling excludes warmup and final retirement probes. Wall time includes report
collection, and producer CPU includes verification/reporting overhead. Short
smoke rates and CPU counters are not performance evidence.

For timing, use immutable release builds with matching settings, one fixed peer,
an otherwise idle isolated network namespace, and distinct CPUs from server CPU
0. First check whether one/four producers can drive the server. Different
producer counts are different workloads and must not be described as a gain.

```
unshare --user --map-root-user --net sh -c 'ip link set lo up && exec "$@"' compare \
  python benchmarks/compare-crypto-churn.py /path/to/baseline /path/to/candidate \
  /tmp/crypto-peer/crypto-churn-peer /tmp/crypto-primary \
  --mode overlap-duplicates --connections 12000 --pairs 3 --client-cpus 2 4 6 8
```

Repeat in a new directory with `--candidate-first` for independent reversed
confirmation. Test all three schedules. Retain all raw reports and failures.
An improvement still needs uncertainty assessment and ordinary fixed-client
serial/concurrent CPU and latency guards; this fixture cannot establish that a
microbenchmark saving improves steady-state HTTP throughput. The fixed small TLS
messages also do not model arbitrarily large certificates or sparse attack input.
