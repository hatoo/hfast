# Timer-driven HTTP/2 persistent-pin fixture

This test peer keeps old responses open while completing younger requests. It
supports validation of bounded stream tracking under sustained sparse traffic.
It is a separate generated executable; production hfast sources and Cargo files
are not modified. There is no server throughput improvement claim.

The generator archives hfast `d66a790f895f80c76ea8c1cedadb84dd7958fde5`, checks
every insertion anchor, and appends the fixture code. The design extends the
bounded response/pause/PING barrier from the C451 H2 drain fixture.

Each connection holds at most two response tails. It sends up to the first 12
bytes of the normal 13-byte body using real connection and stream credit. All
younger responses use the ordinary H2 response path. A monotonic timer starts
on the first pinned request. At one second, a separate worker timer event sends
`SETTINGS_MAX_CONCURRENT_STREAMS=0`. The peer waits for its acknowledgment,
finishes held bodies subject to flow control, and sends PING only when every
pending body is finished or reset. The matching PING acknowledgment proves the
client parsed the preceding final bytes before the stream limit reopens.

New traffic can start another hold cycle. A quiet connection starts no cycle;
one outstanding request can complete without any further requests. Clients must
still process SETTINGS/PING and return receive credit while draining. GOAWAY and
connection close cancel pending work rather than proving a completed drain.

The fixture adds a fixed 72-byte gate to the 72-byte H2 connection. Held responses
live outside the sorted pending queue. Ordinary blocked bodies are limited to
1024; exceeding this fixture limit fails visibly. A worker timerfd wakes every
10 ms and visits live sockets outside all I/O buffer borrowing barriers. The
fixture requires the multishot/provided-buffer worker and fails visibly if that
capability is unavailable. The production fallback implementation is unchanged.

```sh
python3 benchmarks/build-h2-pin-peer.py . /absolute/new/fixture-directory
python3 benchmarks/check-h2-pin-peer.py \
  /absolute/new/fixture-directory/h2-pin-peer /absolute/new/interop-one
python3 benchmarks/check-h2-pin-peer.py \
  /absolute/new/fixture-directory/h2-pin-peer /absolute/new/interop-two --threads 2
```

Python 3.12, `h2==4.4.1`, Rust with rustfmt/Clippy, and Linux io_uring are needed.
The build runs all 58 original H2 tests, including the original layout contract,
then formatting, all 459 generated tests in debug and release, production Clippy
with warnings denied, and the release build. The frozen executable's manifest
records its hash, compiler, source hashes, and generator inputs. Test compilation
keeps ordinary production tests on ordinary connections; the 11 additional tests
explicitly enable the fixture and timer.

The independent hyper-h2 checker runs nine cases with each worker count: repeated
cycles, a single pin, byte-fragmented input, reduced stream credit, exhausted
connection credit, reset, expected pre-release timeout/cancellation, GOAWAY, and
large continued headers. It validates every completed body and the causal drain
barrier. The expected cancellations are recorded separately from completions.

`--trace` builds a diagnostic variant that logs pause/drain boundaries and the
number of requests accepted at connection closure. Never use that variant for
throughput measurements. `--generate-only` prepares inspectable source without
building it. Output directories must be new. The optional `C455_TARGET` environment
variable selects a separate Cargo target directory; use different targets for
concurrent builds.

## Benchmark-integrity finding

Qualification against frozen shb default `d29fae1` and the experimental C454
candidate `0fa4e2f` found that `-z 250ms` closes connections with pinned responses
still outstanding. Across cleartext/TLS and one/two workers, each four-connection
run left eight pins open and reported 98–128 fewer completed requests than the
peer had accepted, despite reporting zero errors. Equal reported totals and
latency sample counts do **not** establish a complete final drain.

Count-bounded `-n 512` runs of both shb binaries passed the same cleartext/TLS and
worker matrix with exactly 512 completed responses and samples each. Sustained
duration-mode throughput acceptance is blocked on final-drain accounting; this
fixture must not be used to claim an improvement from truncated responses.
The workflow qualifies the fixture independently of these external client builds.
