# Sustained asymmetric native workloads

`burst_workers.py --schedule FILE --latency` runs four explicitly configured
producers. Each configuration fixes its role, requests per datagram (`batch`),
datagrams per GSO send, batch count, and start delay in nanoseconds. The schedule
replaces the uniform `--batch`, `--datagrams`, and `--batches` settings. Warmup
batches and measured cycle count remain common to all producers. Every producer
has one active and one quiet connection, with one active burst outstanding.

Build the native peer using `build-sparse-ack-peer.py PATH_TO_SHB NEW_DIRECTORY
--burst`. This extracts the pinned transport from Git objects, builds it, and
runs its debug and release tests without changing the shb checkout.

For example, in an isolated network namespace with loopback enabled:

```sh
python benchmarks/burst_workers.py /immutable/hfast /immutable/burst-peer /new/results \
  --client-cpus 8,10,12,14 --cycles 2 --warmup 64 --latency \
  --udp-receive-buffer 4194304 --schedule benchmarks/burst-schedule-example.json
```

The example declares 4,194,304 hot and 16,384 requests per cold producer per
measured phase. All peers share initial credit of 2048 streams, with exactly
1024 additional streams granted at each complete window. Small cold bursts do
not earn a grant prematurely. Burst widths must divide the common window.
Counts and all response bytes, FINs, fences, packet numbers and credits remain
checked; a wrong count cannot be offset by another producer's extra work.

After handshake and warmup, all producers finish PREPARE (including faulting in
sample storage) before the controller dispatches RUN. RUN carries an absolute
CLOCK_MONOTONIC deadline, 50 ms ahead, plus each declared delay. An expired or
more-than-one-second-ahead deadline fails. The example delays hot work by 5 ms
to allow the cold schedules to begin first. Counts and delays must be identical
for every baseline/candidate comparison; unsuitable runs cannot be repaired by
truncating populations or changing the schedule for just one executable.

Each phase reports its actual start/end, first send and last authenticated
completion. Two monotonic reads bracket the native Instant epoch conversion;
the controller checks the clock identity, time namespace, deadline and phase
bounds. Raw sample files independently verify the reported first/last sample
timestamps after STOP. Even with the most conservative clock bounds, **each
cold first send must precede the hot first send and each cold last completion
must follow the hot last completion**. This checks complete serial schedules;
it does not imply cold requests are continuously outstanding between bursts.

Every warmup and measured sample is retained. The existing combined exact
quantiles are supplemented by hot, cold and per-producer measured populations.
Initial and final overlap margins are reported separately. An unsuitable
overlap produces `schedule-evidence.json`, the complete sample files and failure
snapshots, but no successful `result.json`. Other clock, worker, count, credit
or export failures also fail the run and preserve available failure evidence.

Wall time and full server CPU include RUN dispatch, the 50 ms release lead,
declared start delays, all work, quiet-peer fences and final socket settlement.
PREPARE, export, sample validation and quantile calculation remain outside that
interval. The actual request intervals are reported separately; no samples or
time intervals are silently trimmed. Use `burst_schedule.compare` before
comparing results: it checks the workload, producer binary, CPUs, GRO mode,
receive capacity, warmup, sampling and overlap gates.

`burst-schedule-check.py SERVER PEER NEW_OUTPUT` is a short correctness check
for GRO and fallback delivery, early cold completion, damaged samples and a
failed producer. Its timings are not performance evidence. The ordinary burst
latency/failure suites also remain required.

The example is a starting workload, not a guarantee of overlap on every host.
Passing overlap is insufficient to establish producer headroom or a performance
gain. Preserve the fixed workload and use alternating and independently reversed
comparisons, ordinary-client guards, and every latency population before
accepting a change.

For a server capacity reference, explicitly add `--reference-workers 1` or
`--reference-workers 2`. Use the same immutable server, producer, workload and
client CPUs in both cases; server workers use CPUs 0 through N-1, which must be
available and distinct from every producer CPU. This mode audits the exact set
of process-owned sockets. It is a capacity diagnostic, not an optimization gain:
the usual capacity and schedule comparators reject different worker counts.
The default mode retains its strict single-server-socket/shared-port rejection.

Every reference server socket must be owned by the expected PID/start-time and
namespace, have a distinct inode/SOCK_DIAG cookie, and retain its FD, address and
receive capacity. All sockets on the server port must belong to that exact set;
foreign reuseport sockets cannot be counted as workers. Each producer must own
exactly its active and quiet socket, on unique ports. Every audited socket must
have zero drops and empty send/receive queues. Namespace UDP/error totals, native
body/FIN/credit/fence counts, and every latency/overlap gate remain mandatory.
The actual receive capacity is recorded for each socket; all server workers
must have the same capacity. Missing or unavailable evidence fails the run.

`reference-start.json` and `reference-end.json` retain server observations.
`socket-audit.jsonl` contains the complete server and all producer observations
after warmup and before/after each measured phase, including failed/partial
snapshots. Detailed process/SOCK_DIAG inspection is outside the measured wall
and CPU interval. Final settlement still checks exact live inodes, queues and
drops in both UDP tables inside that interval. These are non-atomic boundary
observations; they do not claim to detect every transient socket lifecycle.

`burst-reference-check.py SERVER PEER NEW_OUTPUT` verifies one/two-worker uniform
and sustained workloads, GRO/fallback, exact exported populations, and bounded
cleanup after real server/producer termination. `test_burst_sockets.py` also
closes, replaces, adds and overflows actual reuseport sockets, introduces a
foreign owner, and checks corrupted identities/capacities and unavailable
diagnostics. Its smoke timings do not establish producer headroom. More workers
can change cold completion times; an unsuitable fixed schedule keeps all samples
but must still fail rather than silently shorten the required overlap.
