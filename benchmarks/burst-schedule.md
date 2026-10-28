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
gain. The controller still requires one live server socket and checks every
producer socket, queue and drop counter plus namespace UDP totals. A reference
server with multiple workers requires a separate extension that audits every
owned socket by inode/cookie; do not bypass the single-socket guard. Preserve
the fixed workload and use alternating and independently reversed comparisons,
ordinary-client guards, and every latency population before accepting a change.
