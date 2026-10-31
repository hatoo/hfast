# Counted HTTP/2 server comparison

`h2_response_cohort.py` runs two processes from one immutable shb binary, on CPUs 8 and 9,
against one hfast TCP worker on CPU 1. Each client uses eight connections,
128 streams per connection, one thread, batch size one, and a 10-second
request timeout. Both collect every latency sample. The server is pinned
after an actual readiness exchange because it sets its own initial affinity.

Use release binaries built with identical compiler/profile settings and save
their revisions and hashes. On Linux, with these CPUs available:

```sh
python3 -m unittest discover -s benchmarks -p test_h2_response_cohort.py -v
python3 benchmarks/h2_response_cohort.py qualification \
  --baseline /absolute/frozen/hfast-baseline \
  --candidate /absolute/frozen/hfast-candidate \
  --client /absolute/frozen/shb \
  --output /absolute/new/results/qualification
```

Output directories must not exist. Every server gets one readiness exchange,
then two concurrent warmups of 4,194,304 requests each. The measured clients
each complete 134,217,728 requests. The aggregate rate is 268,435,456 divided
by one monotonic interval spanning both launches and complete reports. It
includes report processing; it is not the sum of individual client rates.

Each raw report, command, exit status, launch/completion time, CPU/RSS receipt,
and server task snapshot is retained. Every request must succeed with status
200 and exactly one latency sample. Latencies must be finite and ordered.
Per-child byte totals must match across each baseline/candidate pair. Protocol
body correctness is separately checked by the independent interoperability
and flow-control suites; the throughput fixture does not replace those checks.

The controller samples task identities, affinities, and scheduler CPU runtime
every 250 ms. It also computes CPU occupancy over the interval in which both
shb request worker threads are present, excluding the later latency-summary
tail. Qualification needs at least 10 seconds, server occupancy of at least
0.85 core in both full and active intervals, and each producer below 0.90 core.
One-second server occupancy bins are retained for inspection. Review those
bins for sustained load; one busy instant is insufficient.

Only after both qualification runs pass, run `primary` (four alternating
AB/BA pairs). If promising, run `confirm` (three BA-first pairs) and `controls`
(two pairs using the baseline for both labels), each with a new output path.
Require reproducible improvement exceeding uncertainty, normally at least 3%,
and all identical-binary control differences within 3%. No configuration or
CPU sweep is part of this fixture. Failed qualification stops comparisons.

`smoke` uses 16,384 requests per child and is correctness evidence only.
`failure` deliberately exits the second measured child with status 17 while
the first is running. It must fail, retain its partial evidence, and terminate
all owned process groups. Run these before qualification; never overlap other
builds, profiles, or protocol tests with measured phases.
