//! A native producer controlled through bounded, newline-delimited phases.
//! Only the controller samples namespace UDP counters and process CPU time.
use super::*;
use std::io::Write;

#[path = "udp_socket_evidence.rs"]
mod udp_socket_evidence;

const MAX_BATCHES: usize = 1 << 20;

fn monotonic_ns() -> Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "monotonic clock read failed"
    );
    ensure!(
        time.tv_sec >= 0 && (0..1_000_000_000).contains(&time.tv_nsec),
        "invalid clock"
    );
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(time.tv_nsec as u64))
        .context("clock overflow")
}

fn scheduled_command(line: &str, phase: usize, batches: usize, now: u64) -> Result<u64> {
    let (command, deadline) = line
        .rsplit_once(' ')
        .context("missing scheduled deadline")?;
    ensure!(
        parse_command(command, phase)? == Some(batches),
        "scheduled work mismatch"
    );
    let deadline: u64 = deadline.parse()?;
    ensure!(
        deadline > now && deadline - now <= 1_000_000_000,
        "scheduled deadline expired or too far ahead"
    );
    Ok(deadline)
}

fn wait_until(deadline: u64) -> Result<()> {
    loop {
        let now = monotonic_ns()?;
        if now >= deadline {
            return Ok(());
        }
        if deadline - now > 100_000 {
            std::thread::sleep(Duration::from_nanos(deadline - now - 100_000));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn command_line() -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut bytes = Vec::new();
    loop {
        ensure!(Instant::now() < deadline, "controller command timeout");
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut fd, 1, 100) };
        ensure!(ready >= 0, "controller poll failed");
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        let n = unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) };
        ensure!(n == 1, "controller disconnected");
        if byte == b'\n' {
            return Ok(std::str::from_utf8(&bytes)?.to_owned());
        }
        bytes.push(byte);
        ensure!(bytes.len() < 128, "oversized controller command");
    }
}

fn command(expected: usize) -> Result<Option<usize>> {
    parse_command(&command_line()?, expected)
}

fn prepare_command(line: &str, phase: usize) -> Result<Option<usize>> {
    if line == "STOP" {
        return Ok(None);
    }
    let work = line.strip_prefix("PREPARE ").context("expected PREPARE")?;
    parse_command(&format!("RUN {work}"), phase)
}

fn export_command(line: &str, phase: usize) -> Result<()> {
    ensure!(
        line == format!("EXPORT {phase}"),
        "expected latency EXPORT phase {phase}"
    );
    Ok(())
}

fn parse_command(line: &str, expected: usize) -> Result<Option<usize>> {
    if line == "STOP" {
        return Ok(None);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    ensure!(
        fields.len() == 3 && fields[0] == "RUN",
        "invalid worker command"
    );
    ensure!(
        fields[1].parse::<usize>()? == expected,
        "wrong worker phase"
    );
    let batches = fields[2].parse()?;
    ensure!((1..=MAX_BATCHES).contains(&batches), "invalid batch count");
    Ok(Some(batches))
}

fn ledger(peer: &Peer) -> Result<Value> {
    Ok(json!({
        "port": peer.socket.local_addr()?.port(),
        "completed": peer.completed, "next_stream": peer.next_stream,
        "initial_limit": peer.initial_limit, "stream_limit": peer.stream_limit,
        "initial_max_data": peer.initial_max_data, "max_data": peer.max_data,
        "sent_data": peer.sent_data,
        "sent_datagrams": peer.sent_datagrams, "sent_messages": peer.sent_messages,
        "received_datagrams": peer.received_datagrams,
        "last_sent": peer.last_sent, "acked_through": peer.acked_through,
        "last_received": peer.last_received, "packet_count": peer.packet_count,
    }))
}

fn run_phase(
    active: &mut Peer,
    quiet: &mut Peer,
    phase: usize,
    batches: usize,
    batch: usize,
    datagrams: usize,
    run_at: Option<u64>,
) -> Result<()> {
    let first = active.completed;
    let sent = active.sent_datagrams;
    let messages = active.sent_messages;
    let received = active.received_datagrams;
    let clock_before = monotonic_ns()?;
    let start = Instant::now();
    let clock_after = monotonic_ns()?;
    let mut work = BurstWorkspace::new(datagrams);
    work.prepare(active.next_stream, batch, &active.request);
    for i in 0..batches {
        active.burst_batch(batch, &mut work, i + 1 < batches)?;
    }
    let burst_seconds = start.elapsed().as_secs_f64();
    if let Some(latency) = active.latency.as_mut() {
        latency.finish(Instant::now())?;
    }
    let work = json!({
        "batches": batches, "requests": active.completed - first,
        "first_completed": first, "completed": active.completed,
        "request_datagrams": batches * datagrams, "fences": batches,
        "sent_datagrams": active.sent_datagrams - sent,
        "sent_messages": active.sent_messages - messages,
        "received_datagrams": active.received_datagrams - received,
        "burst_seconds": burst_seconds,
    });
    quiet.ping(Some(quiet.last_received))?;
    ensure!(quiet.completed == 0 && quiet.next_stream == 0);
    ensure!(
        quiet.latency.is_none(),
        "quiet peer collected request samples"
    );
    ensure!(quiet.stream_limit == quiet.initial_limit);
    // Both sockets remain open while the controller waits for consumption and
    // audits their queues. These pure ACKs do not elicit more server output.
    active.final_ack()?;
    quiet.final_ack()?;
    let mut report = json!({
        "phase": phase, "work": work,
        "active": ledger(active)?, "quiet": ledger(quiet)?,
        "quiet_pings": phase + 1, "pending_requests": 0,
        "pending_fences": 0, "errors": 0,
    });
    if let Some(latency) = &active.latency {
        report["latency"] = latency.metadata();
        let offset = latency.ns(start)?;
        let (first_sent, last_complete) = latency.bounds()?;
        report["phase_clock"] = json!({
            "clock": "CLOCK_MONOTONIC",
            "namespace": std::fs::read_link("/proc/self/ns/time")?.to_string_lossy(),
            "run_at_ns": run_at,
            "start_ns": clock_before,
            "epoch_low_ns": clock_before.checked_sub(offset).context("clock epoch underflow")?,
            "epoch_high_ns": clock_after.checked_sub(offset).context("clock epoch underflow")?,
            "end_ns": monotonic_ns()?,
            "first_sent_ns": first_sent, "last_complete_ns": last_complete,
        });
    }
    println!("{report}");
    std::io::stdout().flush()?;
    Ok(())
}

fn failure_peer(peer: &Peer) -> Value {
    let ledger = match ledger(peer) {
        Ok(row) => json!({"status": "available", "value": row}),
        Err(error) => json!({"status": "unavailable", "error": format!("{error:#}")}),
    };
    json!({"ledger": ledger, "socket": udp_socket_evidence::snapshot(&peer.socket)})
}

fn report_failure(phase: usize, error: &anyhow::Error, active: &Peer, quiet: Option<&Peer>) {
    // Only failed runs pay for /proc and getsockopt. Observe our still-owned
    // sockets before unwinding, even if the controller later sees an exited PID.
    // A broken diagnostic stream must not replace the protocol error.
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        json!({"kind": "burst_failure", "phase": phase, "pid": std::process::id(),
            "error": format!("{error:#}"), "timing_evidence": false,
            "udp_table": match std::fs::read_to_string("/proc/self/net/udp") {
                Ok(table) => json!({"status": "available", "value": table}),
                Err(error) => json!({"status": "unavailable", "error": error.to_string()}),
            },
            "active": failure_peer(active),
            "quiet": quiet.map(failure_peer).unwrap_or_else(||
                json!({"status": "unavailable", "error": "quiet connection not established"})),
        })
    );
}

fn prepare_latency(
    active: &mut Peer,
    producer: usize,
    phase: usize,
    batches: usize,
    batch: usize,
    datagrams: usize,
) -> Result<()> {
    // Drop the preceding ledger before reserving the next one.
    active.latency = None;
    active.latency = Some(burst_latency::Ledger::new(
        producer,
        phase,
        active.next_stream,
        batches
            .checked_mul(batch)
            .and_then(|n| n.checked_mul(datagrams))
            .context("latency count overflow")?,
        Instant::now(),
    )?);
    Ok(())
}

fn export_latency(active: &mut Peer, directory: &std::path::Path, phase: usize) -> Result<()> {
    export_command(&command_line()?, phase)?;
    let metadata = active
        .latency
        .as_mut()
        .context("missing latency ledger")?
        .export(&directory.join(format!("phase-{phase}.bin")), false)?;
    println!("{}", json!({"phase": phase, "latency_export": metadata}));
    std::io::stdout().flush()?;
    Ok(())
}

pub(super) fn main(args: &[String]) -> Result<()> {
    ensure!(
        args.len() >= 4,
        "usage: peer --worker PORT BATCH DATAGRAMS WARMUP [--latency-dir NEW_DIRECTORY] [--initial-window N] [--scheduled]"
    );
    ensure!(
        std::env::var_os("BURST_QUEUE_AUDIT").is_none(),
        "worker cannot use queue audit"
    );
    let port = args[0].parse()?;
    let batch: usize = args[1].parse()?;
    let datagrams: usize = args[2].parse()?;
    let warmup: usize = args[3].parse()?;
    ensure!((1..=32).contains(&batch) && (1..=32).contains(&datagrams));
    ensure!((1..=MAX_BATCHES).contains(&warmup));
    let mut directory = None;
    let mut initial_window = None;
    let mut scheduled = false;
    let mut options = args[4..].iter();
    while let Some(flag) = options.next() {
        match flag.as_str() {
            "--latency-dir" if directory.is_none() => {
                directory = Some(std::path::PathBuf::from(
                    options.next().context("missing latency directory")?,
                ));
            }
            "--initial-window" if initial_window.is_none() => {
                initial_window = Some(
                    options
                        .next()
                        .context("missing initial window")?
                        .parse::<usize>()?,
                );
            }
            "--scheduled" if !scheduled => scheduled = true,
            _ => bail!("invalid or repeated worker option: {flag}"),
        }
    }
    ensure!(
        !scheduled || directory.is_some(),
        "scheduled work requires every latency sample"
    );
    let window = initial_window.unwrap_or(batch * datagrams);
    ensure!(
        (batch * datagrams..=1024).contains(&window),
        "invalid initial window"
    );
    ensure!(
        window.is_multiple_of(batch * datagrams),
        "burst width must divide initial window"
    );
    let producer: usize = if directory.is_some() {
        std::env::var("BURST_PRODUCER_INDEX")
            .unwrap_or_else(|_| "0".to_owned())
            .parse()?
    } else {
        0
    };
    ensure!(producer < 4, "invalid latency producer");
    if let Some(path) = &directory {
        // Exclusive creation also prevents accidental reuse of prior evidence.
        std::fs::create_dir(path)?;
    }
    let mut active = Peer::connect(port, window)?;
    let mut quiet = match Peer::connect(port, window) {
        Ok(peer) => peer,
        Err(error) => {
            report_failure(0, &error, &active, None);
            return Err(error);
        }
    };
    let mut phase = 0;
    let result = (|| -> Result<()> {
        if directory.is_some() {
            prepare_latency(&mut active, producer, 0, warmup, batch, datagrams)?;
        }
        run_phase(&mut active, &mut quiet, 0, warmup, batch, datagrams, None)?;
        if let Some(path) = &directory {
            export_latency(&mut active, path, 0)?;
        }
        phase = 1;
        loop {
            let mut run_at = None;
            let batches = if directory.is_some() {
                let Some(batches) = prepare_command(&command_line()?, phase)? else {
                    break;
                };
                prepare_latency(&mut active, producer, phase, batches, batch, datagrams)?;
                println!(
                    "{}",
                    json!({"phase": phase, "latency_ready": active.latency.as_ref().unwrap().metadata()})
                );
                std::io::stdout().flush()?;
                if scheduled {
                    let line = command_line()?;
                    let deadline = scheduled_command(&line, phase, batches, monotonic_ns()?)?;
                    run_at = Some(deadline);
                    wait_until(deadline)?;
                } else {
                    ensure!(
                        command(phase)? == Some(batches),
                        "RUN differs from prepared latency work"
                    );
                }
                batches
            } else {
                let Some(batches) = command(phase)? else {
                    break;
                };
                batches
            };
            run_phase(
                &mut active,
                &mut quiet,
                phase,
                batches,
                batch,
                datagrams,
                run_at,
            )
            .with_context(|| format!("worker phase {phase}"))?;
            if let Some(path) = &directory {
                export_latency(&mut active, path, phase)?;
            }
            phase += 1;
        }
        Ok(())
    })();
    if let Err(error) = &result {
        if let (Some(path), Some(latency)) = (&directory, active.latency.as_mut()) {
            let evidence = match latency.export(&path.join(format!("failure-{phase}.bin")), true) {
                Ok(metadata) => json!({"status": "available", "metadata": metadata}),
                Err(diagnostic) => {
                    json!({"status": "unavailable", "error": format!("{diagnostic:#}")})
                }
            };
            let _ = writeln!(
                std::io::stderr(),
                "{}",
                json!({"kind": "burst_latency_failure",
                "phase": phase, "timing_evidence": false, "latency": evidence})
            );
        }
        report_failure(phase, error, &active, Some(&quiet));
    }
    result
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    #[test]
    fn scheduled_commands_bind_phase_count_and_bounded_future_clock() {
        assert_eq!(
            scheduled_command("RUN 2 4096 101", 2, 4096, 100).unwrap(),
            101
        );
        for line in [
            "RUN 1 4096 101",
            "RUN 2 4095 101",
            "RUN 2 4096",
            "STOP 101",
            "RUN 2 4096 100",
            "RUN 2 4096 99",
            "RUN 2 4096 1000000101",
            "RUN 2 4096 -1",
        ] {
            assert!(scheduled_command(line, 2, 4096, 100).is_err(), "{line}");
        }
    }

    #[test]
    fn partial_cold_bursts_require_exact_whole_credit_grants() {
        for (completed, expected) in [
            (0, 2048),
            (1, 2048),
            (1023, 2048),
            (1024, 3072),
            (1025, 3072),
            (2047, 3072),
            (2048, 4096),
        ] {
            assert_eq!(granted_stream_limit(2048, completed).unwrap(), expected);
        }
        for initial in [0, 1, 3] {
            assert!(granted_stream_limit(initial, 1).is_err());
        }
        assert!(granted_stream_limit(2, u64::MAX).is_err());
    }

    #[test]
    fn sampling_commands_require_separate_ordered_prepare_run_and_export() {
        assert_eq!(prepare_command("PREPARE 1 8", 1).unwrap(), Some(8));
        assert_eq!(prepare_command("STOP", 1).unwrap(), None);
        for bad in [
            "RUN 1 8",
            "PREPARE 0 8",
            "PREPARE 2 8",
            "PREPARE 1 0",
            "PREPARE 1 1048577",
            "PREPARE 1 8 extra",
            "EXPORT 1",
        ] {
            assert!(prepare_command(bad, 1).is_err(), "{bad}");
        }
        export_command("EXPORT 1", 1).unwrap();
        for bad in [
            "EXPORT 0",
            "EXPORT 2",
            "EXPORT 1 extra",
            "EXPORT 01",
            "STOP",
            "RUN 1 8",
        ] {
            assert!(export_command(bad, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn commands_reject_repeated_skipped_and_unbounded_work() {
        assert_eq!(parse_command("RUN 1 8", 1).unwrap(), Some(8));
        assert_eq!(parse_command("STOP", 1).unwrap(), None);
        for bad in [
            "RUN 0 8",
            "RUN 2 8",
            "RUN 1 0",
            "RUN 1 1048577",
            "RUN 1 8 extra",
            "STOP extra",
            "RUN 1",
            "RUN -1 8",
        ] {
            assert!(parse_command(bad, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn four_workers_keep_independent_response_and_fence_oracles() {
        let mut batches: Vec<_> = (0..4).map(|_| Batch::new(0, 2)).collect();
        let mut fences: Vec<_> = (0..4)
            .map(|i| Fence {
                expected: Some([i; 8]),
                seen: false,
            })
            .collect();
        for index in [3, 1, 0, 2] {
            batches[index].response(1, 0, 0, true, RESPONSE).unwrap();
            assert!(batches[index].complete().is_err());
            assert!(batches[index].response(2, 4, 0, false, RESPONSE).is_err());
            assert!(batches[index].response(2, 4, 0, true, b"wrong").is_err());
            batches[index].response(2, 4, 0, true, RESPONSE).unwrap();
            assert!(batches[index].response(2, 4, 0, true, RESPONSE).is_err());
            batches[index].complete().unwrap();
        }
        for index in [2, 0, 3] {
            fences[index].response([index as u8; 8]).unwrap();
        }
        assert!(fences.iter().try_for_each(Fence::complete).is_err());
        assert!(fences[1].response([2; 8]).is_err());
        fences[1].response([1; 8]).unwrap();
        fences.iter().try_for_each(Fence::complete).unwrap();
    }
}
