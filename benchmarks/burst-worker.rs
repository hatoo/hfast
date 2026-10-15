//! A native producer controlled through bounded, newline-delimited phases.
//! Only the controller samples namespace UDP counters and process CPU time.
use super::*;
use std::io::Write;

const MAX_BATCHES: usize = 1 << 20;

fn command(expected: usize) -> Result<Option<usize>> {
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
            return parse_command(std::str::from_utf8(&bytes)?, expected);
        }
        bytes.push(byte);
        ensure!(bytes.len() < 128, "oversized controller command");
    }
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
) -> Result<()> {
    let first = active.completed;
    let sent = active.sent_datagrams;
    let messages = active.sent_messages;
    let received = active.received_datagrams;
    let start = Instant::now();
    let mut work = BurstWorkspace::new(datagrams);
    work.prepare(active.next_stream, batch, &active.request);
    for i in 0..batches {
        active.burst_batch(batch, &mut work, i + 1 < batches)?;
    }
    let burst_seconds = start.elapsed().as_secs_f64();
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
    ensure!(quiet.stream_limit == quiet.initial_limit);
    // Both sockets remain open while the controller waits for consumption and
    // audits their queues. These pure ACKs do not elicit more server output.
    active.final_ack()?;
    quiet.final_ack()?;
    println!(
        "{}",
        json!({
            "phase": phase, "work": work,
            "active": ledger(active)?, "quiet": ledger(quiet)?,
            "quiet_pings": phase + 1, "pending_requests": 0,
            "pending_fences": 0, "errors": 0,
        })
    );
    std::io::stdout().flush()?;
    Ok(())
}

pub(super) fn main(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 4,
        "usage: peer --worker PORT BATCH DATAGRAMS WARMUP"
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
    let mut active = Peer::connect(port, batch * datagrams)?;
    let mut quiet = Peer::connect(port, batch * datagrams)?;
    run_phase(&mut active, &mut quiet, 0, warmup, batch, datagrams)?;
    let mut phase = 1;
    while let Some(batches) = command(phase)? {
        run_phase(&mut active, &mut quiet, phase, batches, batch, datagrams)
            .with_context(|| format!("worker phase {phase}"))?;
        phase += 1;
    }
    Ok(())
}

#[cfg(test)]
mod peer_tests {
    use super::*;

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
