use super::tests::ring;
use super::*;
use std::time::{Duration, Instant};

#[test]
fn zero_wait_and_full_sq_run_multishot_work_before_republishing_buffers() {
    let mut io = ring(2);
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let receive = opcode::RecvMulti::new(types::Fd(socket.as_raw_fd()), GROUP)
        .build()
        .user_data(RECV | 1);
    unsafe { push(io.ring(), &receive) };
    submit(io.ring(), 0);
    for round in 0..32_u8 {
        let bytes = [round; 17];
        peer.write_all(&bytes).unwrap();
        // The ninth NOP enters through push's SQ-pressure path. Deferred
        // receive work must run there even if ready completions already exist.
        for token in 100..109 {
            let nop = opcode::Nop::new().build().user_data(token);
            unsafe { push(io.ring(), &nop) };
        }
        let end = Instant::now() + Duration::from_secs(2);
        let mut nops = Vec::new();
        let mut observed = Vec::new();
        while nops.len() < 9 || observed.len() < bytes.len() {
            submit(io.ring(), 0);
            let completions: Vec<_> = io.ring().completion().collect();
            for c in completions {
                if c.user_data() == RECV | 1 {
                    assert!(c.result() > 0 && cqueue::more(c.flags()));
                    let id = io.pool.claim(c.result(), c.flags()).unwrap();
                    observed.extend_from_slice(io.pool.bytes(id, c.result() as usize));
                    io.pool.release(id);
                    io.pool.publish();
                } else {
                    assert_eq!(c.result(), 0);
                    nops.push(c.user_data());
                }
            }
            assert!(Instant::now() < end, "deferred multishot was stranded");
        }
        nops.sort_unstable();
        assert_eq!(nops, (100..109).collect::<Vec<_>>());
        assert_eq!(observed, bytes);
        assert!(io.pool.owned.iter().all(|&owned| !owned));
    }
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        submit(io.ring(), 0);
        let completion = io.ring().completion().next();
        if let Some(c) = completion {
            assert_eq!(c.user_data(), RECV | 1);
            assert_eq!(c.result(), 0);
            assert!(!cqueue::more(c.flags()));
            if let Some(id) = io.pool.claim(c.result(), c.flags()) {
                io.pool.release(id);
                io.pool.publish();
            }
            break;
        }
        assert!(Instant::now() < end, "deferred EOF was stranded");
    }
    assert!(io.ring().completion().is_empty());
}
