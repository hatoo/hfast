// Test-only code appended to a generated h2.rs by build-h2-drain-peer.py.
// One held body is kept OUTSIDE the sorted pending queue, with its own credit.
// No logging, timestamps or per-request counters remain after the gate finishes.
const DRAIN_REQUESTS: u32 = 97;
const DRAIN_REQUEST_BOUND: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainPhase {
    Holding,
    Settings,
    Bodies,
    Ping,
    Done,
}

struct DrainGate {
    phase: DrainPhase,
    held: Option<Pending>,
    requests: u32,
    settings_sent: u8,
    settings_acked: u8,
    nonce: [u8; 8],
}

impl DrainGate {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NONCE: AtomicU64 = AtomicU64::new(0xc451_0000_0000_0000);
        Self {
            phase: DrainPhase::Holding,
            held: None,
            requests: 0,
            settings_sent: 1, // Conn::new already queued the initial SETTINGS.
            settings_acked: 0,
            nonce: NONCE.fetch_add(1, Ordering::Relaxed).to_be_bytes(),
        }
    }
}

fn drain_limit(out: &mut Vec<u8>, limit: u32) {
    out.extend_from_slice(&[0, 0, 6, SETTINGS, 0, 0, 0, 0, 0, 0, 3]);
    out.extend_from_slice(&limit.to_be_bytes());
}

impl Conn {
    fn respond(&mut self, out: &mut Vec<u8>, stream: u32) {
        if let Some(gate) = &mut self.gate
            && gate.phase != DrainPhase::Done
        {
            // New streams following the zero-limit ACK violate the fixture's
            // causal barrier. Fail visibly instead of claiming a complete drain.
            if matches!(gate.phase, DrainPhase::Bodies | DrainPhase::Ping)
                || gate.requests == DRAIN_REQUEST_BOUND
            {
                self.fail(out, 0, PROTOCOL_ERROR);
                return;
            }
            gate.requests += 1;
            if gate.requests == 1 {
                let block = if self.header_table == HeaderTable::ZeroPending {
                    self.header_table = HeaderTable::Zero;
                    ZERO_TABLE_HEADER_BLOCK
                } else {
                    HEADER_BLOCK
                };
                headers(out, stream, block);
                gate.held = Some(Pending {
                    stream,
                    window: self.initial_window as i32,
                    sent: 0,
                });
                return;
            }
        }
        self.respond_ordinary(out, stream);
        if let Some(gate) = &mut self.gate
            && gate.phase == DrainPhase::Holding
            && gate.requests == DRAIN_REQUESTS
        {
            drain_limit(out, 0);
            gate.settings_sent += 1;
            gate.phase = DrainPhase::Settings;
        }
    }

    fn drain_settings_ack(&mut self) -> bool {
        let Some(gate) = &mut self.gate else {
            return true;
        };
        if gate.settings_acked == gate.settings_sent {
            return false;
        }
        gate.settings_acked += 1;
        if gate.settings_acked == 2 && gate.phase == DrainPhase::Settings {
            // All pre-pause client HEADERS precede this ACK in the TCP stream.
            gate.phase = DrainPhase::Bodies;
        }
        true
    }

    fn drain_cancel(&mut self, stream: u32) {
        if let Some(gate) = &mut self.gate
            && gate.held.as_ref().is_some_and(|held| held.stream == stream)
        {
            gate.held = None;
        }
    }

    fn drain_credit(&mut self, out: &mut Vec<u8>, stream: u32, increment: u32) -> bool {
        let Some(gate) = &mut self.gate else {
            return false;
        };
        let Some(held) = &mut gate.held else {
            return false;
        };
        if held.stream != stream {
            return false;
        }
        match held.window.checked_add(increment as i32) {
            Some(window) if increment != 0 => held.window = window,
            _ => {
                gate.held = None;
                reset(
                    out,
                    stream,
                    if increment == 0 {
                        PROTOCOL_ERROR
                    } else {
                        FLOW_CONTROL_ERROR
                    },
                );
            }
        }
        true
    }

    fn drain_advance(&mut self, out: &mut Vec<u8>) {
        let Some(gate) = &mut self.gate else {
            return;
        };
        if gate.phase != DrainPhase::Bodies {
            return;
        }
        if let Some(held) = &mut gate.held
            && send_body(out, &mut self.send_window, held)
        {
            gate.held = None;
        }
        if gate.held.is_none() && self.pending.is_empty() {
            // The client cannot ACK this PING before parsing all preceding
            // final DATA frames while MAX_CONCURRENT_STREAMS is still zero.
            out.extend_from_slice(&[0, 0, 8, PING, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&gate.nonce);
            gate.phase = DrainPhase::Ping;
        }
    }

    fn drain_ping(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        if let Some(gate) = &mut self.gate
            && gate.phase == DrainPhase::Ping
            && payload == gate.nonce
        {
            drain_limit(out, MAX_WINDOW);
            gate.settings_sent += 1;
            gate.phase = DrainPhase::Done;
        }
    }
}
