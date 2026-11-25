// Appended only to a generated test peer. Never linked into production hfast.
use std::time::{Duration, Instant};

const PIN_COUNT: usize = 2;
const PIN_HOLD: Duration = Duration::from_millis(1_000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinPhase {
    Armed,
    Holding,
    Settings,
    Bodies,
    Ping,
}

struct PinGate {
    held: [Option<Pending>; PIN_COUNT],
    deadline: Option<Instant>,
    nonce: [u8; 8],
    captured: usize,
    phase: PinPhase,
    unacked: u8,
}

fn pin_nonce() -> [u8; 8] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0xc455_0000_0000_0000);
    NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes()
}

impl PinGate {
    fn new() -> Self {
        Self {
            held: std::array::from_fn(|_| None),
            deadline: None,
            nonce: pin_nonce(),
            captured: 0,
            phase: PinPhase::Armed,
            unacked: 1, // Initial SETTINGS queued by Conn::new.
        }
    }
}

fn pin_limit(out: &mut Vec<u8>, limit: u32) {
    out.extend_from_slice(&[0, 0, 6, SETTINGS, 0, 0, 0, 0, 0, 0, 3]);
    out.extend_from_slice(&limit.to_be_bytes());
}

// Send only the prefix, consuming real connection/stream credit. At least the
// last byte and END_STREAM remain withheld until the timer and pause ACK.
fn pin_prefix(out: &mut Vec<u8>, window: &mut u32, response: &mut Pending) {
    let end = BODY.len() - 1;
    let n = (*window)
        .min(response.window.max(0) as u32)
        .min((end - response.sent as usize) as u32) as u8;
    if n == 0 {
        return;
    }
    let start = response.sent as usize;
    response.sent += n;
    out.extend_from_slice(&[0, 0, n, DATA, 0]);
    out.extend_from_slice(&response.stream.to_be_bytes());
    out.extend_from_slice(&BODY[start..response.sent as usize]);
    *window -= u32::from(n);
    response.window -= i32::from(n);
}

impl Conn {
    fn respond(&mut self, out: &mut Vec<u8>, stream: u32) {
        if let Some(gate) = &mut self.gate {
            if matches!(gate.phase, PinPhase::Bodies | PinPhase::Ping) || self.pending.len() >= 1024
            {
                self.fail(out, 0, PROTOCOL_ERROR);
                return;
            }
            if gate.phase == PinPhase::Armed {
                gate.deadline = Some(Instant::now() + PIN_HOLD);
                gate.phase = PinPhase::Holding;
            }
            if gate.phase == PinPhase::Holding && gate.captured < PIN_COUNT {
                let block = if self.header_table == HeaderTable::ZeroPending {
                    self.header_table = HeaderTable::Zero;
                    ZERO_TABLE_HEADER_BLOCK
                } else {
                    HEADER_BLOCK
                };
                headers(out, stream, block);
                let mut response = Pending {
                    stream,
                    window: self.initial_window as i32,
                    sent: 0,
                };
                pin_prefix(out, &mut self.send_window, &mut response);
                gate.held[gate.captured] = Some(response);
                gate.captured += 1;
                return;
            }
        }
        self.respond_ordinary(out, stream);
    }

    // Called by an independent timer event, including when no socket receives
    // anything. Unit tests supply time explicitly; hot responses read no clock.
    pub(super) fn pin_tick(&mut self, now: Instant, out: &mut Vec<u8>) {
        if let Some(gate) = &mut self.gate
            && gate.phase == PinPhase::Holding
            && gate.deadline.is_some_and(|deadline| now >= deadline)
        {
            pin_limit(out, 0);
            gate.unacked += 1;
            gate.phase = PinPhase::Settings;
            gate.deadline = None;
        }
    }

    fn pin_settings_ack(&mut self) -> bool {
        let Some(gate) = &mut self.gate else {
            return true;
        };
        if gate.unacked == 0 {
            return false;
        }
        gate.unacked -= 1;
        if gate.unacked == 0 && gate.phase == PinPhase::Settings {
            // Pre-pause requests precede this ACK on the incoming TCP stream.
            gate.phase = PinPhase::Bodies;
        }
        true
    }

    fn pin_cancel(&mut self, stream: u32) {
        if let Some(gate) = &mut self.gate {
            for slot in &mut gate.held {
                if slot.as_ref().is_some_and(|r| r.stream == stream) {
                    *slot = None;
                }
            }
        }
    }

    fn pin_credit(&mut self, out: &mut Vec<u8>, stream: u32, increment: u32) -> bool {
        let Some(gate) = &mut self.gate else {
            return false;
        };
        for slot in &mut gate.held {
            let Some(response) = slot else { continue };
            if response.stream != stream {
                continue;
            }
            match response.window.checked_add(increment as i32) {
                Some(window) if increment != 0 => response.window = window,
                _ => {
                    *slot = None;
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
            return true;
        }
        false
    }

    fn pin_advance(&mut self, out: &mut Vec<u8>) {
        let Some(gate) = &mut self.gate else { return };
        match gate.phase {
            PinPhase::Holding | PinPhase::Settings => {
                for response in gate.held.iter_mut().flatten() {
                    pin_prefix(out, &mut self.send_window, response);
                }
            }
            PinPhase::Bodies => {
                for slot in &mut gate.held {
                    if let Some(response) = slot
                        && send_body(out, &mut self.send_window, response)
                    {
                        *slot = None;
                    }
                }
                if gate.held.iter().all(Option::is_none) && self.pending.is_empty() {
                    out.extend_from_slice(&[0, 0, 8, PING, 0, 0, 0, 0, 0]);
                    out.extend_from_slice(&gate.nonce);
                    gate.phase = PinPhase::Ping;
                }
            }
            PinPhase::Armed | PinPhase::Ping => {}
        }
    }

    fn pin_ping(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        if let Some(gate) = &mut self.gate
            && gate.phase == PinPhase::Ping
            && payload == gate.nonce
        {
            pin_limit(out, MAX_WINDOW);
            gate.unacked += 1;
            gate.captured = 0;
            gate.nonce = pin_nonce();
            gate.phase = PinPhase::Armed;
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_pin_test(&mut self) {
        self.gate = Some(PinGate::new());
    }
}
