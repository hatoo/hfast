use super::*;

// Dispatch-only fixtures use real Connection timers without inventing packets
// or retransmission obligations. Authenticated tests below use actual flights.
pub(in crate::quic) fn seed_deadline(conn: &mut Connection, deadline: Option<Instant>) {
    for st in &mut conn.spaces {
        st.oldest_sent = None;
    }
    conn.spaces[Space::Initial as usize].oldest_sent =
        deadline.map(|t| t - conn.pto() * (1 << conn.pto_count.min(6)));
}

pub(in crate::quic) fn backoff(conn: &mut Connection, count: u32) {
    conn.pto_count = count;
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::quic) struct State {
    pub pto_count: u32,
    pub previous_keys: bool,
    pub next_packet: u64,
    pub finished: u64,
}

pub(in crate::quic) fn state(conn: &Connection) -> State {
    State {
        pto_count: conn.pto_count,
        previous_keys: conn
            .key_updates
            .as_ref()
            .is_some_and(|keys| keys.previous.is_some()),
        next_packet: conn.spaces[Space::Data as usize].next_pn,
        finished: conn.finished,
    }
}
