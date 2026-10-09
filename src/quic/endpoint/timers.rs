use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Instant;

/// One entry per peer, including peers with no recovery timer (idle expiry).
/// Postponement leaves the earlier check in place, avoiding tree work on each
/// receive. When that check expires the endpoint consults the current state.
#[derive(Default)]
pub(super) struct Timers {
    entries: BTreeSet<(Instant, SocketAddr)>,
}

impl Timers {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn schedule(
        &mut self,
        addr: SocketAddr,
        scheduled: &mut Option<Instant>,
        next: Instant,
    ) {
        if scheduled.is_some_and(|old| old <= next) {
            return;
        }
        self.remove(addr, scheduled);
        self.entries.insert((next, addr));
        *scheduled = Some(next);
    }

    pub(super) fn remove(&mut self, addr: SocketAddr, scheduled: &mut Option<Instant>) {
        if let Some(old) = scheduled.take() {
            self.entries.remove(&(old, addr));
        }
    }

    pub(super) fn drain_due(&mut self, now: Instant, due: &mut Vec<SocketAddr>) {
        while self.entries.first().is_some_and(|&(at, _)| at <= now) {
            due.push(self.entries.pop_first().unwrap().1);
        }
    }
}

#[cfg(test)]
#[path = "timer_tests.rs"]
mod tests;
