use super::*;
use std::collections::BTreeMap;
use std::time::Duration;

fn addr(i: usize) -> SocketAddr {
    ([127, 0, 0, 1], 10000 + i as u16).into()
}

#[test]
fn earlier_deadlines_replace_and_later_deadlines_keep_one_entry() {
    let now = Instant::now();
    let mut timers = Timers::default();
    let mut scheduled = None;
    timers.schedule(addr(0), &mut scheduled, now);
    for i in 0..10000 {
        timers.schedule(addr(0), &mut scheduled, now + Duration::from_nanos(i));
        assert_eq!(timers.entries.len(), 1);
        assert_eq!(scheduled, Some(now));
    }
    let earlier = now - Duration::from_secs(1);
    timers.schedule(addr(0), &mut scheduled, earlier);
    assert_eq!(timers.entries.first(), Some(&(earlier, addr(0))));
    let mut due = Vec::new();
    timers.drain_due(earlier - Duration::from_nanos(1), &mut due);
    assert!(due.is_empty());
    timers.drain_due(earlier, &mut due);
    assert_eq!(due, [addr(0)]);
    assert!(timers.entries.is_empty());
}

#[test]
fn cancellation_and_same_address_reuse_do_not_leave_old_timers() {
    let now = Instant::now();
    let mut timers = Timers::default();
    let mut scheduled = None;
    for i in 0..10000 {
        timers.schedule(addr(0), &mut scheduled, now + Duration::from_nanos(i));
        timers.remove(addr(0), &mut scheduled);
        assert!(scheduled.is_none());
        assert!(timers.entries.is_empty());
    }
    timers.schedule(addr(0), &mut scheduled, now + Duration::from_secs(1));
    let mut due = Vec::new();
    timers.drain_due(now, &mut due);
    assert!(due.is_empty());
    timers.drain_due(now + Duration::from_secs(1), &mut due);
    assert_eq!(due, [addr(0)]);
}

#[test]
fn tied_deadlines_and_rearming_form_separate_due_batches() {
    let now = Instant::now();
    let mut timers = Timers::default();
    let mut scheduled = vec![None; 16384];
    for (i, slot) in scheduled.iter_mut().enumerate() {
        timers.schedule(addr(i), slot, now);
    }
    assert_eq!(timers.entries.len(), scheduled.len());
    let mut due = Vec::new();
    timers.drain_due(now, &mut due);
    assert_eq!(due.len(), scheduled.len());
    assert!(timers.entries.is_empty());
    for &address in &due {
        let slot = &mut scheduled[(address.port() - 10000) as usize];
        *slot = None;
        // A callback can arm a past deadline. It belongs to the next tick.
        timers.schedule(address, slot, now - Duration::from_nanos(1));
    }
    assert_eq!(due.len(), scheduled.len());
    assert_eq!(timers.entries.len(), scheduled.len());
    due.clear();
    timers.drain_due(now, &mut due);
    assert_eq!(due.len(), scheduled.len());
}

#[derive(Clone, Copy)]
struct State {
    last: Instant,
    recovery: Option<Instant>,
    scheduled: Option<Instant>,
}

fn next(state: State) -> Instant {
    let idle = state.last + super::super::IDLE_TIMEOUT + Duration::from_nanos(1);
    state.recovery.map_or(idle, |t| t.min(idle))
}

fn expired(state: State, now: Instant) -> bool {
    now.duration_since(state.last) > super::super::IDLE_TIMEOUT
}

#[test]
fn simulated_time_matches_full_scan_for_updates_expiry_and_reuse() {
    for seed in 1..=16u64 {
        let mut rng = seed;
        let mut now = Instant::now();
        let mut states = BTreeMap::<SocketAddr, State>::new();
        let mut timers = Timers::default();
        let mut due = Vec::new();
        for step in 0..8192 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            now += Duration::from_millis(rng % 40);
            let address = addr((rng >> 8) as usize % 128);
            match (rng >> 16) % 8 {
                0 => {
                    if let Some(mut s) = states.remove(&address) {
                        timers.remove(address, &mut s.scheduled);
                    }
                }
                1..=5 => {
                    let s = states.entry(address).or_insert(State {
                        last: now,
                        recovery: None,
                        scheduled: None,
                    });
                    // Last-receive refreshes, unchanged/earlier/later recovery,
                    // cancellation, and already-due deadlines are independent.
                    if rng & 1 != 0 {
                        s.last = now;
                    }
                    s.recovery = match (rng >> 24) % 4 {
                        0 => None,
                        1 => Some(now),
                        2 => Some(now + Duration::from_millis((rng >> 32) % 2000)),
                        _ => s.recovery,
                    };
                    let deadline = next(*s);
                    timers.schedule(address, &mut s.scheduled, deadline);
                }
                _ => {
                    let expected: BTreeMap<_, _> = states
                        .iter()
                        .filter_map(|(&a, &s)| {
                            if expired(s, now) {
                                Some((a, true))
                            } else if s.recovery.is_some_and(|t| t <= now) {
                                Some((a, false))
                            } else {
                                None
                            }
                        })
                        .collect();
                    timers.drain_due(now, &mut due);
                    let mut actual = BTreeMap::new();
                    for &a in &due {
                        let s = states.get_mut(&a).unwrap();
                        s.scheduled = None;
                        if expired(*s, now) {
                            actual.insert(a, true);
                            states.remove(&a);
                        } else {
                            if s.recovery.is_some_and(|t| t <= now) {
                                actual.insert(a, false);
                                // Include rearming at the current instant: the
                                // reference handles each peer once per tick.
                                s.recovery = (rng & 2 != 0)
                                    .then_some(now + Duration::from_millis((rng >> 40) % 2));
                            }
                            let deadline = next(*s);
                            timers.schedule(a, &mut s.scheduled, deadline);
                        }
                    }
                    assert_eq!(actual, expected, "seed {seed}, step {step}");
                    due.clear();
                }
            }
            assert_eq!(timers.entries.len(), states.len());
            for (&a, &s) in &states {
                let at = s.scheduled.unwrap();
                assert!(at <= next(s));
                assert!(timers.entries.contains(&(at, a)));
            }
        }
    }
}
