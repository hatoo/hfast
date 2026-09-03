//! A server whose only job is to not be the bottleneck
//!
//! It answers every request with `Hello, World!` over HTTP/1.1, HTTP/2 or
//! HTTP/3, and exists so that a load generator pointed at it is measuring the
//! load generator. See README.md for what it skips and why that is allowed.

mod h1;
mod h2;
mod h3;
mod quic;
mod sys;
mod tcp;

const DEFAULT_TCP: u16 = 8083;
const DEFAULT_QUIC: u16 = 8443;
/// Concurrent HTTP/3 requests allowed per connection. Generous enough for any
/// load generator's default and cheap enough not to matter; see `h3::config`.
const DEFAULT_MAX_STREAMS: u32 = 1024;

fn main() {
    let mut tcp_port = DEFAULT_TCP;
    let mut quic_port = DEFAULT_QUIC;
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut max_streams = DEFAULT_MAX_STREAMS;
    // Answer HTTP/3 from quinn rather than from the stack in `quic`, which is
    // what this serves it from by default
    let mut use_quinn = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| usage())
        };
        match arg.as_str() {
            "--tcp" => tcp_port = value() as u16,
            "--quic" => quic_port = value() as u16,
            "--threads" => threads = value(),
            "--max-streams" => max_streams = value() as u32,
            "--quinn" => use_quinn = true,
            _ => usage(),
        }
    }
    if tcp_port == 0 && quic_port == 0 {
        usage();
    }

    let mut running = Vec::new();
    if quic_port != 0 {
        eprintln!("hfast: HTTP/3 on udp/{quic_port}, {threads} threads");
        running.push(std::thread::spawn(move || match use_quinn {
            true => h3::serve(quic_port, threads, max_streams),
            false => quic::endpoint::serve(quic_port, threads, max_streams),
        }));
    }
    if tcp_port != 0 {
        eprintln!("hfast: HTTP/1.1 and HTTP/2 on tcp/{tcp_port}, {threads} threads");
        // One listener and one epoll per thread, sharing the port through
        // SO_REUSEPORT, so no two of them ever touch the same memory. They are
        // bound here rather than in the workers so that the order they join the
        // group in is known: the steering program returns a CPU number, and the
        // socket at that index has to be the one whose worker runs there.
        let listeners: Vec<_> = (0..threads).map(|_| sys::tcp_listener(tcp_port)).collect();
        sys::attach_reuseport_cbpf(listeners[0], threads as u32);
        for (cpu, lfd) in listeners.iter().skip(1).enumerate() {
            let lfd = *lfd;
            running.push(std::thread::spawn(move || tcp::worker(lfd, cpu + 1)));
        }
        tcp::worker(listeners[0], 0);
    }
    for t in running {
        let _ = t.join();
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: hfast [--tcp PORT] [--quic PORT] [--threads N] [--max-streams N] [--quinn]\n\
         \n\
         HTTP/1.1 and HTTP/2 (cleartext, told apart by the client's first\n\
         bytes) share the TCP port; HTTP/3 has the UDP one. A port of 0\n\
         turns that side off, which is worth doing when measuring the other:\n\
         each side takes a full set of threads.\n\
         \n\
         --quinn serves HTTP/3 from quinn instead of the QUIC stack here,\n\
         which is slower and is kept for comparing the two.\n\
         \n\
         --max-streams is how many HTTP/3 requests a connection may have in\n\
         flight. Raising it costs server CPU per request, so raise it only to\n\
         what the load generator actually asks for; leaving it below that\n\
         measures this limit instead.\n\
         \n\
         defaults: --tcp {DEFAULT_TCP}  --quic {DEFAULT_QUIC}  --threads <cores>  \
         --max-streams {DEFAULT_MAX_STREAMS}"
    );
    std::process::exit(2)
}
