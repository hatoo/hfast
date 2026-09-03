# hfast

An HTTP server that does as little as an HTTP server can and still be one. It
answers every request with `Hello, World!` over HTTP/1.1, HTTP/2 or HTTP/3, and
exists so that a load generator pointed at it is measuring the load generator.

    cargo build --release
    ./target/release/hfast                  # h1+h2 on tcp/8083, h3 on udp/8443
    ./target/release/hfast --quic 0         # TCP only
    ./target/release/hfast --tcp 0          # HTTP/3 only

HTTP/1.1 and HTTP/2 share the TCP port: HTTP/2 over cleartext opens with a
preface that no HTTP/1.1 request line can begin with, so which one a connection
is speaking is decided by its first bytes and nothing has to be negotiated.
Each side takes a full set of threads, so turn off the one not being measured.

## Measured against nginx

Serving the same 13-byte body, on 16 cores of a Ryzen 9 3950X, driven by
[shb](https://github.com/hatoo/shb). `us/req` is server CPU per request, which
is the number that decides whether the server or the client is the bottleneck.

| | nginx | hfast | |
|---|---|---|---|
| HTTP/1.1 | 1,116,909 rps · 16.54 us/req | 1,697,440 rps · 8.95 us/req | 1.85x cheaper |
| HTTP/2   | 1,408,387 rps · 18.56 us/req | 32,863,903 rps · 0.40 us/req | 46x cheaper |
| HTTP/3   | 2,045,749 rps · 5.69 us/req | 2,973,451 rps · 3.07 us/req | 1.85x cheaper |

The HTTP/1.1 figure is within 6% of [faf](https://github.com/errantmind/faf),
which is the fastest HTTP/1.1 implementation on the TechEmpower plaintext
board and needs a nightly compiler; this needs stable. The HTTP/3 figure is
what it is at 16 requests in flight per connection; at 64 it is 1.37 us.

## What it skips, and why that is allowed

**HPACK and QPACK, in both directions.** A request's stream id is in the clear
in the HTTP/2 frame header and in the QUIC stream, and nothing else about a
request changes the answer, so a decoder that never reads a header block needs
no dynamic table to keep in sync. The response header block is a constant: a
client that sends `SETTINGS_HEADER_TABLE_SIZE = 0`, or offers a zero-capacity
QPACK table, forbids the server's encoder from indexing anyway, so a
static-table blob is all it would be allowed to send.

**Flow-control accounting.** Windows are advertised large enough that a 13-byte
response can never be blocked by one.

**The `Date` header.** Every other server here sends it because TechEmpower
requires it. Nothing pointed at this reads it, and the point of this server is
to be a floor.

What it does not skip: the HTTP/2 connection preface and SETTINGS exchange and
its ACK, PING/PONG, GOAWAY, the HTTP/3 control stream and its SETTINGS, correct
framing in every direction, HTTP/1.1 request pipelining, and request bodies -
a `Content-Length` is read so that a body is never mistaken for the request
behind it.

## How it is built

**One thread per core, and nothing shared between them.** Each TCP worker has
its own `SO_REUSEPORT` listener and its own epoll instance; each HTTP/3 worker
has its own `SO_REUSEPORT` socket, its own QUIC endpoint and its own
single-threaded runtime. Sharing one QUIC endpoint between threads instead put
every connection through the same lock and cost two thirds of the throughput.

**Connections steered to the core that will read them.** The TCP listeners
carry a `SO_ATTACH_REUSEPORT_CBPF` program that returns the CPU the packet
arrived on, and the workers are pinned, so the softirq that delivers a packet
and the thread that reads it are the same core. Without it, the kernel picks a
listener by hashing addresses and the two land apart: same packets, same
syscalls, half again as much system time.

The UDP sockets deliberately do **not** carry that program. On TCP a reuseport
program only picks the listener a new connection is accepted on, and everything
after that goes to the accepted socket; on UDP it picks the socket for every
datagram, so the packets of one QUIC connection scatter across endpoints that
know nothing about it. Steering HTTP/3 by CPU dropped it from 3M requests a
second to under 400k.

**One write per wakeup**, however many responses accumulated in it. That is
where HTTP/2's advantage over HTTP/1.1 comes from: at 32 streams a connection
it puts sixteen requests in a TCP segment, and the kernel charges per segment.

**No allocation per request.** Reads are parsed where they land, and only a
trailing partial request is copied anywhere.

## HTTP/3, and what a stream limit costs

`--max-streams` is how many requests a connection may have in flight, and it
is the single setting that decides what HTTP/3 costs here. Raising it is not
free: measured at 8 threads, a request costs 1.27us of server CPU at 128 and
2.14us at 16384, and the first version of this server set it to 65536 on the
theory that a limit nobody reaches cannot hurt. It more than doubled the cost
of every request.

It cannot simply be set low, either. A limit below what the load generator
asks for does not slow the run down honestly - it caps the concurrency, so the
run measures the limit rather than either end's speed. The default of 1024 is
above any load generator's default and cheap enough not to matter; set it to
what is actually being asked for when that is higher.

The transport is [quinn](https://github.com/quinn-rs/quinn)'s. A QUIC stack is
packet protection, loss recovery, congestion control and flow control before it
is any use at all, and none of that is worth hand-rolling for something whose
whole job is to answer quickly. What is ours is the HTTP/3 layer above it,
which for a server that sends the same response every time is a constant, and
the threading around it, which is most of what made it fast.

The certificate is self-signed and generated at startup. There is nothing here
worth authenticating, and a load generator pointed at it is not checking.
