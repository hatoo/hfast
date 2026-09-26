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
| HTTP/3   | 1,948,323 rps · 6.05 us/req | 3,359,834 rps · 0.88 us/req | 6.9x cheaper |

The HTTP/1.1 figure is within 6% of [faf](https://github.com/errantmind/faf),
which is the fastest HTTP/1.1 implementation on the TechEmpower plaintext
board and needs a nightly compiler; this needs stable. The HTTP/3 figure is
at 16 requests in flight per connection; at 64 it is 0.32us, and four threads
answer 9.7 million requests a second - which is the load generator's ceiling,
not this one's.

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

## HTTP/3

The QUIC is ours. quinn's cost 1.53us of server CPU a request against the
0.32us this does, and none of it was configuration: what a request cost there
was hashing streams into a map and allocating per chunk, which is a fair way
for a general-purpose stack to be built and not one a benchmark target has to
pay. `--quinn` still serves HTTP/3 from quinn, for comparing the two.

rustls does TLS 1.3, the QUIC key schedule and the AEAD, as it does for quinn.
What is ours is the transport: packets, frames, acknowledgement, flow control
and enough loss recovery to get through a path that drops things. Against a
relay dropping 5% each way, 3000 requests all arrive at 3,922 a second, where
quinn manages 3,960.

Nothing in a request is read. A request's stream id is what says which stream
to answer on and the end of the stream is what says to answer at all, so there
is no reassembly and no allocation per request; the answer is a constant. That
is the whole of the difference.

Received frames borrow the decrypted packet directly. Packet assembly and ACK
range buffers are reused across packets, so these steps do not allocate fresh
storage for every datagram once the buffers have grown to fit the traffic.

The socket loop receives up to 32 datagrams with `recvmmsg` and sends up to 8
with `sendmmsg`, using reusable buffers. It waits only for the first incoming
datagram and sends any partial output batch before receiving again;
there is no wait to fill a batch. A single outgoing datagram uses `send_to`.
The receive batch size follows the number of datagrams available on the previous
receive. With at most one connection, receiving also uses the single-datagram path.
Receive storage is 2 MiB per QUIC worker so large incoming datagrams still fit.

Within each receive batch, all datagrams are processed before building response
packets, once per connection. This combines their ACKs and packs more answers
into each encrypted packet, including when peers interleave their datagrams.
Pending output is flushed before the next receive; no extra batching wait is
introduced. Connection lookup on the established path uses one hash-table lookup
per received datagram. See [the batching measurements](benchmarks/http3-batching.md)
for the before/after comparison and reproduction commands.

What it leaves out, all of which a load generator does without: address
validation and Retry, connection migration (connections are found by the
address they came from), 0-RTT, key update, and congestion control - it sends
what flow control allows, which for 25-byte answers on a benchmark path is
what a controller would allow anyway.

## What a stream limit costs

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
