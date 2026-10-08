#!/usr/bin/env python3
"""Correctness only: independent HTTP implementations, no rate measurements."""

import asyncio, ssl, subprocess, socket, time, sys
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
import h2.connection, h2.config, h2.events

BODY = b"Hello, World!"


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.http = H3Connection(self._quic)
        self.pending = {}

    def quic_event_received(self, event):
        for ev in self.http.handle_event(event):
            if (
                isinstance(ev, (HeadersReceived, DataReceived))
                and ev.stream_id in self.pending
            ):
                fut, headers, body = self.pending[ev.stream_id]
                if isinstance(ev, HeadersReceived):
                    headers.extend(ev.headers)
                else:
                    body.extend(ev.data)
                if ev.stream_ended:
                    fut.set_result((headers, bytes(body)))

    async def request(self, post=False):
        stream = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        self.pending[stream] = (fut, [], bytearray())
        headers = [
            (b":method", b"POST" if post else b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
        ]
        if post:
            headers.append((b"content-length", b"9"))
        self.http.send_headers(stream, headers, end_stream=not post)
        if post:
            self.http.send_data(stream, b"test body", end_stream=True)
        self.transmit()
        headers, body = await asyncio.wait_for(fut, 10)
        assert (b":status", b"200") in headers and body == BODY, (headers, body)
        del self.pending[stream]


async def h3(port=18443):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf, create_protocol=Client
    ) as client:
        for post in [False, True]:
            await asyncio.gather(*(client.request(post) for _ in range(64)))


def tcp():
    for proto in ["h1", "h2"]:
        with socket.create_connection(("127.0.0.1", 18083), timeout=5) as s:
            if proto == "h1":
                # Fragmented POST body followed by pipelined GET.
                s.sendall(
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\ntest"
                )
                time.sleep(0.01)
                s.sendall(b" bodyGET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                out = b""
                while out.count(BODY) < 2:
                    out += s.recv(4096)
                assert out.count(b"HTTP/1.1 200 OK") == 2 and out.count(BODY) == 2
            else:
                c = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=True)
                )
                c.initiate_connection()
                ids = []
                for _ in range(64):
                    stream = c.get_next_available_stream_id()
                    ids.append(stream)
                    c.send_headers(
                        stream,
                        [
                            (b":method", b"GET"),
                            (b":scheme", b"http"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                        ],
                        end_stream=True,
                    )
                s.sendall(c.data_to_send())
                bodies = {i: bytearray() for i in ids}
                ended = set()
                status = set()
                while len(ended) < len(ids):
                    for e in c.receive_data(s.recv(65536)):
                        if isinstance(e, h2.events.ResponseReceived):
                            assert (b":status", b"200") in e.headers
                            status.add(e.stream_id)
                        if isinstance(e, h2.events.DataReceived):
                            bodies[e.stream_id].extend(e.data)
                            c.acknowledge_received_data(
                                e.flow_controlled_length, e.stream_id
                            )
                        if isinstance(e, h2.events.StreamEnded):
                            ended.add(e.stream_id)
                    data = c.data_to_send()
                    if data:
                        s.sendall(data)
                assert status == ended and all(
                    bytes(b) == BODY for b in bodies.values()
                )


def backpressure():
    with socket.create_connection(("127.0.0.1", 18083), timeout=10) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        # Large request crosses the receive chunks; pipelined answers fill the
        # server send queue while the peer deliberately postpones reading.
        payload = b"x" * 70000
        sock.sendall(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 70000\r\n\r\n"
            + payload
        )
        out = b""
        while BODY not in out:
            out += sock.recv(4096)
        assert out.count(BODY) == 1
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" * 40000)
        time.sleep(0.1)
        out = bytearray()
        while out.count(BODY) < 40000:
            data = sock.recv(65536)
            assert data, "server closed under backpressure"
            out.extend(data)
        assert out.count(b"HTTP/1.1 200 OK") == 40000


def deny_uring():
    # Force the fallback without adding a server tuning flag. This filter only
    # applies to the child server, so independent clients keep their normal I/O.
    import ctypes

    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7FFF0000)
    assert ctx
    syscall = lib.seccomp_syscall_resolve_name(b"io_uring_setup")
    assert lib.seccomp_rule_add(ctx, 0x50001, syscall, 0) == 0
    assert lib.seccomp_load(ctx) == 0
    lib.seccomp_release(ctx)


def main():
    server = subprocess.Popen(
        [sys.argv[1], "--threads", "1", "--tcp", "18083", "--quic", "18443"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=deny_uring if "--epoll" in sys.argv[2:] else None,
    )
    try:
        time.sleep(0.2)
        tcp()
        backpressure()
        asyncio.run(h3())
        print(
            "HTTP/1.1 fragmented/pipelined POST+GET; hyper-h2 64 streams; aioquic 64 GET + 64 POST: PASS"
        )
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
