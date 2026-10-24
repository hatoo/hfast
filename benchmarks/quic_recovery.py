"""Untimed HTTP/3 recovery oracle; aioquic is pinned in interop-requirements.txt."""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import random
import ssl

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset

BODY = b"Hello, World!"
DIRECTIONS = ("client", "server")
SCENARIOS = (
    "clean", "client-initial-loss", "server-initial-loss", "client-loss",
    "server-loss", "bidirectional-loss", "reorder", "duplicate",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Ledger:
    """Keep completed streams too: late events must not silently disappear."""

    def __init__(self):
        self.streams = {}

    def register(self, stream, method):
        require(stream not in self.streams, f"duplicate request {stream}")
        self.streams[stream] = dict(method=method, headers=[], body=bytearray(), ends=0)

    def receive(self, event):
        stream = event.stream_id
        require(stream in self.streams, f"unknown response stream {stream}")
        row = self.streams[stream]
        require(row["ends"] == 0, f"duplicate/late response event {stream}")
        if isinstance(event, HeadersReceived):
            require(not row["headers"], f"duplicate response headers {stream}")
            status = [v for k, v in event.headers if k == b":status"]
            require(status == [b"200"], f"wrong/duplicate status {stream}: {status!r}")
            lengths = [v for k, v in event.headers if k == b"content-length"]
            require(not lengths or lengths == [str(len(BODY)).encode()],
                    f"wrong/duplicate content length {stream}")
            row["headers"] = list(event.headers)
        else:
            require(isinstance(event, DataReceived), "unexpected HTTP event")
            require(row["headers"], f"body before headers {stream}")
            row["body"].extend(event.data)
            require(BODY.startswith(row["body"]), f"wrong/extra response body {stream}")
        if event.stream_ended:
            require(row["headers"] and row["body"] == BODY,
                    f"truncated response {stream}: {len(row['body'])} bytes")
            row["ends"] += 1

    def missing(self):
        return [stream for stream, row in self.streams.items() if row["ends"] != 1]

    def finish(self, expected):
        require(len(self.streams) == expected,
                f"request count {len(self.streams)} != {expected}")
        require(not self.missing(), f"missing responses: {self.missing()}")
        return [dict(stream=stream, method=row["method"], status=200,
                     body_bytes=len(row["body"]),
                     body_sha256=hashlib.sha256(row["body"]).hexdigest(), ends=row["ends"])
                for stream, row in self.streams.items()]


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.ledger = Ledger()
        self.changed = asyncio.Event()
        self.failure = None
        self.closing = False
        self.transport_closed = asyncio.Event()

    def connection_lost(self, error):
        super().connection_lost(error)
        self.transport_closed.set()

    def quic_event_received(self, event):
        try:
            if isinstance(event, (StreamReset, StopSendingReceived)):
                raise RuntimeError(f"unexpected stream failure: {event}")
            if isinstance(event, ConnectionTerminated) and not self.closing:
                raise RuntimeError(f"premature connection termination: {event}")
            for item in self.http.handle_event(event):
                require(isinstance(item, (HeadersReceived, DataReceived)),
                        f"unexpected HTTP event: {item}")
                self.ledger.receive(item)
        except Exception as error:
            # Callback failures otherwise only reach the event-loop logger.
            self.failure = self.failure or error
        self.changed.set()

    def check(self):
        if self.failure:
            raise self.failure

    async def batch(self, method, count):
        self.check()
        for _ in range(count):
            stream = self._quic.get_next_available_stream_id()
            self.ledger.register(stream, method)
            headers = [(b":method", method.encode()), (b":scheme", b"https"),
                       (b":authority", b"localhost"), (b":path", b"/")]
            post = method == "POST"
            if post:
                headers.append((b"content-length", b"9"))
            self.http.send_headers(stream, headers, end_stream=not post)
            if post:
                self.http.send_data(stream, b"test body", end_stream=True)
            self.transmit()
        while self.ledger.missing():
            self.changed.clear()
            self.check()
            await self.changed.wait()
        self.check()


@asynccontextmanager
async def connection(port, report):
    """Own the transport so cancellation cannot strand a QUIC close timer."""
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                               initial_rtt=0.02, idle_timeout=5)
    config.verify_mode = ssl.CERT_NONE
    client = Client(QuicConnection(configuration=config))
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: client, local_addr=("127.0.0.1", 0))
    report["client_port"] = transport.get_extra_info("sockname")[1]
    try:
        client.connect(("127.0.0.1", port))
        await client.wait_connected()
        yield client
    finally:
        report["registered"] = len(client.ledger.streams)
        report["missing"] = client.ledger.missing()
        if client.failure:
            report["client_error"] = str(client.failure)
        client.closing = True
        # aioquic shields these futures. An enclosing deadline cancels their
        # callers, so retire the abandoned waiters before close sets exceptions.
        waiters = [client._connected_waiter, *client._ping_waiters.values()]
        client._connected_waiter = None
        client._ping_waiters.clear()
        for waiter in waiters:
            if waiter is not None and not waiter.done():
                waiter.cancel()
        try:
            client.close()
            await asyncio.wait_for(client.wait_closed(), 0.5)
            report["closed"] = True
        except TimeoutError:
            report["forced_transport_close"] = True
        finally:
            # These two handles are pinned aioquic1.3 internals. No encryption,
            # packet parsing, recovery or HTTP processing is replaced.
            for handle in (client._timer, client._transmit_task):
                if handle is not None:
                    handle.cancel()
            transport.close()
            await asyncio.wait_for(client.transport_closed.wait(), 1)


def schedule(name, phase, direction, index):
    if phase == "handshake":
        return "drop" if name == f"{direction}-initial-loss" and index == 1 else "pass"
    if phase not in ("GET", "POST"):
        return "pass"
    if (name == f"{direction}-loss" or name == "bidirectional-loss") and index <= 2:
        return "drop"
    if name == "reorder" and index == 1:
        return "hold"
    if name == "duplicate" and index == 1:
        return "duplicate"
    return "pass"


class Relay(asyncio.DatagramProtocol):
    """Per-direction ordinals are independent of opposite-direction callbacks.

    Named schedules act on visible Initial packets, or on short-header datagrams
    after a completed-handshake/request-batch milestone. They do not pretend to
    identify encrypted frames or guarantee identical packetization across runs.
    """

    def __init__(self, target, name, seed=42, loss=0.05, replay=None):
        self.target, self.name = target, name
        self.peer = None
        self.phase = "idle"
        self.indices = {}
        self.held = {}
        self.trace = []
        self.failure = None
        self.rng = {d: random.Random(f"{seed}:{d}") for d in DIRECTIONS}
        self.loss = loss
        self.replay = replay
        self.replayed = set()
        self.closed = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, error):
        if error:
            self.failure = self.failure or error
        self.closed.set()

    def check(self):
        if self.failure:
            raise self.failure

    def arm(self, phase):
        self.check()
        require(not self.held, "unreleased reordered datagram")
        self.phase = phase

    def error_received(self, error):
        self.failure = self.failure or error

    def datagram_received(self, data, source):
        try:
            self.forward(data, source)
        except Exception as error:
            self.failure = self.failure or error

    def forward(self, data, source):
        require(data, "empty UDP datagram")
        require(len(self.trace) < 20000, "trace exceeded bounded datagram budget")
        direction = "server" if source == self.target else "client"
        if direction == "client":
            require(self.peer in (None, source), "unexpected second client")
            self.peer = source
        destination = self.peer if direction == "server" else self.target
        require(destination is not None, "server datagram without a client")
        kind = "initial" if data[0] & 0xF0 == 0xC0 else (
            "short" if not data[0] & 0x80 else "long")
        eligible = (self.phase == "handshake" and kind == "initial" or
                    self.phase in ("GET", "POST", "explore") and kind == "short")
        action, index = "pass", None
        if eligible:
            key = (self.phase, direction)
            index = self.indices.get(key, 0) + 1
            self.indices[key] = index
            coordinate = (*key, index)
            if self.replay is not None:
                require(coordinate in self.replay, f"replay has extra datagram {coordinate}")
                row = self.replay[coordinate]
                require((kind, len(data)) == (row["kind"], row["bytes"]),
                        f"replay packetization diverged at {coordinate}")
                self.replayed.add(coordinate)
                action = row["action"]
            elif self.name == "seeded":
                action = "drop" if self.rng[direction].random() < self.loss else "pass"
            else:
                action = schedule(self.name, self.phase, direction, index)
        row = dict(event=len(self.trace), phase=self.phase, direction=direction,
                   index=index, kind=kind, bytes=len(data),
                   sha256=hashlib.sha256(data).hexdigest(), action=action, deliveries=[])
        self.trace.append(row)
        if action == "drop":
            return
        if action == "hold":
            require(direction not in self.held, "multiple held datagrams")
            self.held[direction] = (data, destination, row["event"])
            return
        self.transport.sendto(data, destination)
        row["deliveries"].append(row["event"])
        if action == "duplicate":
            self.transport.sendto(data, destination)
            row["deliveries"].append(row["event"])
        if direction in self.held:
            held, address, event = self.held.pop(direction)
            self.transport.sendto(held, address)
            row["deliveries"].append(event)

    def finish(self):
        self.check()
        require(not self.held, "reorder had no overtaking datagram")
        if self.replay is not None:
            require(self.replayed == self.replay.keys(), "replay omitted datagrams")
        counts = {}
        for phase in ("handshake", "GET", "POST", "explore"):
            for direction in DIRECTIONS:
                for action in ("drop", "hold", "duplicate"):
                    count = sum(r["phase"] == phase and r["direction"] == direction
                                and r["action"] == action for r in self.trace)
                    if count:
                        counts[f"{phase}/{direction}/{action}"] = count
                    if self.name not in ("seeded", "replay"):
                        expected = sum(schedule(self.name, phase, direction, i) == action
                                       for i in range(1, 4))
                        require(count == expected,
                                f"impairment missing: {phase}/{direction}/{action} "
                                f"{count} != {expected}")
        if self.name == "seeded" and self.loss:
            require(all(any(r["direction"] == d and r["action"] == "drop"
                            for r in self.trace) for d in DIRECTIONS),
                    "seeded loss was not exercised in both directions")
        return counts


def replay_plan(trace):
    result = {}
    for row in trace:
        if row["index"] is not None:
            key = (row["phase"], row["direction"], row["index"])
            require(key not in result, "duplicate replay coordinate")
            require(row["action"] in ("pass", "drop", "hold", "duplicate"),
                    "unknown replay action")
            result[key] = row
    require(result, "empty replay trace")
    return result
