"""Untimed, independent receive-ACK history oracle (pinned aioquic 1.3.0)."""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import ssl

from aioquic import tls
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.logger import QuicLogger

from quic_recovery import Client, require

OFFSETS = {
    "ascending-oldest": [*range(100, 132, 4), 132, 0, 101, 101, 103, 105,
                         106, 107, 108, 112, 136, 140],
    "oldest-boundary": [*range(100, 132, 4), 99, 101, 102, 103, 0, 104,
                        105, 106, 107, 132, 136],
    "oldest-bridge": [100, 102, 106, 110, 114, 118, 122, 126, 101, 99,
                      127, 128, 130, 134, 102, 0],
    "reverse-disjoint": [128, 124, 120, 116, 112, 108, 104, 100, 96, 92,
                         99, 101, 102, 103, 132],
}
CASES = (*OFFSETS, "pn-wrap-1", "pn-wrap-2", "pn-wrap-3", "pn-wrap-4")


def canonical(ranges):
    """Normalize aioquic's inclusive ranges without silently merging bad ACKs."""
    require(0 < len(ranges) <= 8, "ACK range count outside 1..8")
    rows = []
    for row in ranges:
        require(len(row) == 2 and all(type(n) is int for n in row), "invalid ACK range")
        lo, hi = row
        require(0 <= lo <= hi < 1 << 62, "invalid ACK bounds")
        rows.append((lo, hi))
    rows.sort(reverse=True)
    require(all(older[1] + 1 < newer[0] for newer, older in zip(rows, rows[1:])),
            "overlapping, duplicate or adjacent ACK ranges")
    return tuple(rows)


def retained(history, pn):
    """A small set-and-sort model, independent of hfast's insertion algorithm."""
    require(0 <= pn < 1 << 62, "invalid packet number")
    require(sum(hi - lo + 1 for lo, hi in history) <= 4096, "model history too large")
    numbers = {n for lo, hi in history for n in range(lo, hi + 1)}
    numbers.add(pn)
    runs = []
    for n in sorted(numbers):
        if runs and runs[-1][1] + 1 == n:
            runs[-1] = (runs[-1][0], n)
        else:
            runs.append((n, n))
    return tuple(reversed(runs[-8:]))


def plan(scenario, next_pn):
    """Use wide anchors before testing truncated PNs across each wrap boundary."""
    if scenario in OFFSETS:
        base = next_pn + 1024
        return [(base + n, 4) for n in OFFSETS[scenario]]
    require(scenario in CASES, "unknown receive-ACK scenario")
    width = int(scenario[-1])
    boundary = 1 << (8 * width)
    require(next_pn < 200, "unexpected handshake packet-number budget")
    # A four-byte PN can only jump half its window from the previous largest.
    anchors = [(boundary // 2 - 16, 4)] if width == 4 else []
    offsets = [*range(-24, 8, 4), 8, -28, -23, -23, -21, -19, -18, -17, 12]
    return anchors + [(boundary + n, 4 if i == 0 else width)
                      for i, n in enumerate(offsets)]


def protected(key, cid, pn, width, token, expected):
    require(width in (1, 2, 3, 4) and len(token) == 8, "invalid probe layout")
    plain = b"\x01\x1a" + token  # PING and PATH_CHALLENGE
    header = bytes([0x40 | (width - 1)]) + cid
    header += (pn % (1 << (8 * width))).to_bytes(width, "big")
    wire = key.encrypt_packet(header, plain, pn)
    _, decoded, observed, _ = key.decrypt_packet(wire, 1 + len(cid), expected)
    require((decoded, observed) == (plain, pn), "probe plaintext/PN reconstruction mismatch")
    return wire


def packet_events(quic, start):
    return [e["data"] for e in list(quic._quic_logger._events)[start:]
            if e["name"] == "transport:packet_received"
            and e["data"]["header"]["packet_type"] == "1RTT"]


class AckLedger:
    def __init__(self, floor, report):
        self.floor = floor
        self.history = ()
        self.last_server_pn = -1
        self.saturated = False
        self.report = report
        report["probes"] = []

    def observe(self, pn, token, packets, row):
        matches = []
        for packet in packets:
            responses = [f["data"] for f in packet["frames"]
                         if f["frame_type"] == "path_response"]
            require(all(data == token.hex() for data in responses), "unexpected probe response")
            if responses:
                require(len(responses) == 1, "duplicate probe response")
                matches.append(packet)
        if not matches:
            return False
        require(len(matches) == 1, "probe answered more than once")
        packet = matches[0]
        server_pn = int(packet["header"]["packet_number"])
        require(server_pn > self.last_server_pn, "stale server packet used as receive fence")
        acks = [f for f in packet["frames"] if f["frame_type"] == "ack"]
        require(len(acks) == 1, "probe response must carry exactly one owed ACK")
        observed = canonical(acks[0]["acked_ranges"])
        expected = retained(self.history, pn)
        # Before eight separated probes evict the handshake history, compare
        # the probe suffix only. No unknown PN at/above the reserved floor fits.
        visible = tuple((max(lo, self.floor), hi) for lo, hi in observed if hi >= self.floor)
        row.update(server_pn=server_pn, observed=observed, expected=expected)
        require(visible == expected, f"ACK history mismatch for {pn}: {visible} != {expected}")
        if self.saturated or len(expected) == 8:
            require(observed == expected, "old handshake range survived full probe history")
        # Only a matching authenticated response and exact ACK commits state.
        self.history = expected
        self.last_server_pn = server_pn
        self.saturated |= len(expected) == 8
        row["checked"] = True
        return True


class WireClient(Client):
    """Capture callback errors and pause automatic sends during the probe ledger."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.paused = False

    def fail(self, error):
        self.failure = self.failure or error
        self.changed.set()

    def datagram_received(self, data, addr):
        try:
            super().datagram_received(data, addr)
        except Exception as error:
            self.fail(error)
        self.changed.set()

    def transmit(self):
        self._transmit_task = None
        if not self.paused:
            try:
                super().transmit()
            except Exception as error:
                self.fail(error)

    def _handle_timer(self):
        if not self.paused:
            try:
                super()._handle_timer()
            except Exception as error:
                self.fail(error)

    def error_received(self, error):
        self.fail(error)

    def connection_lost(self, error):
        if error:
            self.fail(error)
        super().connection_lost(error)

    def pause(self):
        self.paused = True
        for handle in (self._timer, self._transmit_task):
            if handle is not None:
                handle.cancel()
        self._timer = self._timer_at = self._transmit_task = None


@asynccontextmanager
async def connection(port, report):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], initial_rtt=0.02,
                               idle_timeout=5, quic_logger=QuicLogger())
    config.verify_mode = ssl.CERT_NONE
    client = WireClient(QuicConnection(configuration=config))
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
        client.closing = True
        client.paused = False
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
            for handle in (client._timer, client._transmit_task):
                if handle is not None:
                    handle.cancel()
            transport.close()
            await asyncio.wait_for(client.transport_closed.wait(), 1)
            report["transport_closed"] = True
            if client.failure:
                report["client_error"] = str(client.failure)


async def await_probe(client, ledger, pn, token, start, row):
    while True:
        client.changed.clear()
        client.check()
        row["received_packets"] = packet_events(client._quic, start)
        if ledger.observe(pn, token, row["received_packets"], row):
            return
        await client.changed.wait()


async def exercise(port, scenario, report):
    async with connection(port, report) as client:
        await client.batch("GET", 1)
        await client.ping()
        client.check()
        q = client._quic
        require(q._handshake_confirmed, "handshake not confirmed")
        report["first_fence"] = True
        probes = plan(scenario, q._packet_number)
        client.pause()
        start_phase = len(q._quic_logger._events)
        # These authenticated test PNs are deliberately outside aioquic's
        # normal sender. Reserve them so ACK validation and resumption are safe.
        expected_pn = q._packet_number
        q._packet_number = max(pn for pn, _ in probes) + 1
        ledger = AckLedger(min(pn for pn, _ in probes), report)
        cache = {}
        try:
            for index, (pn, width) in enumerate(probes):
                replay = pn in cache
                if not replay:
                    token = index.to_bytes(8, "big")
                    wire = protected(q._cryptos[tls.Epoch.ONE_RTT].send, q._peer_cid.cid,
                                     pn, width, token, expected_pn)
                    cache[pn] = (wire, token, width)
                wire, token, original_width = cache[pn]
                require(original_width == width, "replay changed PN encoding")
                expected_pn = max(expected_pn, pn + 1)
                row = dict(index=index, pn=pn, pn_width=width, replay=replay,
                           token=token.hex(), bytes=len(wire),
                           sha256=hashlib.sha256(wire).hexdigest(), checked=False)
                report["probes"].append(row)
                # Register the actual challenge with aioquic's independent
                # PATH_RESPONSE validator, including an exact wire replay.
                require(not q._local_challenges, "previous challenge is still outstanding")
                q._local_challenges[token] = q._network_paths[0]
                start = len(q._quic_logger._events)
                client._transport.sendto(wire, q._network_paths[0].addr)
                await asyncio.wait_for(await_probe(client, ledger, pn, token, start, row), 2)
                require(not q._local_challenges, "probe response did not validate its token")
            require(not any(e["name"] == "transport:packet_sent"
                            for e in list(q._quic_logger._events)[start_phase:]),
                    "automatic client send changed the probe history")
            report["unique_packets"] = len(cache)
            report["checked_acks"] = len(report["probes"])
        finally:
            client.paused = False
        await client.batch("POST", 1)
        await client.ping()
        client.check()
        report["final_fence"] = True
        report["responses"] = client.ledger.finish(2)
    client.check()
