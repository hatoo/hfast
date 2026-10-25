"""Independent, untimed coalesced receive oracle (pinned aioquic 1.3.0).

Only outgoing packet layout is changed. TLS, packet protection, incoming QUIC,
HTTP/3 decoding, response accounting and ACK fences remain in aioquic.
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
import hashlib
import ssl

from aioquic import tls
from aioquic.buffer import Buffer, size_uint_var
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoContext, CryptoError
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicPacketType as Type, pull_quic_header

from quic_recovery import Client, require

EPOCH = {Type.INITIAL: tls.Epoch.INITIAL, Type.HANDSHAKE: tls.Epoch.HANDSHAKE,
         Type.ONE_RTT: tls.Epoch.ONE_RTT}
CASES = ("initial-widths", "skipped-forged", "sample-boundaries", "finished",
         "finished-retired", "malformed-header", "malformed-token",
         "malformed-length", "malformed-cid")


def varint(value, width):
    require(width in (1, 2, 4, 8) and 0 <= value < 1 << (width * 8 - 2),
            "invalid varint value/width")
    return ((width.bit_length() - 1) << (width * 8 - 2) | value).to_bytes(width)


def long_header(kind, dcid, scid, length, *, token=b"", width=2, pn_width=2):
    first = {Type.INITIAL: 0xc0, Type.ZERO_RTT: 0xd0, Type.HANDSHAKE: 0xe0}[kind]
    header = bytes([first | (pn_width - 1)]) + b"\0\0\0\1"
    header += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    if kind == Type.INITIAL:
        header += varint(len(token), size_uint_var(len(token))) + token
    return header + varint(length, width)


@dataclass
class Packet:
    wire: bytes
    kind: Type
    crypto: object = None
    pn: int = 0
    plain: bytes = b""
    mode: str = "authenticated"


def protected(kind, crypto, dcid, scid, pn, *, plain=b"\x01", token=b"",
              width=2, pn_width=2):
    # RFC 9001 5.4.2: the sample starts four bytes after the PN offset.
    plain += bytes(max(0, 4 - pn_width - len(plain)))
    header = long_header(kind, dcid, scid, pn_width + len(plain) + 16,
                         token=token, width=width, pn_width=pn_width)
    header += (pn % (1 << (pn_width * 8))).to_bytes(pn_width)
    return Packet(crypto.encrypt_packet(header, plain, pn), kind, crypto, pn, plain)


def opaque(kind, dcid, scid, length, *, mode="unavailable"):
    return Packet(long_header(kind, dcid, scid, length) + bytes([0xaa]) * length,
                  kind, mode=mode)


def split(data, cid_length):
    """Read packet extents with aioquic, including its external Initial padding."""
    buf = Buffer(data=data)
    result = []
    while not buf.eof():
        start = buf.tell()
        if data[start] == 0:
            require(not any(data[start:]), "nonzero data after datagram padding")
            break
        header = pull_quic_header(buf, host_cid_length=cid_length)
        end = start + header.packet_length
        require(end > start, "non-advancing packet extent")
        result.append((start, buf.tell() - start, end, header))
        buf.seek(end)
    return result


def layout(packets, cid_length):
    """Reject any disagreement between intended packets and independent parsing."""
    data = b"".join(p.wire for p in packets)
    require(0 < len(data) <= 65507, "invalid UDP payload size")
    parsed = split(data, cid_length)
    require(len(parsed) == len(packets), "packet count/layout mismatch")
    rows = []
    for spec, (start, offset, end, header) in zip(packets, parsed):
        require(data[start:end] == spec.wire and header.packet_type == spec.kind,
                "packet boundary/type mismatch")
        sample = len(spec.wire) - offset >= 20
        if spec.mode == "short-sample":
            require(not sample, "truncated sample unexpectedly fits")
        elif spec.mode in ("authenticated", "forged"):
            require(sample, "authenticated packet lacks protection sample")
            try:
                _, plain, pn, _ = spec.crypto.decrypt_packet(spec.wire, offset, spec.pn)
            except CryptoError:
                require(spec.mode == "forged", "valid packet failed authentication")
            else:
                require(spec.mode == "authenticated", "forgery authenticated")
                require((plain, pn) == (spec.plain, spec.pn), "plaintext/PN mismatch")
        else:
            require(spec.mode == "unavailable", "unknown packet expectation")
        rows.append(dict(start=start, end=end, pn_offset=offset, kind=spec.kind.name,
                         mode=spec.mode, pn=spec.pn if spec.crypto else None,
                         token_bytes=len(header.token), sample_fits=sample))
    require(rows[-1]["end"] == len(data), "unexpected trailing padding")
    return data, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), packets=rows)


class Plan:
    def __init__(self, quic, scenario, report):
        self.quic, self.scenario, self.report = quic, scenario, report
        self.original = quic.datagrams_to_send
        self.keys = {}
        self.done = False
        self.initial = False
        self.failure = None
        self.acked = set()
        self.forbidden = set()
        self.sent = 0
        self.report["layouts"] = []
        quic.datagrams_to_send = self.outgoing

    def snapshot_keys(self):
        for kind, epoch in EPOCH.items():
            context = self.quic._cryptos[epoch].send
            if context.is_valid() and kind not in self.keys:
                clone = CryptoContext()
                clone.setup(cipher_suite=context.cipher_suite, secret=context.secret,
                            version=context.version)
                self.keys[kind] = clone

    def decode(self, data):
        packets = []
        for start, offset, end, header in split(data, len(self.quic._peer_cid.cid)):
            key = self.keys[header.packet_type]
            wire = data[start:end]
            _, plain, pn, _ = key.decrypt_packet(wire, offset, self.quic._packet_number)
            packets.append(Packet(wire, header.packet_type, key, pn, plain))
        return packets

    def inject(self, packets):
        data, row = layout(packets, len(self.quic._peer_cid.cid))
        require(len(packets) > 1, "coalescing was not exercised")
        require(len(data) >= 1200, "Initial datagram below 1200 bytes")
        self.report["layouts"].append(row)
        self.done = True
        return data

    def prefix_initial(self, packets):
        q = self.quic
        dcid, scid = q._peer_cid.cid, q.host_cid
        key = self.keys[Type.INITIAL]
        prefix = []
        if self.scenario == "initial-widths":
            for size in (0, 1, 63, 64, 255):
                for width in (1, 2, 4, 8):
                    for pn_width in (1, 2, 3, 4):
                        pn = len(prefix) + 1
                        prefix.append(protected(Type.INITIAL, key, dcid, scid, pn,
                                                token=b"T" * size, width=width,
                                                pn_width=pn_width))
                        self.acked.add(pn)
        elif self.scenario == "skipped-forged":
            first = protected(Type.INITIAL, key, dcid, scid, 1)
            forged = protected(Type.INITIAL, key, dcid, scid, 2, token=b"forged")
            forged = replace(forged, wire=forged.wire[:-1] + bytes([forged.wire[-1] ^ 1]),
                             mode="forged")
            prefix = [first, opaque(Type.ZERO_RTT, dcid, scid, 20),
                      opaque(Type.HANDSHAKE, dcid, scid, 20), forged,
                      protected(Type.INITIAL, key, dcid, scid, 3, width=8)]
            self.acked.update((1, 3))
            self.forbidden.add(2)
        elif self.scenario == "sample-boundaries":
            for size in range(20):
                prefix.extend([opaque(Type.INITIAL, dcid, scid, size, mode="short-sample"),
                               protected(Type.INITIAL, key, dcid, scid, 21 + size)])
                self.acked.add(21 + size)
        else:
            raise RuntimeError("unknown Initial scenario")
        require(len(packets) == 1 and packets[0].kind == Type.INITIAL,
                "expected one ClientHello packet")
        hello = packets[0]
        # Keep the generated CRYPTO/PN, but put all padding inside encryption.
        hello = protected(Type.INITIAL, key, dcid, scid, hello.pn,
                          plain=hello.plain + bytes(max(0, 1200 - len(hello.plain))),
                          width=4, pn_width=4)
        self.acked.add(hello.pn)
        return self.inject(prefix + [hello])

    def finished(self, packets):
        q = self.quic
        generated_initial = None
        if packets and packets[0].kind == Type.INITIAL:
            generated_initial, *packets = packets
        require([p.kind for p in packets] == [Type.HANDSHAKE, Type.ONE_RTT],
                f"expected Finished and first short packet, got {[p.kind.name for p in packets]}")
        # aioquic's authenticated outgoing qlog identifies the CRYPTO and request
        # frames; the independent decryption above verifies their exact bytes.
        sent = [e["data"] for e in q._quic_logger._events
                if e["name"] == "transport:packet_sent"]
        for packet, frame_type in zip(packets, ("crypto", "stream")):
            events = [e for e in sent if e["header"]["packet_number"] == packet.pn]
            require(len(events) == 1, "missing/duplicate generated packet trace")
            frames = events[0]["frames"]
            require(any(f["frame_type"] == frame_type and
                        (f.get("length", 0) > 0 if frame_type == "crypto" else
                         f.get("stream_id") == 0 and f.get("fin")) for f in frames),
                    "Finished or complete request not in coalesced packet")
        dcid, scid = q._peer_cid.cid, q.host_cid
        plain = generated_initial.plain if generated_initial else b"\x01"
        initial = protected(Type.INITIAL, self.keys[Type.INITIAL], dcid, scid,
                            generated_initial.pn if generated_initial else 90,
                            plain=plain + bytes(max(0, 1200 - len(plain))),
                            token=b"offset", width=8)
        hs = packets[0]
        hs = protected(Type.HANDSHAKE, hs.crypto, dcid, scid, hs.pn,
                       plain=hs.plain, width=4, pn_width=3)
        result = [initial, hs]
        if self.scenario == "finished-retired":
            # Finished discards both long-header key spaces before the short
            # packet. Valid packets in those retired spaces must be skipped.
            result.extend([protected(Type.INITIAL, self.keys[Type.INITIAL], dcid, scid, 91),
                           protected(Type.HANDSHAKE, hs.crypto, dcid, scid, 92),
                           opaque(Type.ZERO_RTT, dcid, scid, 20)])
        return self.inject(result + [packets[1]])

    def outgoing(self, now):
        try:
            self.snapshot_keys()
            if not self.initial:
                # Reserve unique packet numbers for injected Initial probes.
                self.quic._packet_number = 96
                self.initial = True
            datagrams = self.original(now)
            output = []
            for data, addr in datagrams:
                if not self.done and not self.scenario.startswith("malformed-"):
                    packets = self.decode(data)
                    if self.scenario.startswith("finished"):
                        if self.quic._handshake_complete:
                            data = self.finished(packets)
                    else:
                        data = self.prefix_initial(packets)
                output.append((data, addr))
            self.sent += len(output)
            return output
        except Exception as error:
            # transmit() also runs from asyncio callbacks: do not lose failures
            # to the event-loop logger and accidentally report a passing case.
            self.failure = self.failure or error
            return []

    def check(self):
        if self.failure:
            raise self.failure

    def finish(self):
        self.check()
        require(self.done and len(self.report["layouts"]) == 1, "injection did not occur once")
        observed = set()
        for event in self.quic._quic_logger._events:
            if event["name"] != "transport:packet_received":
                continue
            packet = event["data"]
            if packet["header"]["packet_type"] == "initial":
                for frame in packet["frames"]:
                    if frame["frame_type"] == "ack":
                        for first, last in frame["acked_ranges"]:
                            require(0 <= last - first <= 4096, "unbounded ACK range")
                            observed.update(range(first, last + 1))
        require(self.acked <= observed, f"unacknowledged Initial probes: {self.acked - observed}")
        require(not self.forbidden & observed, "forged Initial was acknowledged")
        sent = [e["data"] for e in self.quic._quic_logger._events
                if e["name"] == "transport:packet_sent"]
        requests = [f for p in sent for f in p["frames"]
                    if f["frame_type"] == "stream" and f["stream_id"] == 0]
        finished = [f for p in sent if p["header"]["packet_type"] == "handshake"
                    for f in p["frames"] if f["frame_type"] == "crypto"]
        require(len(requests) == 1 and requests[0]["fin"], "first request was retransmitted")
        require(len(finished) == 1, "Finished was retransmitted or fragmented")
        self.report.update(initial_acks=sorted(observed), required_acks=sorted(self.acked),
                           forbidden_acks=sorted(self.forbidden), sent_datagrams=self.sent,
                           first_request_transmissions=len(requests),
                           finished_transmissions=len(finished))


@asynccontextmanager
async def connection(port, scenario, report, cid_length=8):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], initial_rtt=0.02,
                               idle_timeout=5, connection_id_length=cid_length,
                               quic_logger=QuicLogger())
    config.verify_mode = ssl.CERT_NONE
    quic = QuicConnection(configuration=config)
    client = Client(quic)
    plan = Plan(quic, scenario, report)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: client, local_addr=("127.0.0.1", 0))
    try:
        # Queue the first request before the handshake so it shares Finished's
        # datagram. Its response must not be recovered by a later transmission.
        client.ledger.register(0, "GET")
        client.http.send_headers(0, [(b":method", b"GET"), (b":scheme", b"https"),
                                    (b":authority", b"localhost"), (b":path", b"/")],
                                 end_stream=True)
        client.connect(("127.0.0.1", port))
        await client.wait_connected()
        yield client, plan
    finally:
        report["registered"] = len(client.ledger.streams)
        report["missing"] = client.ledger.missing()
        report["sent_datagrams"] = plan.sent
        if plan.failure:
            report["layout_error"] = str(plan.failure)
        if client.failure:
            report["client_error"] = str(client.failure)
        client.closing = True
        waiters = [client._connected_waiter, *client._ping_waiters.values()]
        client._connected_waiter = None
        client._ping_waiters.clear()
        for waiter in waiters:
            if waiter is not None and not waiter.done():
                waiter.cancel()
        try:
            if not scenario.startswith("malformed-"):
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


async def responses(client, plan):
    while client.ledger.missing():
        client.changed.clear()
        plan.check()
        client.check()
        await client.changed.wait()
    await client.ping()
    plan.check()
    client.check()


async def exercise(port, scenario, report, cid_length=8):
    async with connection(port, scenario, report, cid_length) as (client, plan):
        await responses(client, plan)
        require(client._quic._handshake_confirmed, "handshake not confirmed")
        report["first_fence"] = True
        if scenario.startswith("malformed-"):
            q = client._quic
            dcid, scid = q._peer_cid.cid, q.host_cid
            prefix = protected(Type.HANDSHAKE, plan.keys[Type.HANDSHAKE], dcid, scid, 93)
            header = long_header(Type.INITIAL, dcid, scid, 20, token=b"T" * 64)
            if scenario == "malformed-header":
                suffix = b"\xe0\0\0\0\1\x08\x01"
            elif scenario == "malformed-token":
                suffix = header[:7 + len(dcid) + len(scid) + 5]
            elif scenario == "malformed-length":
                suffix = long_header(Type.HANDSHAKE, dcid, scid, (1 << 62) - 1, width=8)
            else:
                suffix = b"\xe0\0\0\0\1\x15" + bytes(21) + b"\0\0"
            prefix_wire, prefix_layout = layout([prefix], len(dcid))
            data = prefix_wire + suffix
            try:
                split(data, len(dcid))
            except ValueError:
                pass
            else:
                raise RuntimeError("malformed suffix unexpectedly parsed")
            report["malformed"] = dict(prefix_bytes=len(prefix.wire), suffix_hex=suffix.hex(),
                                       prefix_layout=prefix_layout,
                                       sha256=hashlib.sha256(data).hexdigest())
            client._transport.sendto(data, ("127.0.0.1", port))
            before = plan.sent
            # Baseline endpoint removes this connection without a close frame.
            # Observe its wire consequence, then require a fresh healthy peer.
            try:
                await asyncio.wait_for(client.ping(), 0.35)
            except TimeoutError:
                require(plan.sent > before, "no post-malformation probe sent")
                report["expected_silence"] = True
            else:
                raise RuntimeError("malformed connection still answered a PING")
            plan.check()
            client.check()
            report["responses"] = client.ledger.finish(1)
        else:
            await client.batch("POST", 1)
            await responses(client, plan)
            plan.finish()
            report["final_fence"] = True
            report["responses"] = client.ledger.finish(2)
    client.check()
    plan.check()
