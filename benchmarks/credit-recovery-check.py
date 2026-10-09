#!/usr/bin/env python3
"""Independent aioquic regression for lost MAX_STREAMS credit at a small window."""

import argparse
import asyncio
import json
import socket
import ssl
import subprocess

from aioquic import tls
from aioquic.asyncio import connect
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.crypto import CryptoError
from aioquic.quic.logger import QuicLogger

from interoperability import Client, deny_uring


def stream_limits(plain):
    """Inspect authenticated frames before aioquic records or ACKs the packet."""
    buf = Buffer(data=plain)
    limits = []
    while not buf.eof():
        ty = buf.pull_uint_var()
        if ty in (0, 1, 0x1E):  # PADDING, PING, HANDSHAKE_DONE
            continue
        if ty in (2, 3):  # ACK, ACK_ECN
            buf.pull_uint_var()
            buf.pull_uint_var()
            count = buf.pull_uint_var()
            buf.pull_uint_var()
            for _ in range(2 * count + (3 if ty == 3 else 0)):
                buf.pull_uint_var()
        elif ty == 6:  # CRYPTO
            buf.pull_uint_var()
            buf.pull_bytes(buf.pull_uint_var())
        elif 8 <= ty <= 15:  # STREAM
            buf.pull_uint_var()
            if ty & 4:
                buf.pull_uint_var()
            size = buf.pull_uint_var() if ty & 2 else buf.capacity - buf.tell()
            buf.pull_bytes(size)
        elif ty in (0x10, 0x12, 0x13):  # MAX_DATA, MAX_STREAMS
            limit = buf.pull_uint_var()
            if ty == 0x12:
                limits.append(limit)
        elif ty in (0x1A, 0x1B):
            buf.pull_bytes(8)
        else:
            raise AssertionError(f"unexpected server frame {ty:#x}")
    return limits


class CreditClient(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dropped = []
        self.injected = False
        self.blocked_seen = False

    def datagram_received(self, data, addr):
        if not self.injected:
            # Pinned aioquic 1.3 internals: reject whole protected packets
            # before frame processing, received-PN accounting, or ACKs. Other
            # packets coalesced in the datagram remain independently usable.
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def lossy_decrypt(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                limits = stream_limits(plain)
                if limits and len(self.dropped) < 2:
                    self.dropped.append(pn)
                    self.blocked_seen |= bool(self._quic._streams_blocked_bidi)
                    self._quic._quic_logger.log_event(
                        category="testing",
                        event="credit_dropped",
                        data={"packet_number": pn, "limits": limits},
                    )
                    print("Injected credit loss:", pn, limits, flush=True)
                    raise CryptoError("injected credit-packet loss")
                return result

            crypto.decrypt_packet = lossy_decrypt
            self.injected = True
        super().datagram_received(data, addr)


async def check(port, window, logger):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=conf, create_protocol=CreditClient
    ) as client:
        assert client._quic._remote_max_streams_bidi == window
        try:
            # Exhaust the initial stream allowance, with further requests
            # queued in aioquic's actual flow control. A four-stream window can
            # generate at most two original updates before blocking; recovery
            # needs a retransmission even when every response is acknowledged.
            await asyncio.gather(*(client.request() for _ in range(32)))
            await asyncio.gather(*(client.request(True) for _ in range(32)))
            assert client.blocked_seen, "the client never exhausted its credit"
            assert len(client.dropped) == 2
            space = client._quic._spaces[tls.Epoch.ONE_RTT]
            assert all(pn not in space.ack_queue for pn in client.dropped)
            assert not client.pending
            assert client.http.received_settings == {}
            assert client._quic._handshake_confirmed
            assert client._quic._remote_max_streams_bidi >= 64
            print(
                f"PASS: window {window}, lost packets {client.dropped}, "
                "32 GET + 32 POST with exact status/body beyond initial credit",
                flush=True,
            )
        finally:
            print(
                "Final credit:", client._quic._remote_max_streams_bidi,
                "pending:", sorted(client.pending),
                "blocked:", len(client._quic._streams_blocked_bidi),
                flush=True,
            )


async def main(args):
    logger = QuicLogger()
    try:
        for window in ([args.window] if args.window else [4, 1]):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            server = subprocess.Popen(
                [args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port),
                 "--max-streams", str(window)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=deny_uring if args.epoll else None,
            )
            try:
                await asyncio.sleep(0.2)
                assert server.poll() is None, "server exited during startup"
                await asyncio.wait_for(check(port, window, logger), 10)
            finally:
                server.terminate()
                server.wait(timeout=5)
    finally:
        if args.qlog:
            with open(args.qlog, "x") as out:
                json.dump(logger.to_dict(), out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--window", type=int, choices=[1, 4])
    parser.add_argument("--epoll", action="store_true")
    parser.add_argument("--qlog")
    asyncio.run(main(parser.parse_args()))
