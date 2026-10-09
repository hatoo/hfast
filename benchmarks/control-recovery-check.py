#!/usr/bin/env python3
"""Independent aioquic regression for lost SETTINGS and HANDSHAKE_DONE packets."""

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


def control_frames(plain):
    """Inspect hfast's frame types without delivering or acknowledging them."""
    buf = Buffer(data=plain)
    found = []
    while not buf.eof():
        ty = buf.pull_uint_var()
        if ty in (0, 1):  # PADDING, PING
            continue
        if ty in (2, 3):  # ACK, ACK_ECN
            buf.pull_uint_var()  # largest
            buf.pull_uint_var()  # delay
            count = buf.pull_uint_var()
            buf.pull_uint_var()  # first range
            for _ in range(2 * count + (3 if ty == 3 else 0)):
                buf.pull_uint_var()
        elif ty == 6:  # CRYPTO
            buf.pull_uint_var()
            buf.pull_bytes(buf.pull_uint_var())
        elif 8 <= ty <= 15:  # STREAM
            stream = buf.pull_uint_var()
            offset = buf.pull_uint_var() if ty & 4 else 0
            size = buf.pull_uint_var() if ty & 2 else buf.capacity - buf.tell()
            data = buf.pull_bytes(size)
            if stream == 3:
                assert offset == 0 and data == b"\x00\x04\x00" and not ty & 1
                found.append("settings")
        elif ty in (0x10, 0x12, 0x13):  # MAX_DATA, MAX_STREAMS
            buf.pull_uint_var()
        elif ty in (0x1A, 0x1B):
            buf.pull_bytes(8)
        elif ty == 0x1E:
            found.append("handshake_done")
        else:
            raise AssertionError(f"unexpected server frame {ty:#x}")
    return found


class RecoveryClient(Client):
    def __init__(self, *args, lost_frame, **kwargs):
        super().__init__(*args, **kwargs)
        self.lost_frame = lost_frame
        self.dropped = []
        self.injected = False

    def datagram_received(self, data, addr):
        if not self.injected:
            # Pinned aioquic 1.3 internals. Drop an entire packet after genuine
            # decryption but BEFORE frame processing, PN accounting or ACKs.
            # Other packets coalesced in the datagram are delivered normally.
            crypto = self._quic._cryptos[tls.Epoch.ONE_RTT]
            decrypt = crypto.decrypt_packet

            def lossy_decrypt(*args, **kwargs):
                result = decrypt(*args, **kwargs)
                _, plain, pn = result
                if len(self.dropped) < 2:
                    frames = control_frames(plain)
                    if self.lost_frame in frames:
                        self.dropped.append(pn)
                        self._quic._quic_logger.log_event(
                            category="testing",
                            event="packet_dropped",
                            data={"packet_number": pn, "control_frames": frames},
                        )
                        print("Injected loss:", pn, frames, flush=True)
                        raise CryptoError("injected control-packet loss")
                return result

            crypto.decrypt_packet = lossy_decrypt
            self.injected = True
        super().datagram_received(data, addr)


async def check(port, lost_frame, busy, logger):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"], quic_logger=logger)
    conf.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1",
        port,
        configuration=conf,
        create_protocol=lambda *a, **kw: RecoveryClient(*a, lost_frame=lost_frame, **kw),
    ) as client:
        # Busy mode permits later response ACKs to leave gaps at the lost
        # control packets; idle mode requires recovery with no requests yet.
        if busy:
            await asyncio.gather(*(client.request() for _ in range(64)))
        for _ in range(600):
            if client.http.received_settings is not None and client._quic._handshake_confirmed:
                break
            await asyncio.sleep(0.01)
        assert client.http.received_settings == {}, "SETTINGS did not recover"
        assert client._quic._handshake_confirmed, "HANDSHAKE_DONE did not recover"
        assert len(client.dropped) == 2, "two independent packet losses were not exercised"
        # The dropped packet numbers must remain gaps in the client's ACKs.
        space = client._quic._spaces[tls.Epoch.ONE_RTT]
        assert all(pn not in space.ack_queue for pn in client.dropped)
        if not busy:
            await asyncio.gather(*(client.request() for _ in range(64)))
        await asyncio.gather(*(client.request(True) for _ in range(64)))
        assert not client.pending
        print(
            f"PASS: {lost_frame}, {'busy' if busy else 'idle'}, lost packets "
            f"{client.dropped}; SETTINGS, handshake confirmation, 64 GET + 64 POST",
            flush=True,
        )


async def main(args):
    logger = QuicLogger()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server_args = [args.binary, "--threads", "1", "--tcp", "0", "--quic", str(port)]
    server = subprocess.Popen(
        server_args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=deny_uring if args.epoll else None,
    )
    try:
        await asyncio.sleep(0.2)
        assert server.poll() is None, "server exited during startup"
        frames = [args.frame] if args.frame else ["settings", "handshake_done"]
        for frame in frames:
            for busy in (False, True):
                await asyncio.wait_for(check(port, frame, busy, logger), 10)
    finally:
        server.terminate()
        server.wait(timeout=5)
        if args.qlog:
            with open(args.qlog, "x") as out:
                json.dump(logger.to_dict(), out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--frame", choices=["settings", "handshake_done"])
    parser.add_argument("--epoll", action="store_true")
    parser.add_argument("--qlog")
    asyncio.run(main(parser.parse_args()))
