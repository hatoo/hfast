#!/usr/bin/env python3
"""Untimed real-socket cap/failure checks, with independent TLS/HTTP clients.

Compile a narrow libc interposer in a temporary directory. It changes only
SO_RCVBUF for the child server, never the client or host settings. The bind hook
reports the actual kernel capacity, including any replacement socket.
"""
import asyncio
import json
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import subprocess
import sys
import tempfile

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from interoperability import Client

SOURCE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
static int changed;
static int is_mode(const char *s) {
    const char *mode = getenv("HFAST_BUFFER_TEST");
    return mode && !strcmp(mode, s);
}
int getsockopt(int fd, int level, int name, void *value, socklen_t *len) {
    int (*real)(int, int, int, void *, socklen_t *) = dlsym(RTLD_NEXT, "getsockopt");
    if (level == SOL_SOCKET && name == SO_RCVBUF &&
            (is_mode("read-before") || (changed && is_mode("read-after")))) {
        errno = EIO;
        return -1;
    }
    return real(fd, level, name, value, len);
}
int setsockopt(int fd, int level, int name, const void *value, socklen_t len) {
    int (*real)(int, int, int, const void *, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");
    int adjusted;
    if (level == SOL_SOCKET && name == SO_RCVBUF) {
        changed = 1;
        if (is_mode("denied")) { errno = EPERM; return -1; }
        if (is_mode("shrink")) { adjusted = 1024; value = &adjusted; }
        if (is_mode("cap")) {
            int (*get)(int, int, int, void *, socklen_t *) = dlsym(RTLD_NEXT, "getsockopt");
            socklen_t size = sizeof(adjusted);
            if (get(fd, SOL_SOCKET, SO_RCVBUF, &adjusted, &size)) abort();
            value = &adjusted;
        }
    }
    return real(fd, level, name, value, len);
}
int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    int (*real)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
    int (*get)(int, int, int, void *, socklen_t *) = dlsym(RTLD_NEXT, "getsockopt");
    int type = 0, bytes = 0;
    socklen_t size = sizeof(type);
    if (!get(fd, SOL_SOCKET, SO_TYPE, &type, &size) && type == SOCK_DGRAM) {
        size = sizeof(bytes);
        if (get(fd, SOL_SOCKET, SO_RCVBUF, &bytes, &size)) abort();
        fprintf(stderr, "buffer-check capacity=%d\n", bytes);
    }
    return real(fd, addr, len);
}
'''


class ObservedClient(Client):
    handshakes = 0

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            assert event.alpn_protocol == 'h3'
            assert not event.session_resumed and not event.early_data_accepted
            self.handshakes += 1
        super().quic_event_received(event)


async def peer(port):
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    config.verify_mode = ssl.CERT_NONE
    async with connect('127.0.0.1', port, configuration=config,
                       create_protocol=ObservedClient) as client:
        for post in (False, True):
            await asyncio.gather(*(client.request(post) for _ in range(16)))
        await client.ping()
        assert client.handshakes == 1 and not client.pending
    return 32


async def check(binary, library, mode, directory, default, maximum):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    log_path = directory / (mode + '.log')
    flags = [] if mode == 'default' else [
        '--udp-receive-buffer', '0' if mode == 'zero' else '4194304']
    def limit_descriptors():
        # stdin/stdout/stderr and exactly four worker sockets. Replacing the
        # last socket must release its descriptor before creating another.
        resource.setrlimit(resource.RLIMIT_NOFILE, (7, 7))
    with log_path.open('w') as log:
        server = subprocess.Popen([binary, '--threads', '4', '--tcp', '0', '--quic', str(port), *flags],
            env=dict(os.environ, LD_PRELOAD=str(library),
                     HFAST_BUFFER_TEST='shrink' if mode == 'shrink-tight' else mode),
            preexec_fn=limit_descriptors if mode == 'shrink-tight' else None,
            stdout=log, stderr=log)
        try:
            await asyncio.sleep(.2)
            assert server.poll() is None
            descriptors = Path(f'/proc/{server.pid}/fd')
            sockets = [fd for fd in descriptors.iterdir()
                       if os.readlink(fd).startswith('socket:')]
            assert len(sockets) == 4, 'replacement leaked a socket'
            counts = await asyncio.gather(*(peer(port) for _ in range(16)))
            assert counts == [32] * 16
            assert server.poll() is None
        finally:
            server.terminate()
            server.wait(timeout=5)
    text = log_path.read_text()
    capacities = [int(s) for s in re.findall(r'buffer-check capacity=(\d+)', text)]
    if mode in ('default', 'zero') or default >= 8 * 1024 * 1024:
        expected = default
    elif mode == 'normal':
        expected = max(default, min(8 * 1024 * 1024, 2 * maximum))
    elif mode == 'cap':
        expected = max(default, min(2 * default, 2 * maximum))
    else:
        expected = default
    assert capacities == [expected] * 4, (mode, capacities, expected, text)
    if default < 8 * 1024 * 1024:
        messages = {'cap': 'capped' if expected > default else 'did not grow',
                    'shrink': 'did not grow', 'denied': 'could not enlarge',
                    'shrink-tight': 'did not grow',
                    'read-before': 'could not read', 'read-after': 'did not grow'}
        if mode in messages:
            assert messages[mode] in text, (mode, text)
    print(json.dumps(dict(mode=mode, workers=4, capacities=capacities,
                          handshakes=16, responses=sum(counts), closed=16)), flush=True)


def main():
    assert 'LD_PRELOAD' not in os.environ
    binary = str(Path(sys.argv[1]).resolve())
    for value in ([], ['-1'], ['4194305'], ['invalid'], ['18446744073709551616']):
        result = subprocess.run([binary, '--udp-receive-buffer', *value],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 2 and 'usage: hfast' in result.stderr, result
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        default = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    maximum = int(Path('/proc/sys/net/core/rmem_max').read_text())
    with tempfile.TemporaryDirectory(prefix='hfast-udp-buffer-') as temp:
        directory = Path(temp)
        source, library = directory / 'inject.c', directory / 'inject.so'
        source.write_text(SOURCE)
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(source), '-ldl', '-o', str(library)], check=True)
        for mode in ('default', 'zero', 'normal', 'cap', 'shrink', 'shrink-tight',
                     'denied', 'read-before', 'read-after'):
            asyncio.run(asyncio.wait_for(check(binary, library, mode, directory, default, maximum), 30))


if __name__ == '__main__':
    main()
