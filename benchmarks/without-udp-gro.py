#!/usr/bin/env python3
"""Run an independent fixture with the server's UDP_GRO option denied.

HFAST_GRO_BINARY=/absolute/path/to/hfast python benchmarks/interoperability.py \
    benchmarks/without-udp-gro.py

This executable wrapper also works as the binary argument of the recovery,
credit and key-update fixtures. It changes no other socket option or syscall.
Requires libseccomp.so.2, as supplied by the Linux CI image.
"""

import ctypes
import errno
import os
import socket
import sys


def main():
    binary = os.environ["HFAST_GRO_BINARY"]
    assert os.path.isabs(binary) and os.access(binary, os.X_OK), binary
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    class Compare(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.c_int, ctypes.c_uint,
                                         ctypes.POINTER(Compare)]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    assert context
    try:
        syscall = lib.seccomp_syscall_resolve_name(b"setsockopt")
        assert syscall >= 0
        # SCMP_CMP_EQ, level=IPPROTO_UDP, option=UDP_GRO (Linux UAPI 104).
        comparisons = (Compare * 2)(Compare(1, 4, socket.IPPROTO_UDP, 0),
                                   Compare(2, 4, 104, 0))
        assert lib.seccomp_rule_add_array(context, 0x50000 | errno.ENOPROTOOPT,
                                         syscall, 2, comparisons) == 0
        assert lib.seccomp_load(context) == 0
    finally:
        lib.seccomp_release(context)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.setsockopt(socket.IPPROTO_UDP, 104, 1)
        except OSError as error:
            assert error.errno == errno.ENOPROTOOPT, error
        else:
            raise AssertionError("UDP_GRO denial was not installed")
    if "HFAST_GRO_PRELOAD" in os.environ:
        # Used only by the untimed audit: preload after this Python process so
        # its probe socket is excluded from server traffic/counter initialization.
        os.environ["LD_PRELOAD"] = os.environ.pop("HFAST_GRO_PRELOAD")
    os.execv(binary, [binary, *sys.argv[1:]])


if __name__ == "__main__":
    main()
