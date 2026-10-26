#!/usr/bin/env python3
"""Portable smoke-test target for Crashlab (no compiler required).

This is NOT a memory-safety test target. It exists so the CLI, runner, signal
normalization, and report pipeline can be exercised on any host (including
Windows) before a real ASan/GDB target is available.

Modes are selected by the first byte of stdin or ``argv[1]``:

    N  normal exit (0)
    H  simulated access violation (SIGSEGV on POSIX; NTSTATUS 0xC0000005 on Windows)
    U  simulated use-after-free crash
    D  abort (SIGABRT on POSIX; NTSTATUS 0xC0000374 on Windows)
    S  simulated stack overflow
    P  simulated null-pointer crash
    T  sleep for one hour (timeout)
    A  emit a realistic ASan report on stderr and exit 1

The Windows paths use ``os._exit`` with the canonical NTSTATUS value because a
real Python-level null dereference is trapped by ctypes and would not exercise
crashlab's Windows status mapping.
"""

from __future__ import annotations

import os
import signal
import sys
import time

ASAN_REPORT = """\
=================================================================
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x000000401234 bp 0x7ffd00000000 sp 0x7ffd00000000
WRITE of size 1 at 0x602000000011 thread T0
    #0 0x401234 in heap_overflow /home/research/crashlab/examples/target_demo.c:39:12
    #1 0x4014aa in main /home/research/crashlab/examples/target_demo.c:112:13
    #2 0x7f0000000000 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)
    #3 0x4010a9 in _start (/home/research/crashlab/examples/target_asan+0x4010a9)

0x602000000011 is located 1 bytes to the right of 16-byte region [0x602000000000,0x602000000010)
allocated by thread T0 here:
    #0 0x7f0000001111 in malloc (/lib/x86_64-linux-gnu/libasan.so.8+0xc1111)
    #1 0x4011f0 in heap_overflow /home/research/crashlab/examples/target_demo.c:34:24

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/research/crashlab/examples/target_demo.c:39:12 in heap_overflow
==4242==ABORTING
"""

_WINDOWS_CODES = {
    "H": 0xC0000005,
    "U": 0xC0000005,
    "P": 0xC0000005,
    "D": 0xC0000374,
    "S": 0xC00000FD,
}


def _read_payload() -> bytes:
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        with open(sys.argv[1], "rb") as handle:
            return handle.read()
    return sys.stdin.buffer.read()


def _crash(mode: str) -> None:
    if os.name == "nt":
        # Simulated canonical NTSTATUS. -1073741819 == 0xC0000005.
        status = _WINDOWS_CODES[mode]
        os._exit(status - (1 << 32) if status >= 0x80000000 else status)
    os.kill(os.getpid(), signal.SIGABRT if mode == "D" else signal.SIGSEGV)
    os._exit(1)


def main() -> int:
    payload = _read_payload()
    mode = chr(payload[0]) if payload else "N"
    if mode == "N":
        print("normal termination")
        return 0
    if mode == "T":
        print("sleeping", flush=True)
        time.sleep(3600)
        return 0
    if mode == "A":
        sys.stderr.write(ASAN_REPORT)
        sys.stderr.flush()
        return 1
    if mode in _WINDOWS_CODES:
        print(f"simulating crash mode {mode}", flush=True)
        _crash(mode)
    print(f"unknown mode {mode!r}; normal termination")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
