"""Pure-calc of libmetasec_ml session_init / session_lookup / session_set.

Native offsets (libmetasec_ml.so):
  session_init     SO+0x2CBA1C
  session_finalize SO+0x2CBA88  (ret-only no-op)
  session_lookup   SO+0x2CBAD0  → *(session + 0x6070 + slot*8)
  session_set      SO+0x2CBADC  → *(session + 0x6070 + slot*8) = value

This is the *stack session object* used by F18 outer (0x2BA620), NOT the full
MSSDK cold-bootstrap that fills F19 workspace_table. See mssdk_init.py.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

SESSION_MAGIC = 0x020007060C0C0803
SESSION_MAGIC_LE = struct.pack("<Q", SESSION_MAGIC)  # 03 08 0c 0c 06 07 00 02
SESSION_SLOT_BASE = 0x6070
SESSION_SLOT_ZERO_SIZE = 0x381
SESSION_AUX_PTR_OFF = 0x6030
SESSION_MIN_SIZE = SESSION_SLOT_BASE + SESSION_SLOT_ZERO_SIZE  # 0x63F1
# F18 outer allocates 0x6410 stack; keep a convenient round size for buffers.
SESSION_BUF_SIZE = 0x6410


@dataclass
class SessionView:
    """Mutable byte buffer mirroring a native session object."""

    buf: bytearray

    @classmethod
    def create(cls, size: int = SESSION_BUF_SIZE) -> "SessionView":
        if size < SESSION_MIN_SIZE:
            raise ValueError(f"session buffer must be >= {SESSION_MIN_SIZE:#x}")
        view = cls(bytearray(size))
        view.session_init()
        return view

    def session_init(self) -> None:
        """Byte-exact lift of SO+0x2CBA1C."""
        b = self.buf
        # str x8, [x0] with constructed magic
        b[0:8] = SESSION_MAGIC_LE
        # strh w9=0x200, [x0, #8]
        struct.pack_into("<H", b, 8, 0x200)
        # str wzr, [x0, #0xc]
        struct.pack_into("<I", b, 0xC, 0)
        # str xzr, [x19, #0x10]
        struct.pack_into("<Q", b, 0x10, 0)
        # strb w10=1, [x19, #0x20]
        b[0x20] = 1
        # memset(x0+0x6070, 0, 0x381)
        start = SESSION_SLOT_BASE
        end = start + SESSION_SLOT_ZERO_SIZE
        b[start:end] = b"\x00" * SESSION_SLOT_ZERO_SIZE
        # str (x19+0x6030), [x19, #0x6078]  → slot 1 cell
        struct.pack_into("<Q", b, SESSION_SLOT_BASE + 1 * 8, SESSION_AUX_PTR_OFF)

    def lookup(self, slot: int) -> int:
        """SO+0x2CBAD0 — return pointer-sized slot value as int."""
        off = SESSION_SLOT_BASE + slot * 8
        return struct.unpack_from("<Q", self.buf, off)[0]

    def set(self, slot: int, value: int) -> None:
        """SO+0x2CBADC."""
        off = SESSION_SLOT_BASE + slot * 8
        struct.pack_into("<Q", self.buf, off, value & 0xFFFFFFFFFFFFFFFF)

    def lookup_bytes(self, slot: int) -> bytes:
        return struct.pack("<Q", self.lookup(slot))

    def snapshot_header(self, n: int = 0x28) -> bytes:
        return bytes(self.buf[:n])

    def slot_table_hex(self, n_slots: int = 16) -> str:
        raw = bytes(self.buf[SESSION_SLOT_BASE : SESSION_SLOT_BASE + n_slots * 8])
        return raw.hex()


def session_init_bytes(size: int = SESSION_BUF_SIZE) -> bytes:
    """Return a freshly initialized session buffer."""
    return bytes(SessionView.create(size).buf)


def verify_session_init_layout(buf: bytes) -> List[str]:
    """Return list of layout violations (empty == pass)."""
    errs: List[str] = []
    if len(buf) < SESSION_MIN_SIZE:
        return [f"buffer too small: {len(buf):#x}"]
    magic = struct.unpack_from("<Q", buf, 0)[0]
    if magic != SESSION_MAGIC:
        errs.append(f"magic mismatch: {magic:#x} != {SESSION_MAGIC:#x}")
    if struct.unpack_from("<H", buf, 8)[0] != 0x200:
        errs.append("u16@+8 != 0x200")
    if struct.unpack_from("<I", buf, 0xC)[0] != 0:
        errs.append("u32@+0xc != 0")
    if struct.unpack_from("<Q", buf, 0x10)[0] != 0:
        errs.append("u64@+0x10 != 0")
    if buf[0x20] != 1:
        errs.append("u8@+0x20 != 1")
    # slot region zero except slot1 pointer
    region = buf[SESSION_SLOT_BASE : SESSION_SLOT_BASE + SESSION_SLOT_ZERO_SIZE]
    expected = bytearray(SESSION_SLOT_ZERO_SIZE)
    struct.pack_into("<Q", expected, 1 * 8, SESSION_AUX_PTR_OFF)
    if bytes(region) != bytes(expected):
        errs.append("slot region / slot1 aux pointer mismatch")
    return errs
