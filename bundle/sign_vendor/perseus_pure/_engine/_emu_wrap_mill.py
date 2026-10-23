#!/usr/bin/env python3
"""Emulate mill-less WRAP 0x2be114: 19B PT + KEY + IV -> 32B CT via mill bytecode."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from _emu_millless import Mem, i32, pack24, parse_u, sxtw, u64

ROOT = Path(__file__).resolve().parent

# handler PC increment for compounds (from disasm). 0 = use max(extra)+1
COMPOUND_SKIP = {
    204: 5,
    211: 3,
    216: 3,
    217: 3,
    230: 3,
    231: 4,
    254: 1,
    295: 3,
    297: 4,
    272: 3,
    298: 3,
    299: 3,
    300: 3,
    340: 3,
    346: 3,
    359: 5,
    368: 3,
    379: 3,
    410: 4,
    412: 3,
    419: 4,
    433: 3,
    388: 3,
    403: 3,
    430: 4,
    491: 3,
    498: 3,
    504: 3,
    516: 3,
    520: 3,
    530: 3,
    539: 3,
    542: 3,
    569: 5,
    575: 3,
    598: 3,
    539: 3,
    572: 3,
    584: 3,
    597: 3,
    598: 3,
    601: 4,
    640: 3,
    655: 5,
    665: 3,
    639: 3,
    699: 3,
    702: 3,
    717: 4,
    721: 5,
    748: 5,
    725: 3,
    746: 3,
    751: 3,
    769: 3,
    770: 5,
    789: 5,
    192: 3,
    226: 3,
    387: 3,
    649: 3,
    730: 3,
}


def s16_of(raw: bytes) -> int:
    return struct.unpack_from("<h", raw, 2)[0]


def parse_op(raw: bytes, i: int, base: int) -> dict:
    raw = raw.ljust(0x30, b"\0")
    return {
        "i": i,
        "addr": base + i * 0x30,
        "b0": raw[0],
        "b1": raw[1],
        "s16": s16_of(raw),
        "imm16": struct.unpack_from("<H", raw, 2)[0],
        "word0": struct.unpack_from("<i", raw, 0)[0],
        "p8": struct.unpack_from("<Q", raw, 8)[0],
        "p16": struct.unpack_from("<Q", raw, 16)[0],
        "p24": struct.unpack_from("<Q", raw, 24)[0],
        "typ": struct.unpack_from("<I", raw, 0x28)[0],
        "hx": raw.hex(),
        "raw": raw,
    }


def parse_prog(blob: bytes, base: int) -> list[dict]:
    n = len(blob) // 0x30
    return [parse_op(blob[i * 0x30 : (i + 1) * 0x30], i, base) for i in range(n)]


class WrapEmu:
    def __init__(self):
        self.mem = Mem()
        self.rf = [0] * 64
        self.unk: dict[int, int] = {}
        self.exec_t: dict[int, int] = {}
        self.steps = 0
        self.sess0 = 21  # scratch; overwritten if dump has it
        self.sess10n = 6
        self.progs: dict[int, tuple[list[dict], int]] = {}
        self.native_fn: dict[int, str] = {}
        self.log: list[str] = []
        self.depth = 0
        self.heap = 0x30000000

    def alloc(self, n: int) -> int:
        n = max(int(n), 8)
        p = self.heap
        self.heap = (self.heap + n + 32) & ~15
        self.map(p, b"\0" * (n + 16))
        return p

    def map(self, addr: int, data: bytes) -> None:
        if addr:
            self.mem.map_bytes(addr, data)

    def R(self, i: int) -> int:
        return self.rf[i] if 0 <= i < len(self.rf) else 0

    def W(self, i: int, v: int) -> None:
        if 0 <= i < len(self.rf):
            self.rf[i] = u64(v)

    def extra_ops(self, op: dict, ops: list[dict], first: int) -> list[int]:
        n = len(ops)
        out = []
        p32 = struct.unpack_from("<Q", op["raw"], 0x20)[0] if len(op["raw"]) >= 0x28 else 0
        for p in (op["p8"], op["p16"], op["p24"], p32, struct.unpack_from("<Q", op["raw"], 0)[0]):
            if p < first:
                continue
            idx = (p - first) // 0x30
            # compounds fuse forward extras (next 1..5 ops); +0x20 is the 5th ptr
            if op["i"] < idx < n and idx <= op["i"] + 6 and idx not in out:
                out.append(idx)
        return sorted(out)

    def prim(self, op: dict) -> int:
        """Execute one primitive. Return skip (usually 1, or jump delta)."""
        t, a, b, s = op["typ"], op["b0"], op["b1"], op["s16"]
        aa, bb, dd = pack24(op)
        self.exec_t[t] = self.exec_t.get(t, 0) + 1
        skip = 1
        mem, R, W = self.mem, self.R, self.W
        if t == 1:
            W(b, mem.load_u64(u64(R(a) + s)))
        elif t == 7:
            W(dd, u64(struct.unpack("<b", bytes([R(bb) & 0xFF]))[0]))
        elif t == 8:
            W(dd, u64(R(aa) | R(bb)))
        elif t == 4:
            W(b, u64(mem.load_u64(op["p8"]) + s))
        elif t == 10:
            W(bb, sxtw((R(aa) & 0xFFFFFFFF) << (dd & 31)))
        elif t == 11:
            W(dd, u64(R(aa) & R(bb)))
        elif t == 12:
            W(b, sxtw((op["imm16"] << 16) & 0xFFFFFFFF))
        elif t == 21:
            W(dd, sxtw((R(bb) & 0xFFFFFFFF) >> (R(aa) & 31)))
        elif t == 27:
            diff = i32(R(a) - self.sess10n)
            if diff < 0:
                diff += 3
            self._jump_pc = diff >> 2
            skip = 0
        elif t == 29:
            W(dd, u64(R(bb) << (R(aa) & 63)))
        elif t == 30:
            W(bb, sxtw((R(aa) & 0xFFFFFFFF) >> (dd & 31)))
        elif t == 33:
            W(b, 1 if R(a) < u64(s) else 0)
        elif t == 39:
            extra = s if R(a) > 0 else 0
            skip = 1 + extra
        elif t == 96:
            extra = s if R(a) < 1 else 0
            skip = 1 + extra
        elif t == 35:
            W(bb, u64(R(aa) << (dd & 63)))
        elif t == 38:
            W(dd, sxtw((R(aa) + R(bb)) & 0xFFFFFFFF))
        elif t == 41:
            W(dd, sxtw((R(aa) - R(bb)) & 0xFFFFFFFF))
        elif t == 42:
            W(dd, u64(~(R(aa) | R(bb))))
        elif t == 80:
            W(b, u64(mem.load_u16(u64(R(a) + s))))
        elif t == 109:
            sh = dd & 31
            v = R(aa) & 0xFFFFFFFF
            W(bb, u64(((v >> sh) | (v << (32 - sh))) & 0xFFFFFFFF))
        elif t == 152:
            den = R(bb) & 0xFFFFFFFF
            num = R(aa) & 0xFFFFFFFF
            W(dd, sxtw((num % den) if den else 0))
        elif t == 169:
            sh = R(aa) & 31
            v = R(bb) & 0xFFFFFFFF
            W(dd, u64(((v >> sh) | (v << (32 - sh))) & 0xFFFFFFFF))
        elif t == 49:
            extra = 0 if R(a) == R(b) else s
            skip = 1 + extra
        elif t == 54:
            W(dd, u64(R(bb) >> (R(aa) & 63)))
        elif t == 50:
            mem.store_u64(u64(R(a) + s), R(b))
        elif t == 55:
            W(dd, R(aa))
        elif t == 60:
            W(dd, 0 if R(bb) == 0 else R(aa))
        elif t == 65:
            W(bb, u64(R(aa) >> ((dd + 32) & 63)))
        elif t == 67:
            W(bb, u64(R(aa) << ((dd + 32) & 63)))
        elif t == 68:
            W(b, u64(struct.unpack("<b", bytes([mem.load_u8(u64(R(a) + s))]))[0]))
        elif t == 73:
            W(b, u64(R(a) + s))
        elif t == 76:
            W(b, u64(mem.load_i32(u64(R(a) + s))))
        elif t == 82:
            W(b, 1 if i32(R(a)) < s else 0)
        elif t == 94:
            W(b, u64(R(a) ^ op["imm16"]))
        elif t == 99:
            W(dd, u64(R(aa) + R(bb)))
        elif t == 102:
            W(b, u64(R(a) | op["imm16"]))
        elif t == 105:
            W(b, sxtw((i32(R(a)) + s) & 0xFFFFFFFF))
        elif t == 106:
            mem.store(u64(R(a) + s), bytes([R(b) & 0xFF]))
        elif t == 112:
            W(b, u64(R(a) & op["imm16"]))
        elif t == 123:
            W(b, mem.load_u8(u64(R(a) + s)))
        elif t == 125:
            skip = op["word0"] + 1
        elif t == 126:
            extra = s if R(a) == R(b) else 0
            skip = 1 + extra
        elif t == 139:
            W(b, u64(s))
        elif t == 154:
            W(dd, R(aa) if R(bb) == 0 else 0)
        elif t == 159:
            self.call_442e84(op)
        elif t == 165:
            W(dd, 1 if R(aa) < R(bb) else 0)
        elif t == 167:
            mem.store_u32(u64(R(a) + s), R(b) & 0xFFFFFFFF)
        elif t == 170:
            W(dd, 1 if R(aa) < R(bb) else 0)
        elif t == 181:
            W(dd, u64(R(aa) ^ R(bb)))
        elif t == 189:
            self._ret = True
            skip = 0
        else:
            self.unk[t] = self.unk.get(t, 0) + 1
        return skip

    def call_442e84(self, op: dict) -> None:
        w2 = op["word0"] & 0xFFFFFFFF
        p8 = op["p8"]
        if w2 in (8, 33):
            dest, src, nbytes = self.R(8), self.R(9), self.R(10) & 0xFFFFFFFF
            if w2 == 8:
                obj = dest
                if obj:
                    data = self.alloc(8)
                    self.mem.store_u64(obj + 0x10, data)
                    self.mem.store_u32(obj + 0xC, 0)
                    self.mem.store(data, b"\0")
                self.log.append(f"  159 w2=8 empty RF8={dest:x}")
                return
            n = nbytes if 0 < nbytes < 0x10000 else (src & 0xFFFFFFFF)
            n = min(max(int(n), 1), 0x10000)
            if dest:
                data = self.alloc(n)
                self.mem.store_u64(dest + 0x10, data)
                self.mem.store_u32(dest + 0xC, n)
            self.log.append(f"  159 w2=33 alloc n={n} obj={dest:x}")
            return
        if w2 < 40:
            self.log.append(
                f"  159 w2={w2} d={self.depth} RF8={self.R(8):x} RF9={self.R(9):x} RF10={self.R(10):x} "
                f"RF5={self.R(5):x} RF15={self.R(15):x} RF22={self.R(22):x} RF30={self.R(30):x}"
            )
            if w2 == 26 and self.R(8) > 0x10000:
                self.log.append(f"  w26 in8 {self.mem.load(self.R(8), 48).hex()}")
                if self.R(9) > 0x10000:
                    self.log.append(f"  w26 in9 {self.mem.load(self.R(9), 32).hex()}")
        # diagnostic: KEY data pointer if mill dropped RF[5]
        if False and w2 == 26 and self.R(5) < 0x10000 and getattr(self, "key_data", 0):
            self.log.append(f"  inject KEY data {self.key_data:x}")
            self.W(5, self.key_data)
        try:
            table = self.mem.load_u64(p8)
            target = self.mem.load_u64(u64(table + (w2 * 8)))
            disc = self.mem.load_u64(target + 0x58) if target > 0x10000 else 0
        except Exception:
            self.unk[159000 + (w2 & 0xFF)] = self.unk.get(159000 + (w2 & 0xFF), 0) + 1
            return
        # save PC into RF[sess0] — caller already advanced; skip here
        fnptr = self.mem.load_u64(target) if target > 0x10000 else 0
        fn = self.native_fn.get(target) or self.native_fn.get(fnptr)
        if disc == 1 or target in self.progs or (target + 8) in self.progs:
            ops_ptr = self.mem.load_u64(target + 8) if target > 0x10000 else 0
            rec = self.progs.get(ops_ptr) or self.progs.get(target + 8)
            if rec:
                self.log.append(f"  nest mill ops={ops_ptr:x} w2={w2} depth={self.depth}")
                self.run_prog(*rec)
                return
        # glue: RF[8], RF[9], RF[10] = dest/src/len ; RF[6] = result
        dest, src, nbytes = self.R(8), self.R(9), self.R(10) & 0xFFFFFFFF
        if nbytes > 0x10000:
            nbytes = 0x10000
        if w2 == 8 or fnptr in (0x2C4598,):
            obj = dest
            if obj:
                data = self.alloc(8)
                self.mem.store_u64(obj + 0x10, data)
                self.mem.store_u32(obj + 0xC, 0)
                self.mem.store(data, b"\0")
            return
        if w2 == 33 or fnptr in (0x2C49FC,):
            obj = dest
            n = nbytes if 0 < nbytes < 0x10000 else (src & 0xFFFFFFFF)
            n = min(max(int(n), 1), 0x10000)
            if obj:
                data = self.alloc(n)
                self.mem.store_u64(obj + 0x10, data)
                self.mem.store_u32(obj + 0xC, n)
            return
        if fnptr in (0x2BC850, 0x4A0DC0) or w2 == 4 or fn == "memcpy":
            if dest and src and nbytes:
                self.mem.store(dest, self.mem.load(src, nbytes))
            self.W(6, dest)
            return
        if fnptr in (0x41F714,) or w2 == 3 or fn == "memset":
            if dest and nbytes:
                self.mem.store(dest, bytes([src & 0xFF]) * nbytes)
            self.W(6, dest)
            return
        if fnptr in (0x2BC838, 0x2596E8) or w2 == 5:
            obj = dest
            if obj:
                data = self.alloc(8)
                self.mem.store_u64(obj + 0x10, data)
                self.mem.store_u32(obj + 0xC, 0)
                self.mem.store(data, b"\0")
            return
        if fnptr in (0x2BC8B0, 0x25A314) or w2 == 6:
            obj = dest
            n = src & 0xFFFFFFFF if src else nbytes
            n = min(max(n, 1), 0x10000)
            if obj:
                data = self.alloc(n)
                self.mem.store_u64(obj + 0x10, data)
                self.mem.store_u32(obj + 0xC, n)
            return
        if fnptr in (0x2BC7AC, 0x2A6398) or w2 == 0 or fn == "copy":
            if dest and src:
                n = nbytes if nbytes else 32
                self.mem.store(dest, self.mem.load(src, n))
            return
        if w2 in (1, 2, 7, 8):
            return
        self.unk[159000 + (w2 & 0xFF)] = self.unk.get(159000 + (w2 & 0xFF), 0) + 1
        self.log.append(f"  159 miss w2={w2} tgt={target:x} disc={disc} fn={fnptr:x}")

    def run_prog(self, ops: list[dict], first: int) -> None:
        self.depth += 1
        pc = 0
        n = len(ops)
        fused: set[int] = set()
        self._ret = False
        self._jump_pc = None
        guard = 0
        maxpc = 0
        while 0 <= pc < n and guard < 200000 and not self._ret:
            guard += 1
            if pc in fused:
                pc += 1
                continue
            op = ops[pc]
            t = op["typ"]
            self.steps += 1
            if pc > maxpc:
                maxpc = pc
            if first == 0x764A139C00 and pc in (0, 32, 34, 141, 143, 144, 148, 401) and guard < 20:
                r20 = self.R(20)
                mem20 = self.mem.load(r20, 16).hex() if r20 > 0x10000 else ""
                r9 = self.R(9)
                mem9 = self.mem.load(r9, 16).hex() if r9 > 0x10000 else ""
                self.log.append(
                    f"  w26 pc={pc} t={t} RF8={self.R(8):x} RF9={r9:x} mem9={mem9} "
                    f"RF20={r20:x} mem20={mem20} RF11={self.R(11):x} RF6={self.R(6):x}"
                )
            if first == 0x764A115D40 and pc in (16, 41, 56, 100, 105, 106, 111, 119, 222, 411, 437, 439, 444, 487):
                self.log.append(
                    f"  nest pc={pc} t={t} RF2={self.R(2):x} RF5={self.R(5):x} RF7={self.R(7):x} "
                    f"RF8={self.R(8):x} RF22={self.R(22):x} RF30={self.R(30):x}"
                )
            if t in COMPOUND_SKIP or (t >= 200 and t not in (189,)):
                xs = self.extra_ops(op, ops, first)
                landed = None
                for e in xs:
                    fused.add(e)
                    if not (0 <= e < n):
                        continue
                    et = ops[e]["typ"]
                    if et in COMPOUND_SKIP:
                        continue
                    sk = self.prim(ops[e])
                    self.steps += 1
                    if self._ret:
                        break
                    if self._jump_pc is not None:
                        landed = self._jump_pc
                        self._jump_pc = None
                        break
                    if et in (49, 125, 126) and sk != 1:
                        landed = e + sk
                        break
                if self._ret:
                    break
                if landed is not None:
                    pc = landed
                    continue
                skip = COMPOUND_SKIP.get(t) or ((max(xs) + 1 - pc) if xs else 1)
                if skip < 1:
                    skip = 1
                pc = pc + skip
                continue
            skip = self.prim(op)
            if self._ret:
                break
            if self._jump_pc is not None:
                pc = self._jump_pc
                self._jump_pc = None
                continue
            pc = pc + skip
        self.log.append(f"  run_prog first={first:x} n={n} maxpc={maxpc} guard={guard} depth={self.depth}")
        self.depth -= 1
        self._ret = False

    def dest32(self, dest_obj: int) -> bytes:
        n = struct.unpack("<i", self.mem.load(dest_obj + 0xC, 4))[0]
        data = self.mem.load_u64(dest_obj + 0x10)
        if 0 < n <= 64 and data:
            return self.mem.load(data, n)
        # search nearby work for 32B written after PKCS7-ish
        return self.mem.load(data, 32) if data else b""


def load_dump():
    evs = json.loads((ROOT / "_wrap_emu_last.json").read_text(encoding="utf-8"))
    prog = next(e for e in evs if e.get("type") == "prog")
    io_in = next(e for e in evs if e.get("type") == "in")
    io_out = next(e for e in evs if e.get("type") == "out")
    return prog, io_in, io_out


def main() -> None:
    prog, io_in, io_out = load_dump()
    E = WrapEmu()
    E.sess10n = int(prog.get("sess10n") or 6)
    rf_ptrs = [parse_u(x) for x in (prog.get("rf") or [])]
    for i, p in enumerate(rf_ptrs):
        E.W(i, p)

    # objects
    pt = bytes.fromhex(io_in["pt"]["hex"])
    key = bytes.fromhex(io_in["key"]["hex"])
    iv = bytes.fromhex(io_in["iv"]["hex"])
    live = bytes.fromhex(io_out["dst"]["hex"])
    pt_obj = parse_u(io_in["pt"]["ptr"])
    key_obj = parse_u(io_in["key"]["ptr"])
    iv_obj = parse_u(io_in["iv"]["ptr"])
    dst_obj = parse_u(io_out["dst"]["ptr"])
    pt_data = parse_u(io_in["pt"]["data"])
    key_data = parse_u(io_in["key"]["data"])
    iv_data = parse_u(io_in["iv"]["data"])

    def map_obj(obj, n, data_ptr, payload, raw_hex=""):
        hdr = bytes.fromhex(raw_hex) if raw_hex else b"\0" * 48
        hdr = bytearray(hdr.ljust(48, b"\0"))
        struct.pack_into("<i", hdr, 0xC, n)
        if data_ptr:
            struct.pack_into("<Q", hdr, 0x10, data_ptr)
        E.map(obj, bytes(hdr))
        if data_ptr and payload:
            E.map(data_ptr, payload)

    slots = {s["slot"]: s for s in (prog.get("slots") or [])}
    map_obj(iv_obj, 16, iv_data, iv, (slots.get(0) or {}).get("raw") or "")
    map_obj(key_obj, 16, key_data, key, (slots.get(5) or {}).get("raw") or "")
    print("KEY obj", E.mem.load(key_obj, 32).hex(), "data", key_data, key.hex())
    map_obj(pt_obj, 19, pt_data, pt, (slots.get(28) or {}).get("raw") or "")
    map_obj(dst_obj, -221, 0, b"", (slots.get(6) or {}).get("raw") or "")
    # dest heap for mill to fill
    dest_buf = 0x20000000
    E.map(dest_buf, b"\0" * 64)

    rf1 = parse_u(prog.get("rf1") or "0")
    win = bytes.fromhex(prog.get("rfwin") or "")
    E.map(rf1 - 0x400, b"\0" * 0x400)
    if win:
        E.map(rf1, win)
    else:
        E.map(rf1, b"\0" * 0x300)
    # slot4
    if 4 in slots and slots[4].get("ptr"):
        E.map(parse_u(slots[4]["ptr"]), bytes.fromhex(slots[4].get("raw") or "00" * 48))

    # const tables from dump
    sbox_path = ROOT / "_wrap_sbox_tab.hex"
    if sbox_path.exists():
        E.map(0x764A1C7000, bytes.fromhex(sbox_path.read_text().strip()))
    for c in prog.get("consts") or []:
        p = parse_u(c.get("p") or "0")
        if p and c.get("mem"):
            E.map(p, bytes.fromhex(c["mem"]))
        if c.get("jtab") and c.get("jmem"):
            E.map(parse_u(c["jtab"]), bytes.fromhex(c["jmem"]))
        if c.get("t") == 159 and c.get("vt18"):
            vt18 = parse_u(c["vt18"])
            # mill object dumped separately
            pass

    nested_meta = json.loads((ROOT / "_wrap_nested_meta.json").read_text(encoding="utf-8"))
    nested_ops_hex = (ROOT / "_wrap_nested_ops.hex").read_text().strip()
    nested_blob = bytes.fromhex(nested_ops_hex)
    obj18 = bytes.fromhex(nested_meta.get("obj") or "")
    obj18_addr = 0x764A01A260
    E.map(obj18_addr, obj18)
    nested_base = 0x764A115D40
    E.map(nested_base, nested_blob)
    E.progs[nested_base] = (parse_prog(nested_blob, nested_base), nested_base)
    E.progs[obj18_addr + 8] = E.progs[nested_base]
    # mill method objects 17+
    methods_path = ROOT / "_wrap_methods.json"
    if methods_path.exists():
        for rec in json.loads(methods_path.read_text(encoding="utf-8")):
            p = parse_u(rec.get("p") or "0")
            memh = rec.get("mem") or ""
            if p and memh:
                E.map(p, bytes.fromhex(memh))
            if rec.get("at58") == "1" and rec.get("p8"):
                ops_ptr = parse_u(rec["p8"])
                if ops_ptr in E.progs:
                    E.progs[p + 8] = E.progs[ops_ptr]
    w26_hex = ROOT / "_wrap_w26_ops.hex"
    if w26_hex.exists():
        w26_blob = bytes.fromhex(w26_hex.read_text().strip())
        w26_base = 0x764A139C00
        w26_obj = 0x764A01A560
        E.map(w26_base, w26_blob)
        E.progs[w26_base] = (parse_prog(w26_blob, w26_base), w26_base)
        E.progs[w26_obj + 8] = E.progs[w26_base]
        print("w26 ops", len(E.progs[w26_base][0]))
    w109_hex = ROOT / "_wrap_w109_ops.hex"
    if w109_hex.exists():
        w109_blob = bytes.fromhex(w109_hex.read_text().strip())
        w109_base = 0x764A036C00
        w109_obj = 0x764A09B600
        E.map(w109_base, w109_blob)
        E.map(w109_obj, bytes.fromhex((ROOT / "_wrap_w109_meta.json").read_text()) if False else b"")
        meta109 = json.loads((ROOT / "_wrap_w109_meta.json").read_text(encoding="utf-8"))
        if meta109.get("obj"):
            E.map(w109_obj, bytes.fromhex(meta109["obj"]))
        E.progs[w109_base] = (parse_prog(w109_blob, w109_base), w109_base)
        E.progs[w109_obj + 8] = E.progs[w109_base]
        print("w109 ops", len(E.progs[w109_base][0]))
        jtab = 0x764A036200
        E.mem.store_u64(jtab + 26 * 8, 0x764A01A560)
        E.mem.store_u64(jtab + 109 * 8, w109_obj)
    # native labels from live dump
    E.native_fn[0x764A019CC0] = "memset"
    E.native_fn[0x764A01A080] = "memcpy"
    E.native_fn[0x774FFF3220] = "copy"
    E.native_fn[0x7644C4C714] = "memset"
    E.native_fn[0x7644C4C67C] = "memcpy"
    E.native_fn[0x7644AE97AC] = "copy"

    outer_blob = bytes.fromhex(prog.get("ops") or "")
    inner = parse_u(prog.get("inner") or "0")
    outer = parse_prog(outer_blob, inner)
    E.key_data = key_data
    print("outer", len(outer), "nested", len(E.progs[nested_base][0]), "sess10n", E.sess10n)
    print("pt", pt.hex(), "live", live.hex())

    E.run_prog(outer, inner)
    got = E.dest32(dst_obj)
    print("steps", E.steps, "unk", dict(sorted(E.unk.items(), key=lambda x: -x[1])[:20]))
    print("exec top", sorted(E.exec_t.items(), key=lambda x: -x[1])[:12])
    print("got", got.hex() if got else "<empty>")
    print("live", live.hex())
    print("match", got == live)
    for line in E.log[:40]:
        print(line)
    print("--- RF ---")
    for i in range(32):
        if E.R(i):
            print(f"  RF[{i:2d}] {E.R(i):016x} mem8={E.mem.load(E.R(i), 8).hex()}")
    hits = 0
    for base, page in E.mem.pages.items():
        blob = bytes(page)
        idx = blob.find(live)
        if idx >= 0:
            print("found live at", hex(base + idx))
            hits += 1
        # any 32B matching first 4 of live
        p = blob.find(live[:4])
        if p >= 0:
            print("pfx4 at", hex(base + p), blob[p : p + 32].hex())
    print("live hits", hits)
    print("dest hdr", E.mem.load(dst_obj, 32).hex())
    print("work+0", E.mem.load(rf1, 64).hex())
    print("work-448", E.mem.load(rf1 - 448, 64).hex())
    for addr, lab in (
        (0x764CBF5180, "ws5180"),
        (0x764CBF5230, "ivcopy"),
        (0x30000020, "heap20"),
        (0x764CBF5168, "obj5168"),
        (0x764CBF53F0, "rf9end"),
        (0x764CBF5410, "rf6end"),
        (0x764CBF50D8, "obj50d8"),
    ):
        print(lab, E.mem.load(addr, 48).hex())
    # scan heap
    blob = E.mem.load(0x30000000, 0x200)
    print("heap", blob[:64].hex())
    idx = blob.find(live[:4])
    print("heap pfx", idx)
    print("exec159", E.exec_t.get(159), "exec68", E.exec_t.get(68), "exec7", E.exec_t.get(7))
    for i in (6, 8, 9, 11, 16, 18, 28, 30):
        p = E.R(i)
        if p > 0x10000:
            print(f"  *RF[{i}] {p:x} {E.mem.load(p, 32).hex()}")
    # dump RF[1] work window used by nested
    print("rf1-144", E.mem.load(E.R(1), 64).hex() if E.R(1) else "")
    w26 = E.progs.get(0x764A139C00)
    if w26:
        ops26, base26 = w26
        from collections import Counter
        print("w26 217 extras sample")
        n217 = 0
        for o in ops26:
            if o["typ"] == 217 and n217 < 3:
                xs = E.extra_ops(o, ops26, base26)
                print(" ", o["i"], "extras", xs, [ops26[e]["typ"] for e in xs])
                n217 += 1


if __name__ == "__main__":
    main()
