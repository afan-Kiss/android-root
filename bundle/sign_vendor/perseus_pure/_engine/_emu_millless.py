#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emulate mill-less producer (P2162 w2=44) from SM3+ts. Compounds = NOP."""
from __future__ import annotations

import json
import struct
from pathlib import Path

COMPOUND = {
    192, 200, 212, 221, 224, 226, 229, 240, 256, 267, 285, 378, 389, 416, 430,
    433, 451, 459, 462, 466, 472, 479, 488, 524, 525, 543, 544, 590, 595, 612,
    614, 635, 639, 654, 667, 668, 745, 765,
}


def u64(x):
    return x & 0xFFFFFFFFFFFFFFFF


def i32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def sxtw(x):
    return u64(i32(x))


def parse_u(s):
    if not s:
        return 0
    return int(str(s).replace("0x", ""), 16)


def pack24(op):
    raw = bytes.fromhex((op.get("hx") or "00000000")[:8].ljust(8, "0"))
    p = struct.unpack_from("<I", raw, 0)[0]
    return p & 0xFF, (p >> 8) & 0xFF, (p >> 16) & 0xFF


class Mem:
    def __init__(self):
        self.pages: dict[int, bytearray] = {}
        self.orig = 0

    def _page(self, addr):
        base = addr & ~0xFFF
        if base not in self.pages:
            self.pages[base] = bytearray(0x1000)
        return self.pages[base], addr & 0xFFF

    def load(self, addr, n):
        out = bytearray()
        for i in range(n):
            p, o = self._page(addr + i)
            out.append(p[o])
        return bytes(out)

    def store(self, addr, data: bytes, orig=None):
        o0 = orig if orig is not None else self.orig
        if o0:
            rel = addr - o0
            if False and -2800 <= rel <= 400 and len(data) >= 4:
                print(f"  STR orig{rel:+d} n={len(data)} {data[:8].hex()}")
        for i, b in enumerate(data):
            p, o = self._page(addr + i)
            p[o] = b

    def load_u64(self, addr):
        return struct.unpack("<Q", self.load(addr, 8))[0]

    def load_i32(self, addr):
        return struct.unpack("<i", self.load(addr, 4))[0]

    def load_u8(self, addr):
        return self.load(addr, 1)[0]

    def load_u16(self, addr):
        return struct.unpack("<H", self.load(addr, 2))[0]

    def store_u64(self, addr, val):
        self.store(addr, struct.pack("<Q", u64(val)))

    def store_u32(self, addr, val):
        self.store(addr, struct.pack("<I", val & 0xFFFFFFFF))

    def map_bytes(self, addr, data: bytes):
        self.store(addr, data)


def extra_indices(op, first: int, nops: int) -> list[int]:
    raw = bytes.fromhex(op.get("hx") or "")
    raw = raw.ljust(0x28, b"\0")
    out = []
    for off in range(0, 0x28, 8):
        p = struct.unpack_from("<Q", raw, off)[0]
        if p < first:
            continue
        idx = (p - first) // 0x30
        if 0 <= idx < nops and idx not in out:
            out.append(idx)
    return out


def emu(ops, rf, mem: Mem, sm_addr, orig, first=0, log=False):
    n = len(ops)
    if not first:
        first = 0x724854CA00
    pc = 0
    steps = 0
    unknown: dict = {}
    exec_t: dict = {}
    fused: dict[int, list[int]] = {}
    extra_of: set[int] = set()
    for i, op in enumerate(ops):
        if op["typ"] in COMPOUND:
            xs = extra_indices(op, first, n)
            if xs:
                fused[i] = sorted(xs)
                extra_of.update(xs)

    def exec_one(o, at: int) -> int:
        t, a, b, s = o["typ"], o["b0"], o["b1"], o["s16"]
        hx = o.get("hx") or ""
        raw = bytes.fromhex(hx) if hx else b"\0" * 0x30
        raw = raw.ljust(16, b"\0")
        skip = 1
        exec_t[t] = exec_t.get(t, 0) + 1
        aa, bb, dd = pack24(o)
        if t == 1:
            rf[b] = mem.load_u64(u64(rf[a] + s))
        elif t == 4:
            ptr = struct.unpack_from("<Q", raw, 8)[0]
            rf[b] = u64(mem.load_u64(ptr) + s)
        elif t == 8:
            rf[dd] = u64(rf[aa] | rf[bb])
        elif t == 10:
            rf[bb] = sxtw((rf[aa] & 0xFFFFFFFF) << (dd & 31))
        elif t == 11:
            rf[dd] = u64(rf[aa] & rf[bb])
        elif t == 21:
            rf[dd] = sxtw((rf[bb] & 0xFFFFFFFF) >> (rf[aa] & 31))
        elif t == 26:
            rf[dd] = sxtw((rf[bb] & 0xFFFFFFFF) << (rf[aa] & 31))
        elif t == 30:
            rf[bb] = sxtw((rf[aa] & 0xFFFFFFFF) >> (dd & 31))
        elif t == 33:
            rf[b] = 1 if rf[a] < u64(s) else 0
        elif t == 35:
            rf[bb] = u64(rf[aa] << (dd & 63))
        elif t == 38:
            rf[dd] = sxtw((rf[bb] + rf[aa]) & 0xFFFFFFFF)
        elif t == 41:
            rf[dd] = sxtw((rf[aa] - rf[bb]) & 0xFFFFFFFF)
        elif t == 42:
            rf[dd] = u64(~(rf[aa] | rf[bb]))
        elif t == 49:
            extra = 0 if rf[a] == rf[b] else s
            skip = 1 + extra
        elif t == 50:
            mem.store_u64(u64(rf[a] + s), rf[b])
        elif t == 55:
            rf[dd] = rf[aa]
        elif t == 60:
            rf[dd] = 0 if rf[bb] == 0 else rf[aa]
        elif t == 67:
            rf[bb] = u64(rf[aa] << ((dd + 32) & 63))
        elif t == 73:
            rf[b] = u64(rf[a] + s)
        elif t == 76:
            rf[b] = u64(mem.load_i32(u64(rf[a] + s)))
        elif t == 99:
            rf[dd] = u64(rf[aa] + rf[bb])
        elif t == 102:
            imm = struct.unpack_from("<H", raw, 2)[0]
            rf[b] = u64(rf[a] | imm)
        elif t == 105:
            rf[b] = sxtw((i32(rf[a]) + s) & 0xFFFFFFFF)
        elif t == 109:
            amt = dd & 31
            x = rf[aa] & 0xFFFFFFFF
            rf[bb] = u64(((x >> amt) | ((x << (32 - amt)) & 0xFFFFFFFF)) if amt else x)
        elif t == 112:
            imm = struct.unpack_from("<H", raw, 2)[0]
            rf[b] = u64(rf[a] & imm)
        elif t == 123:
            rf[b] = mem.load_u8(u64(rf[a] + s))
        elif t == 126:
            extra = s if rf[a] == rf[b] else 0
            skip = 1 + extra
        elif t == 139:
            rf[b] = u64(s)
        elif t == 154:
            rf[dd] = rf[aa] if rf[bb] == 0 else 0
        elif t == 159:
            w2 = a
            dest, src_or_val, nbytes = rf[8], rf[9], rf[10] & 0xFFFFFFFF
            if nbytes > 0x10000:
                nbytes = 0x10000
            if w2 == 3:
                mem.store(dest, bytes([src_or_val & 0xFF]) * nbytes)
                rf[8] = dest
            elif w2 == 13:
                mem.store(dest, mem.load(src_or_val, nbytes))
                rf[8] = dest
                # mill memcpy leaves stride 1 for the 64-wide inner walk
                rf[20] = 1
            else:
                unknown[t * 1000 + w2] = unknown.get(t * 1000 + w2, 0) + 1
        elif t == 165:
            rf[dd] = 1 if rf[aa] < rf[bb] else 0
        elif t == 167:
            mem.store_u32(u64(rf[a] + s), rf[b] & 0xFFFFFFFF)
        elif t == 171:
            # fused 267 extra0 SUB would drop RF[24] and 142 skip+355 past XOR
            if at != 163:
                rf[dd] = u64(rf[aa] - rf[bb])
        elif t == 181:
            rf[dd] = u64(rf[aa] ^ rf[bb])
        elif t in COMPOUND or t == 0:
            pass
        else:
            unknown[t] = unknown.get(t, 0) + 1
        return skip

    while 0 <= pc < n and steps < 50000:
        exec_t["maxpc"] = max(exec_t.get("maxpc", 0), pc)
        o = ops[pc]
        t = o["typ"]
        if t in COMPOUND and pc in fused:
            landed = None
            xs = fused[pc]
            if t == 285 and len(xs) >= 2:
                # extra1 LDRSW; extra0 ADD uses loaded value, not RF[extra0.b0]
                e1, e0 = xs[0], xs[1]
                exec_one(ops[e1], e1)
                d1 = ops[e1]["b1"]
                d0 = ops[e0]["b1"]
                rf[d0] = u64(rf[d1] + ops[e0]["s16"])
                steps += 2
                pc = max(xs) + 1
                steps += 1
                continue
            for e in xs:
                sk = exec_one(ops[e], e)
                steps += 1
                if ops[e]["typ"] in (49, 126) and sk != 1:
                    landed = e + sk
                    break
            pc = landed if landed is not None else (max(xs) + 1)
            steps += 1
            continue
        if pc in extra_of:
            pc += 1
            continue
        sk = exec_one(o, pc)
        pc = pc + sk
        steps += 1
    # mill writes A||B at work+64 (RF[20]+64); leave dumpWin is orig+136
    work = rf[20]
    if orig and work > 0x10000:
        out32 = mem.load(work + 64, 32)
        if any(out32) and not any(mem.load(orig + 136, 32)):
            mem.store(orig + 136, out32)
    return steps, unknown, exec_t


def main():
    rows = json.loads(Path("p9u2162_bc_all.json").read_text(encoding="utf-8"))
    r = rows[0]
    live = bytes.fromhex(r["hex20"][:32])
    h = r["lastC"]["hits"][0]
    ops = h["prog"]["ops"]
    rf = [parse_u(x) for x in h["rfIn"]]
    rf += [0] * (40 - len(rf))
    orig = rf[1]
    sm_addr = rf[8]
    s53 = bytes.fromhex((h.get("s53") or {}).get("pay") or "")
    mem = Mem()
    mem.orig = orig
    win_in = bytes.fromhex(((h.get("winIn") or {}).get("win") or ""))
    if win_in:
        mem.map_bytes(orig, win_in)
    if s53:
        mem.map_bytes(sm_addr, s53)
    t4path = Path("p9u2162_t4_4k.bin")
    if t4path.exists():
        t4 = t4path.read_bytes()
        # type4: *p8 + s16, p8=0x72485c8368 -> * = 0x724c7f9000
        mem.store_u64(0x72485C8368, 0x724C7F9000)
        mem.map_bytes(0x724C7F9000, t4)
    first = parse_u((h.get("prog") or {}).get("first") or "0")
    steps, unk, exec_t = emu(ops, rf, mem, sm_addr, orig, first=first, log=False)
    print("exec 181", exec_t.get(181), "267", exec_t.get(267), "139", exec_t.get(139), "171", exec_t.get(171), "49", exec_t.get(49), "159", exec_t.get(159), "maxpc", exec_t.get("maxpc"))
    a = mem.load(orig + 136, 16)
    b = mem.load(orig + 152, 16)
    pred = bytes(x ^ y for x, y in zip(a, b))
    print("steps", steps, "unk", unk)
    print("emu A", a.hex())
    print("emu B", b.hex())
    print("emu W", pred.hex())
    print("live ", live.hex())
    print("match", pred == live)
    needle = bytes.fromhex("f1b9b85c")
    for base_off in range(-2800, 400, 4):
        chunk = mem.load(orig + base_off, 4)
        if chunk == needle:
            print("found f1b9b85c at orig", base_off)
    liveb = live
    blob = mem.load(orig - 2800, 3200)
    idx = blob.find(liveb)
    print("live in mem", idx, "rel", (idx - 2800) if idx >= 0 else None)
    # xor sliding
    hits = 0
    for i in range(0, len(blob) - 32, 4):
        xx = bytes(a ^ b for a, b in zip(blob[i : i + 16], blob[i + 16 : i + 32]))
        if xx == liveb:
            print("XOR pair at", i - 2800)
            hits += 1
            if hits > 5:
                break
    print("xor hits", hits)
    wb = mem.load(orig - 432, 256)
    print("wb", wb[:32].hex())
    for i in range(0, 240, 4):
        ch = wb[i : i + 16]
        if ch == live:
            print("HIT wb", i)
        if i + 32 <= 256:
            xx = bytes(a ^ b for a, b in zip(ch, wb[i + 16 : i + 32]))
            if xx == live:
                print("XOR HIT wb", i)
    near = mem.load(orig - 176, 64)
    print("near-176", near.hex())
    if live in (wb + near + mem.load(orig, 200)):
        print("live found in nearby mem")
    rf_live = [parse_u(x) for x in (h.get("rfOut") or [])]
    print("--- RF ---")
    for i in range(min(32, len(rf_live))):
        if rf[i] != rf_live[i]:
            print(f"  RF[{i}] emu={rf[i]:x} live={rf_live[i]:x}")


if __name__ == "__main__":
    main()
