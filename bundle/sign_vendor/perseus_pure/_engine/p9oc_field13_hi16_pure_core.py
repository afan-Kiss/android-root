# -*- coding: utf-8 -*-
"""Pure hi16 schedule replay (no frida). Lifted from p9oc/p9o8."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OPSTREAM = ROOT / "p9oc_field13_hi16_opstream.json"


def not64(h: str) -> str:
    return "".join(f"{(~int(h[i : i + 2], 16)) & 0xFF:02x}" for i in range(0, 16, 2))


def or64(a: str, b: str) -> str:
    return "".join(
        f"{(int(a[i : i + 2], 16) | int(b[i : i + 2], 16)) & 0xFF:02x}"
        for i in range(0, 16, 2)
    )


def and64(a: str, b: str) -> str:
    return "".join(
        f"{(int(a[i : i + 2], 16) & int(b[i : i + 2], 16)) & 0xFF:02x}"
        for i in range(0, 16, 2)
    )


def u64le(h: str) -> int:
    return int.from_bytes(bytes.fromhex(h), "little")


def h64(v: int) -> str:
    return (v & ((1 << 64) - 1)).to_bytes(8, "little").hex()


def lsl_op(sv: str, sh: int) -> str:
    w = u64le(sv) & 0xFFFFFFFF
    sh &= 31
    w = (w << sh) & 0xFFFFFFFF
    if w & 0x80000000:
        v = w | 0xFFFFFFFF00000000
    else:
        v = w
    return h64(v)


def lsr_op(sv: str, sh: int) -> str:
    w = u64le(sv) & 0xFFFFFFFF
    sh &= 31
    w = (w >> sh) & 0xFFFFFFFF
    if w & 0x80000000:
        v = w | 0xFFFFFFFF00000000
    else:
        v = w
    return h64(v)


def add64(a: str, b: str) -> str:
    return h64(u64le(a) + u64le(b))


def pure_replay(v90: str, va0: str, first8: str, schedule: list[dict]) -> str:
    slots = {
        5: "0" * 16,
        6: "0" * 16,
        9: "0" * 16,
        11: "0" * 16,
        13: "0" * 16,
        15: "0" * 16,
        17: "0" * 16,
        18: va0,
        26: v90,
        29: "0" * 16,
    }
    fi = 0
    hi = None
    for i, op in enumerate(schedule):
        k = op["k"]
        if k == "nor":
            a, b, d = op["a"], op["b"], op["d"]
            slots[d] = not64(or64(slots[a], slots[b]))
        elif k == "nand":
            a, b, d = op["a"], op["b"], op["d"]
            slots[d] = not64(and64(slots[a], slots[b]))
        elif k == "orimm":
            slots[op["d"]] = or64(slots[op["src"]], op["imm"])
        elif k == "andimm":
            slots[op["d"]] = and64(slots[op["src"]], op["imm"])
        elif k == "lsl":
            slots[op["d"]] = lsl_op(slots[op["src"]], int(op["sh"]))
        elif k == "lsr":
            slots[op["d"]] = lsr_op(slots[op["src"]], int(op["sh"]))
        elif k == "addimm":
            slots[op["d"]] = add64(slots[op["src"]], op["imm"])
        elif k == "movimm":
            slots[op["d"]] = op["imm"]
        elif k == "movshl16":
            imm16 = int(op["imm16"]) & 0xFFFF
            slots[op["d"]] = h64((imm16 << 16) & 0xFFFFFFFF)
        elif k == "ldrb":
            b = first8[fi * 2 : fi * 2 + 2]
            fi += 1
            slots[op["d"]] = b + "00000000000000"
        elif k == "mask":
            pred = and64(slots[op["src"]], op["imm"])
            slots[op["d"]] = pred
            hi = pred[:4]
        elif k == "addrr":
            continue
        else:
            raise RuntimeError(f"unknown op {i}: {op}")
    if fi != 8:
        raise RuntimeError(f"ldrb count {fi}")
    if not hi:
        raise RuntimeError("no mask hi16")
    return hi


def load_ops() -> list[dict]:
    data = json.loads(OPSTREAM.read_text(encoding="utf-8"))
    ops = data.get("ops") or data
    if not isinstance(ops, list):
        raise RuntimeError("bad opstream")
    return ops


__all__ = ["pure_replay", "load_ops"]
