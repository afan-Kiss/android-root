#!/usr/bin/env python3
"""Mill-less WRAP 19B -> 32B using the live 416-op type-717 mill + static tables."""
from __future__ import annotations

import json
from pathlib import Path

from _emu_wrap_mill import WrapEmu, parse_prog, parse_u

ROOT = Path(__file__).resolve().parent

V34_WRAP_KEY = bytes.fromhex("f1593376766ea98d34f31b057a9d5be4")
V34_WRAP_IV = bytes.fromhex("1fe109a4125283f418de9e051a969e12")

_CACHE: dict | None = None


def _pkcs7_19(pt: bytes) -> bytes:
    if len(pt) != 19:
        raise ValueError("WRAP plaintext must be 19 bytes")
    return pt + b"\x0d" * 13


def _hx(name: str) -> bytes:
    return bytes.fromhex((ROOT / name).read_text().strip())


def clear_cache() -> None:
    global _CACHE
    _CACHE = None


def _load_cache() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    meta = json.loads((ROOT / "_wrap_m416_meta.json").read_text(encoding="utf-8"))
    inner = parse_u(meta["inner"])
    ops = _hx("_wrap_m416_ops.hex")
    w109 = _hx("_wrap_m416_w109.hex")
    _CACHE = {
        "meta": meta,
        "inner": inner,
        "ops": ops,
        "w109": w109,
        "sbox": _hx("_wrap_m416_sbox.hex"),
        "jtab": _hx("_wrap_m416_jtab.hex"),
        "w109obj": _hx("_wrap_m416_w109obj.hex"),
        "ctxpage": _hx("_wrap_m416_ctxpage.hex"),
        "p159": _hx("_wrap_m416_p159.hex"),
        "p4": _hx("_wrap_m416_p4.hex"),
        "prog": parse_prog(ops, inner),
        "prog109": parse_prog(w109, parse_u(meta["w109_base"])),
    }
    return _CACHE


def wrap_encrypt_32(plaintext19: bytes, key: bytes = V34_WRAP_KEY, iv: bytes = V34_WRAP_IV) -> bytes:
    """Return mill-less WRAP ciphertext C0||C1 (32B) for a 19-byte source."""
    kind = ""
    kp = ROOT / "_wrap_mill_kind.txt"
    if kp.exists():
        kind = kp.read_text(encoding="utf-8").strip()
    if kind == "359":
        from _wrap_encrypt_359 import wrap_encrypt_32 as _w359
        return _w359(plaintext19, key=key, iv=iv)
    del key
    pad = _pkcs7_19(plaintext19)
    C = _load_cache()
    meta = C["meta"]
    inner = C["inner"]
    w109_base = parse_u(meta["w109_base"])
    w109_obj = parse_u(meta["w109_obj"])
    jtab = parse_u(meta["jtab"])
    p159 = parse_u(meta["p159"])
    p4 = parse_u(meta["p4"])
    sbox_p = parse_u(meta["sbox"])
    rf = [parse_u(x) for x in meta["rf"]]
    ctx, rk, work, ptd = rf[1], rf[8], rf[6], rf[5]

    E = WrapEmu()
    E.sess10n = int(meta.get("sess10n") or 0)
    E.map(inner, C["ops"])
    E.progs[inner] = (C["prog"], inner)
    E.map(w109_base, C["w109"])
    E.progs[w109_base] = (C["prog109"], w109_base)
    E.progs[w109_obj + 8] = E.progs[w109_base]
    E.map(w109_obj, C["w109obj"] + b"\0" * 64)
    E.map(jtab, C["jtab"] + b"\0" * 64)
    E.mem.store_u64(jtab + 109 * 8, w109_obj)
    E.map(sbox_p, C["sbox"])
    E.map(p159, C["p159"] + b"\0" * 64)
    E.map(p4, C["p4"] + b"\0" * 64)
    E.mem.store_u64(p159, jtab)
    E.mem.store_u64(p159 + 0x48, sbox_p)
    E.map(ctx & ~0xFFF, C["ctxpage"])
    # IV sits at RK+0xb0 (ctx+0x140); restore in case ctxpage is reused.
    E.map(rk + 0xB0, iv + b"\0" * 16)
    E.map(work, pad + b"\0" * 64)
    if rf[9] != work:
        E.map(rf[9], pad + b"\0" * 64)
    E.map(ptd, plaintext19 + b"\0" * 48)
    if rf[24] != ptd:
        E.map(rf[24], plaintext19 + b"\0" * 48)
    for i, v in enumerate(rf):
        E.W(i, v)
    E.run_prog(*E.progs[inner])
    return E.mem.load(work, 32)


def main() -> None:
    pairs = [
        (
            "8a07f6c557a78f4e585f592de7eb4c6af5f577",
            "777b75b4532dcdc3353dc95555793fb73ccd8c44372e2c97f060b5006efe2444",
        ),
        (
            "0ad3520846ce25ed7050c4af009021264189b1",
            "329400ac78c435b9a0a88276b3e1a347a0b1f30d54a015dec53db9b724e44e76",
        ),
        (
            "d20bc4bd62a520831097db15dfec7506e1a610",
            "ca6511af1a7ed1d4e3d46433629d511ad3a724924bdb5ba30911ec193e36fe7f",
        ),
    ]
    for pth, cth in pairs:
        pt, ct = bytes.fromhex(pth), bytes.fromhex(cth)
        got = wrap_encrypt_32(pt)
        print(("HIT" if got == ct else "miss"), pth[:16], got.hex())


if __name__ == "__main__":
    main()
