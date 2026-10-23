#!/usr/bin/env python3
"""Reduce mill6 src (290B) to WRAP 19B PT using the 114-op type-73 mill."""
from __future__ import annotations

import json
from pathlib import Path

from _emu_wrap_mill import WrapEmu, parse_prog, parse_u

ROOT = Path(__file__).resolve().parent


def mill6_pt19(src: bytes, meta: dict | None = None) -> bytes:
    if meta is None:
        meta = json.loads((ROOT / "_wrap_m6_meta.json").read_text(encoding="utf-8"))
    blob = bytes.fromhex((ROOT / "_wrap_pre6_full.hex").read_text().strip())
    base = parse_u(meta["inner"])
    rf = [parse_u(x) for x in meta["rf"]]
    src_p = rf[8]
    dest_p = rf[10]
    stack = rf[1]
    E = WrapEmu()
    E.map(base, blob)
    E.progs[base] = (parse_prog(blob, base), base)
    E.map(stack - 0x200, b"\0" * 0x800)
    E.map(src_p, src + b"\0" * 64)
    E.map(dest_p, b"\0" * 64)
    if rf[24] > 0x10000:
        E.map(rf[24], b"\0" * 48)
    for i, v in enumerate(rf):
        E.W(i, v)
    E.run_prog(*E.progs[base])
    return E.mem.load(dest_p, 19)


def main() -> None:
    evs = json.loads((ROOT / "_m4src_last.json").read_text(encoding="utf-8"))
    inn = next(e for e in evs if e.get("type") == "m6in")
    out = next(e for e in evs if e.get("type") == "m6out")
    meta = {
        "inner": inn["inner"],
        "rf": inn["rf"],
        "nops": 114,
    }
    (ROOT / "_wrap_m6_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    src = bytes.fromhex(inn["src"])
    live = bytes.fromhex(out["dest"])
    got = mill6_pt19(src, meta)
    print("got ", got.hex())
    print("live", live.hex())
    print("HIT" if got == live else "miss")


if __name__ == "__main__":
    main()
