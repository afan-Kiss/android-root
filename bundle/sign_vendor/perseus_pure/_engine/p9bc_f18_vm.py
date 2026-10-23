"""Pure F18 calculation from an explicit 48-byte runtime boundary.

The embedded program and handler tables are generated once from the verified
native lift. Runtime execution uses only the static tables and caller input.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from typing import Sequence

from .p9bc_f18_static import (
    F18_DYNAMIC_SIZE,
    F18_AUX_BLOBS,
    F18_ENTRY_HOLDER,
    F18_ENTRY_PROGRAM,
    F18_HANDLER_CODE,
    F18_IV,
    F18_PROGRAMS,
    F18_REGFILE_OFFSET,
    F18_REGFILE_SIZE,
    F18_RECORD_SIZE,
    F18_SLOT_BLOBS,
    F18_STATE_OFFSET,
    F18_SUFFIX,
    F18_WORKSPACE_BASE,
    F18_WORKSPACE_SIZE,
    F18_WORKSPACE_TEMPLATE,
    F18_ZERO_BLOBS,
)

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
HANDLER_TOKEN_BASE = 0x7F10000000
DISPATCH_BASE = 0x7F20000000
STACK_BASE = 0x7300000000
OUTPUT_OFFSET = 0x5FE0
NESTED_CALLS = {
    (42, 19, 0): 43,
    (42, 20, 0): 44,
    (42, 21, 0): 45,
    (45, 20, 0): 46,
    (45, 20, 1): 47,
    (47, 24, 0): 48,
    (42, 22, 0): 49,
}


class F18PureError(ValueError):
    """Raised when F18 runtime input is incomplete or execution diverges."""


@dataclass(frozen=True)
class F18RuntimeContext:
    """Dynamic state consumed by the recovered F18 chain."""

    dynamic48: bytes
    iv: bytes = F18_IV
    suffix: bytes = F18_SUFFIX

    def __post_init__(self) -> None:
        dynamic = bytes(self.dynamic48)
        iv = bytes(self.iv)
        suffix = bytes(self.suffix)
        if len(dynamic) != F18_DYNAMIC_SIZE:
            raise F18PureError(
                f"dynamic48 must contain exactly {F18_DYNAMIC_SIZE} bytes, got {len(dynamic)}"
            )
        if len(iv) != 16:
            raise F18PureError(f"iv must contain exactly 16 bytes, got {len(iv)}")
        if len(suffix) != 16:
            raise F18PureError(f"suffix must contain exactly 16 bytes, got {len(suffix)}")
        object.__setattr__(self, "dynamic48", dynamic)
        object.__setattr__(self, "iv", iv)
        object.__setattr__(self, "suffix", suffix)


@dataclass(frozen=True)
class F18RunResult:
    value20: bytes
    raw20: bytes
    steps: int
    return_value: int


def _u8(data: bytes, offset: int = 0) -> int:
    return data[offset]


def _u16(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _parse_imm(token: str) -> int:
    text = token.strip()
    if text.startswith("#"):
        text = text[1:]
    sign = -1 if text.startswith("-") else 1
    if text.startswith(("-", "+")):
        text = text[1:]
    return sign * int(text, 0)


def _split_operands(text: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return [item for item in result if item]


def _reg_index(name: str) -> int | None:
    match = re.fullmatch(r"[xw]([0-9]|[12][0-9]|3[01])", name.strip().lower())
    return int(match.group(1)) if match else None


def _reg_width(name: str) -> int:
    text = name.strip().lower()
    if text in {"wzr", "xzr"}:
        return 32 if text == "wzr" else 64
    return 32 if text.startswith("w") else 64


class _Memory:
    def __init__(self) -> None:
        self.ranges: list[tuple[int, bytearray, str]] = []

    def map(self, base: int, data: bytes | bytearray, name: str) -> None:
        self.ranges.append((int(base), bytearray(data), name))

    def _find(self, address: int, size: int) -> tuple[int, bytearray, str]:
        address &= MASK64
        for base, data, name in reversed(self.ranges):
            if base <= address and address + size <= base + len(data):
                return base, data, name
        raise F18PureError(f"F18 VM unmapped memory: 0x{address:x}+0x{size:x}")

    def read(self, address: int, size: int) -> bytes:
        base, data, _ = self._find(address, size)
        offset = address - base
        return bytes(data[offset : offset + size])

    def write(self, address: int, value: bytes) -> None:
        base, data, _ = self._find(address, len(value))
        offset = address - base
        data[offset : offset + len(value)] = value

    def read_u8(self, address: int) -> int:
        return _u8(self.read(address, 1))

    def read_u16(self, address: int) -> int:
        return _u16(self.read(address, 2))

    def read_u32(self, address: int) -> int:
        return _u32(self.read(address, 4))

    def read_u64(self, address: int) -> int:
        return _u64(self.read(address, 8))

    def read_s8(self, address: int) -> int:
        return _signed(self.read_u8(address), 8)

    def read_s16(self, address: int) -> int:
        return _signed(self.read_u16(address), 16)

    def read_s32(self, address: int) -> int:
        return _signed(self.read_u32(address), 32)

    def write_u8(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<B", value & 0xFF))

    def write_u16(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<H", value & 0xFFFF))

    def write_u32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value & MASK32))

    def write_u64(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<Q", value & MASK64))


class _F18Vm:
    def __init__(self, context: F18RuntimeContext) -> None:
        self.context = context
        self.memory = _Memory()
        self.x = [0] * 31
        self.sp = STACK_BASE + 0x8000
        self.flags = {"eq": False, "lt": False, "lo": False}
        self.entry_stack: list[int] = []
        self.outer_occurrences: dict[tuple[int, int], int] = {}
        self.steps = 0
        self.total_steps = 0
        self.halted = False
        self.return_value = 0
        self.prog_base = 0
        self.holder = 0
        self.current_idx: int | None = None
        self._map_memory()

    @property
    def workspace(self) -> int:
        return F18_WORKSPACE_BASE

    @property
    def state(self) -> int:
        return self.workspace + F18_STATE_OFFSET

    @property
    def regfile(self) -> int:
        return self.workspace + F18_REGFILE_OFFSET

    def _map_memory(self) -> None:
        template = bytes(F18_WORKSPACE_TEMPLATE)
        if len(template) != F18_WORKSPACE_SIZE:
            raise F18PureError(
                f"embedded F18 workspace has invalid size: 0x{len(template):x}"
            )
        self.memory.map(self.workspace, template, "workspace")
        self.memory.map(
            self.regfile,
            template[F18_REGFILE_OFFSET : F18_REGFILE_OFFSET + F18_REGFILE_SIZE],
            "regfile",
        )
        for pointer, blob in F18_SLOT_BLOBS.items():
            self.memory.map(pointer, blob, f"slot_{pointer:x}")
        for pointer, blob in F18_PROGRAMS.items():
            self.memory.map(pointer, blob, f"program_{pointer:x}")
        for pointer, blob in F18_AUX_BLOBS.items():
            self.memory.map(pointer, blob, f"aux_{pointer:x}")
        for pointer, blob in F18_ZERO_BLOBS.items():
            self.memory.map(pointer, blob, f"zero_{pointer:x}")
        for entry, holder in F18_ENTRY_HOLDER.items():
            self.memory.map(holder, b"\0" * 0x80, f"holder_{entry}")
        dispatch = bytearray(0x400 * 8)
        for index in range(0x400):
            struct.pack_into("<Q", dispatch, index * 8, HANDLER_TOKEN_BASE + index * 8)
        self.memory.map(DISPATCH_BASE, dispatch, "dispatch")
        self.memory.map(STACK_BASE - 0x10000, b"\0" * 0x20000, "stack")

    def _init_registers(self) -> None:
        self.x = [0] * 31
        self.sp = STACK_BASE + 0x8000
        self.x[0] = self.prog_base
        self.x[1] = self.workspace
        self.x[19] = self.workspace
        self.x[20] = self.holder
        self.x[23] = self.state
        self.x[24] = self.regfile
        self.x[25] = DISPATCH_BASE

    def _read_reg(self, name: str) -> int:
        text = name.strip().lower()
        if text in {"wzr", "xzr"}:
            return 0
        if text == "sp":
            return self.sp
        index = _reg_index(text)
        if index is None:
            raise F18PureError(f"unsupported F18 register: {name}")
        value = self.x[index]
        return value & (MASK32 if text.startswith("w") else MASK64)

    def _write_reg(self, name: str, value: int) -> None:
        text = name.strip().lower()
        if text in {"wzr", "xzr"}:
            return
        if text == "sp":
            self.sp = value & MASK64
            return
        index = _reg_index(text)
        if index is None:
            raise F18PureError(f"unsupported F18 register: {name}")
        self.x[index] = value & (MASK32 if text.startswith("w") else MASK64)

    def _parse_memory_operand(self, text: str) -> tuple[int, int, str]:
        match = re.fullmatch(r"\[(.*?)\](?:\s*,\s*(#[^,]+))?", text.strip())
        if not match:
            raise F18PureError(f"unsupported F18 memory operand: {text}")
        parts = [item.strip() for item in match.group(1).split(",")]
        base_name = parts[0]
        address = self._read_reg(base_name)
        index_name: str | None = None
        shift = 0
        immediate = 0
        for part in parts[1:]:
            if part.startswith("#"):
                immediate += _parse_imm(part)
            elif part.startswith("lsl"):
                shift = _parse_imm(part.split()[-1])
            elif part.startswith("uxtw"):
                shift = _parse_imm(part.split("#", 1)[1]) if "#" in part else 0
            else:
                index_name = part
        if index_name is not None:
            index_value = self._read_reg(index_name)
            if index_name.startswith("w") or any(part.startswith("uxtw") for part in parts[1:]):
                index_value &= MASK32
            address += index_value << shift
        address += immediate
        post = _parse_imm(match.group(2)) if match.group(2) else 0
        return address & MASK64, post, base_name

    def _load(self, mnemonic: str, destination: str, operand: str) -> None:
        address, post, base_name = self._parse_memory_operand(operand)
        if mnemonic == "ldrb":
            value = self.memory.read_u8(address)
        elif mnemonic == "ldrsb":
            value = self.memory.read_s8(address)
        elif mnemonic == "ldrh":
            value = self.memory.read_u16(address)
        elif mnemonic == "ldrsh":
            value = self.memory.read_s16(address)
        elif mnemonic == "ldrsw":
            value = self.memory.read_s32(address)
        elif mnemonic == "ldr":
            value = self.memory.read_u32(address) if destination.startswith("w") else self.memory.read_u64(address)
        else:
            raise F18PureError(f"unsupported F18 load: {mnemonic}")
        self._write_reg(destination, value)
        if post:
            self._write_reg(base_name, self._read_reg(base_name) + post)

    def _store(self, mnemonic: str, source: str, operand: str) -> None:
        address, post, base_name = self._parse_memory_operand(operand)
        value = self._read_reg(source)
        if mnemonic == "strb":
            self.memory.write_u8(address, value)
        elif mnemonic == "strh":
            self.memory.write_u16(address, value)
        elif mnemonic == "str":
            if source.startswith("w"):
                self.memory.write_u32(address, value)
            else:
                self.memory.write_u64(address, value)
        else:
            raise F18PureError(f"unsupported F18 store: {mnemonic}")
        if post:
            self._write_reg(base_name, self._read_reg(base_name) + post)

    def _operand_value(self, token: str, width: int) -> int:
        text = token.strip()
        if text.startswith("#"):
            return _parse_imm(text) & ((1 << width) - 1)
        return self._read_reg(text) & ((1 << width) - 1)

    def _cmp(self, left: str, right: str) -> None:
        width = _reg_width(left)
        a = self._operand_value(left, width)
        b = self._operand_value(right, width)
        self.flags["eq"] = a == b
        self.flags["lo"] = a < b
        self.flags["lt"] = _signed(a, width) < _signed(b, width)

    def _operand3(self, pointer: int, width: int = 3) -> tuple[int, int, int]:
        raw = self.memory.read(pointer, width)
        return raw[0], raw[1], raw[2]

    def _operand4(self, pointer: int) -> tuple[int, int, int]:
        raw = self.memory.read(pointer, 4)
        return raw[0], raw[1], _signed(_u16(raw, 2), 16)

    def _counter_helper(self, delta: int) -> None:
        self.memory.write_u32(self.state, self.memory.read_u32(self.state) + delta)
        self._write_reg("x0", 1)
        self._write_reg("x1", self.state)

    def _helper(self, target: int, record: int) -> None:
        rf = self.regfile
        if target == 0x3011B4:
            add = self._operand3(self.memory.read_u64(record))
            copy2 = self._operand3(self.memory.read_u64(record + 8))
            copy1 = self._operand3(self.memory.read_u64(record + 0x10))
            self.memory.write_u64(rf + copy1[2] * 8, self.memory.read_u64(rf + copy1[0] * 8))
            self.memory.write_u64(rf + copy2[2] * 8, self.memory.read_u64(rf + copy2[0] * 8))
            value = (self.memory.read_u32(rf + add[0] * 8) + self.memory.read_u32(rf + add[1] * 8)) & MASK32
            self.memory.write_u64(rf + add[2] * 8, _signed(value, 32))
            self._counter_helper(4)
            return
        if target == 0x304B08:
            merged = self._operand3(self.memory.read_u64(record + 8))
            immediate = self.memory.read(self.memory.read_u64(record), 4)
            self.memory.write_u64(rf + merged[2] * 8, self.memory.read_u64(rf + merged[0] * 8) | self.memory.read_u64(rf + merged[1] * 8))
            self.memory.write_u64(rf + immediate[1] * 8, _signed(_u16(immediate, 2), 16))
            self._counter_helper(3)
            return
        if target == 0x307524:
            load_a = self._operand4(self.memory.read_u64(record + 0x10))
            load_b = self._operand4(self.memory.read_u64(record + 8))
            store_c = self._operand4(self.memory.read_u64(record))
            self.memory.write_u64(rf + load_a[1] * 8, self.memory.read_u64(self.memory.read_u64(rf + load_a[0] * 8) + load_a[2]))
            self.memory.write_u64(rf + load_b[1] * 8, self.memory.read_u64(self.memory.read_u64(rf + load_b[0] * 8) + load_b[2]))
            self.memory.write_u32(self.memory.read_u64(rf + store_c[0] * 8) + store_c[2], self.memory.read_u64(rf + store_c[1] * 8))
            self._counter_helper(4)
            return
        if target == 0x307B50:
            copy = self._operand4(self.memory.read_u64(record + 0x18))
            load = self._operand4(self.memory.read_u64(record + 0x10))
            shift = self._operand4(self.memory.read_u64(record + 8))
            add = self._operand4(self.memory.read_u64(record))
            self.memory.write_u64(rf + copy[2] * 8, self.memory.read_u64(rf + copy[0] * 8))
            load_value = self.memory.read_s32(self.memory.read_u64(rf + load[0] * 8) + load[2])
            self.memory.write_u64(rf + load[1] * 8, load_value)
            value = (self.memory.read_u32(rf + shift[0] * 8) << (shift[2] & 31)) & MASK32
            self.memory.write_u64(rf + shift[1] * 8, _signed(value, 32))
            value = (self.memory.read_u32(rf + add[0] * 8) + self.memory.read_u32(rf + add[1] * 8)) & MASK32
            self.memory.write_u64(rf + add[2] * 8, _signed(value, 32))
            self._counter_helper(5)
            return
        if target == 0x2FFCCC:
            merged = self._operand3(self.memory.read_u64(record + 0x10))
            left_b = self._operand3(self.memory.read_u64(record + 8))
            left_a = self._operand3(self.memory.read_u64(record))
            self.memory.write_u64(rf + merged[2] * 8, self.memory.read_u64(rf + merged[0] * 8) | self.memory.read_u64(rf + merged[1] * 8))
            for operand in (left_b, left_a):
                value = (self.memory.read_u32(rf + operand[0] * 8) << (operand[2] & 31)) & MASK32
                self.memory.write_u64(rf + operand[1] * 8, _signed(value, 32))
            self._counter_helper(4)
            return
        if target == 0x305BF8:
            add32 = self._operand4(self.memory.read_u64(record + 8))
            add64 = self._operand4(self.memory.read_u64(record))
            value32 = (self.memory.read_u32(rf + add32[0] * 8) + add32[2]) & MASK32
            self.memory.write_u64(rf + add32[1] * 8, _signed(value32, 32))
            value64 = (self.memory.read_u64(rf + add64[0] * 8) + add64[2]) & MASK64
            self.memory.write_u64(rf + add64[1] * 8, value64)
            self._counter_helper(3)
            return
        if target == 0x308090:
            store = self._operand4(self.memory.read_u64(record + 8))
            load = self._operand4(self.memory.read_u64(record))
            self.memory.write_u32(self.memory.read_u64(rf + store[0] * 8) + store[2], self.memory.read_u32(rf + store[1] * 8))
            load_value = self.memory.read_s32(self.memory.read_u64(rf + load[0] * 8) + load[2])
            self.memory.write_u64(rf + load[1] * 8, load_value)
            self._counter_helper(3)
            return
        if target == 0x302FA8:
            load_raw = self.memory.read(self.memory.read_u64(record + 0x18), 4)
            load = (load_raw[0], load_raw[1], _signed(_u16(load_raw, 2), 16))
            left_b = self._operand4(self.memory.read_u64(record + 0x10))
            merged = self._operand4(self.memory.read_u64(record + 8))
            left_a = self._operand4(self.memory.read_u64(record))
            load_value = self.memory.read_s32(self.memory.read_u64(rf + load[0] * 8) + load[2])
            self.memory.write_u64(rf + load[1] * 8, load_value)
            for operand in (left_b, left_a):
                value = (self.memory.read_u32(rf + operand[0] * 8) << (operand[2] & 31)) & MASK32
                self.memory.write_u64(rf + operand[1] * 8, _signed(value, 32))
            self.memory.write_u64(rf + merged[2] * 8, self.memory.read_u64(rf + merged[0] * 8) | self.memory.read_u64(rf + merged[1] * 8))
            self._counter_helper(5)
            return
        if target == 0x303838:
            immediate = self.memory.read_u64(record)
            add = self._operand3(self.memory.read_u64(record + 8))
            xor = self._operand3(self.memory.read_u64(record + 0x10))
            self.memory.write_u64(rf + xor[2] * 8, self.memory.read_u64(rf + xor[0] * 8) ^ self.memory.read_u64(rf + xor[1] * 8))
            value = (self.memory.read_u32(rf + add[0] * 8) + self.memory.read_u32(rf + add[1] * 8)) & MASK32
            self.memory.write_u64(rf + add[2] * 8, _signed(value, 32))
            dest = self.memory.read_u8(immediate + 1)
            value = (self.memory.read_u16(immediate + 2) << 16) & MASK32
            self.memory.write_u64(rf + dest * 8, _signed(value, 32))
            self._counter_helper(4)
            return
        if target == 0x305088:
            immediate = self.memory.read_u64(record)
            xor = self._operand3(self.memory.read_u64(record + 8))
            self.memory.write_u64(rf + xor[2] * 8, self.memory.read_u64(rf + xor[0] * 8) ^ self.memory.read_u64(rf + xor[1] * 8))
            source = self.memory.read_u8(immediate)
            dest = self.memory.read_u8(immediate + 1)
            self.memory.write_u64(rf + dest * 8, self.memory.read_u64(rf + source * 8) | self.memory.read_u16(immediate + 2))
            self._counter_helper(3)
            return
        if target in {0x2FFF50, 0x302A78}:
            xor_first = target == 0x302A78
            xor = self._operand3(self.memory.read_u64(record))
            add = self._operand3(self.memory.read_u64(record + 8))
            rotate = self._operand3(self.memory.read_u64(record + 0x10))
            source = self.memory.read_u32(rf + rotate[0] * 8)
            count = rotate[2] & 31
            rotated = source if count == 0 else ((source >> count) | (source << (32 - count))) & MASK32
            self.memory.write_u64(rf + rotate[1] * 8, rotated)
            value = (self.memory.read_u32(rf + add[0] * 8) + self.memory.read_u32(rf + add[1] * 8)) & MASK32
            self.memory.write_u64(rf + add[2] * 8, _signed(value, 32))
            if xor_first:
                value64 = self.memory.read_u64(rf + xor[0] * 8) ^ self.memory.read_u64(rf + xor[1] * 8)
            else:
                value64 = self.memory.read_u64(rf + xor[0] * 8) & self.memory.read_u64(rf + xor[1] * 8)
            self.memory.write_u64(rf + xor[2] * 8, value64)
            self._counter_helper(4)
            return
        if target == 0x303F04:
            immediate = self.memory.read_u64(record)
            add_a = self._operand3(self.memory.read_u64(record + 8))
            add_b = self._operand3(self.memory.read_u64(record + 0x10))
            for operand in (add_b, add_a):
                value = (self.memory.read_u32(rf + operand[0] * 8) + self.memory.read_u32(rf + operand[1] * 8)) & MASK32
                self.memory.write_u64(rf + operand[2] * 8, _signed(value, 32))
            dest = self.memory.read_u8(immediate + 1)
            value = (self.memory.read_u16(immediate + 2) << 16) & MASK32
            self.memory.write_u64(rf + dest * 8, _signed(value, 32))
            self._counter_helper(4)
            return
        if target == 0x3072E0:
            load_ptr = self.memory.read_u64(record)
            immediate = self.memory.read_u64(record + 8)
            load_raw = self.memory.read(load_ptr, 4)
            dest = self.memory.read_u8(immediate + 1)
            value = (self.memory.read_u16(immediate + 2) << 16) & MASK32
            self.memory.write_u64(rf + dest * 8, _signed(value, 32))
            source = load_raw[0]
            load_dest = load_raw[1]
            offset = _signed(_u16(load_raw, 2), 16)
            self.memory.write_u64(rf + load_dest * 8, self.memory.read_u64(self.memory.read_u64(rf + source * 8) + offset))
            self._counter_helper(3)
            return
        if target == 0x301730:
            or_op = self._operand3(self.memory.read_u64(record))
            add = self._operand3(self.memory.read_u64(record + 8))
            load_raw = self.memory.read(self.memory.read_u64(record + 0x10), 4)
            source = load_raw[0]
            dest = load_raw[1]
            offset = _signed(_u16(load_raw, 2), 16)
            self.memory.write_u64(rf + dest * 8, self.memory.read_s32(self.memory.read_u64(rf + source * 8) + offset))
            value = (self.memory.read_u32(rf + add[0] * 8) + self.memory.read_u32(rf + add[1] * 8)) & MASK32
            self.memory.write_u64(rf + add[2] * 8, _signed(value, 32))
            self.memory.write_u64(rf + or_op[2] * 8, self.memory.read_u64(rf + or_op[0] * 8) | self.memory.read_u64(rf + or_op[1] * 8))
            self._counter_helper(4)
            return
        if target == 0x30314C:
            copy_a = self._operand3(self.memory.read_u64(record + 0x18))
            copy_b = self._operand3(self.memory.read_u64(record + 0x10))
            self.memory.write_u64(rf + copy_a[2] * 8, self.memory.read_u64(rf + copy_a[0] * 8))
            self.memory.write_u64(rf + copy_b[2] * 8, self.memory.read_u64(rf + copy_b[0] * 8))
            dispatch_a = self.memory.read_u64(record + 8)
            dispatch_b = self.memory.read_u64(record)
            self._outer_dispatch(dispatch_a + 8, self.workspace, self.memory.read_u32(dispatch_a))
            self._outer_dispatch(dispatch_b + 8, self.workspace, self.memory.read_u32(dispatch_b))
            self._counter_helper(2)
            return
        if target == 0x301D4C:
            for offset in (0x18, 0x10, 0x08):
                operand = self._operand3(self.memory.read_u64(record + offset))
                self.memory.write_u64(rf + operand[2] * 8, self.memory.read_u64(rf + operand[0] * 8))
            dispatch = self.memory.read_u64(record)
            self._outer_dispatch(dispatch + 8, self.workspace, self.memory.read_u32(dispatch))
            self._counter_helper(5)
            return
        if target == 0x304140:
            self._counter_helper(3)
            return
        raise F18PureError(f"unsupported F18 helper: 0x{target:x}")

    def _outer_dispatch(self, arg_ptr: int, workspace: int, op_index: int) -> int:
        current_index = self.memory.read_u8(workspace)
        state_value = self.memory.read_u32(workspace + F18_STATE_OFFSET)
        self.memory.write_u64(self.regfile + current_index * 8, state_value)

        if op_index == 16:
            destination = self.memory.read_u64(self.regfile + 8 * 8)
            source = self.memory.read_u64(self.regfile + 9 * 8)
            length = self.memory.read_u64(self.regfile + 10 * 8)
            if destination == 0 or length > 0x10000:
                raise F18PureError("invalid F18 memcpy operands")
            if self.entry_stack and self.entry_stack[-1] == 44 and length == F18_DYNAMIC_SIZE:
                copied = self.context.dynamic48
            else:
                copied = self.memory.read(source, length)
            self.memory.write(destination, copied)
            self.memory.write_u64(self.regfile + 6 * 8, destination)

        if self.entry_stack:
            entry = self.entry_stack[-1]
            key = (entry, op_index)
            occurrence = self.outer_occurrences.get(key, 0)
            self.outer_occurrences[key] = occurrence + 1
            child = NESTED_CALLS.get((entry, op_index, occurrence))
            if child is not None:
                return self._run_entry(child)
        return 0

    def _execute(self, mnemonic: str, op_str: str) -> int | None:
        operands = _split_operands(op_str)
        if mnemonic == "nop":
            return None
        if mnemonic in {"ldr", "ldrb", "ldrsb", "ldrh", "ldrsh", "ldrsw"}:
            self._load(mnemonic, operands[0], operands[1])
            return None
        if mnemonic in {"str", "strb", "strh"}:
            self._store(mnemonic, operands[0], operands[1])
            return None
        if mnemonic == "ldp":
            left, right, memory = operands
            address, post, base_name = self._parse_memory_operand(memory)
            self._write_reg(left, self.memory.read_u64(address))
            self._write_reg(right, self.memory.read_u64(address + 8))
            if post:
                self._write_reg(base_name, self._read_reg(base_name) + post)
            return None
        if mnemonic == "mov":
            self._write_reg(operands[0], self._operand_value(operands[1], _reg_width(operands[0])))
            return None
        if mnemonic == "movk":
            destination, source = operands[0], operands[1]
            shift = _parse_imm(operands[2].split("#", 1)[1]) if len(operands) > 2 else 0
            current = self._read_reg(destination)
            current = (current & ~(0xFFFF << shift)) | ((_parse_imm(source) & 0xFFFF) << shift)
            self._write_reg(destination, current)
            return None
        if mnemonic in {"add", "sub"}:
            destination, left, right = operands[:3]
            width = _reg_width(destination)
            value = self._operand_value(left, width)
            rhs = self._operand_value(right, width)
            if len(operands) > 3:
                rhs <<= _parse_imm(operands[3].split("#", 1)[1])
            self._write_reg(destination, value + rhs if mnemonic == "add" else value - rhs)
            return None
        if mnemonic in {"and", "orr", "eor"}:
            destination, left, right = operands
            width = _reg_width(destination)
            a = self._operand_value(left, width)
            b = self._operand_value(right, width)
            value = {"and": a & b, "orr": a | b, "eor": a ^ b}[mnemonic]
            self._write_reg(destination, value)
            return None
        if mnemonic in {"lsl", "lsr", "ror"}:
            destination, source, count = operands
            width = _reg_width(destination)
            value = self._operand_value(source, width)
            shift = self._operand_value(count, width) & (31 if width == 32 else 63)
            if mnemonic == "lsl":
                value <<= shift
            elif mnemonic == "lsr":
                value >>= shift
            elif shift:
                value = (value >> shift) | (value << (width - shift))
            self._write_reg(destination, value)
            return None
        if mnemonic == "bfi":
            destination, source, lsb_token, width_token = operands
            lsb = _parse_imm(lsb_token)
            width = _parse_imm(width_token)
            mask = ((1 << width) - 1) << lsb
            current = self._read_reg(destination) & MASK32
            value = self._read_reg(source) & MASK32
            self._write_reg(destination, (current & ~mask) | ((value << lsb) & mask))
            return None
        if mnemonic == "ubfx":
            destination, source, lsb_token, width_token = operands
            lsb = _parse_imm(lsb_token)
            width = _parse_imm(width_token)
            self._write_reg(destination, (self._read_reg(source) >> lsb) & ((1 << width) - 1))
            return None
        if mnemonic == "sxtw":
            self._write_reg(operands[0], _signed(self._read_reg(operands[1]), 32))
            return None
        if mnemonic == "mvn":
            destination, source = operands
            width = _reg_width(destination)
            self._write_reg(destination, ~self._operand_value(source, width))
            return None
        if mnemonic == "cmp":
            self._cmp(operands[0], operands[1])
            return None
        if mnemonic == "cset":
            self._write_reg(operands[0], 1 if self.flags[operands[1].strip().lower()] else 0)
            return None
        if mnemonic == "csel":
            destination, true_value, false_value, condition = operands
            selected = true_value if self.flags[condition.strip().lower()] else false_value
            self._write_reg(destination, self._read_reg(selected))
            return None
        if mnemonic == "smaddl":
            destination, left, right, addend = operands
            value = _signed(self._read_reg(left), 32) * _signed(self._read_reg(right), 32) + self._read_reg(addend)
            self._write_reg(destination, value)
            return None
        if mnemonic == "bl":
            target = _parse_imm(operands[0])
            if target == 0x442E84:
                self._write_reg("x0", self._outer_dispatch(self._read_reg("x0"), self._read_reg("x1"), self._read_reg("w2")))
            else:
                self._helper(target, self._read_reg("x0"))
            return None
        if mnemonic == "br":
            token = self._read_reg(operands[0])
            if not HANDLER_TOKEN_BASE <= token < HANDLER_TOKEN_BASE + 0x400 * 8 or token % 8:
                raise F18PureError(f"unresolved F18 handler target: 0x{token:x}")
            return (token - HANDLER_TOKEN_BASE) // 8
        if mnemonic == "ret":
            self.halted = True
            return None
        raise F18PureError(f"unsupported F18 instruction: {mnemonic} {op_str}")

    def _run_entry(self, entry: int) -> int:
        saved = (
            self.x,
            self.sp,
            self.flags,
            self.prog_base,
            self.holder,
            self.halted,
            self.return_value,
            self.current_idx,
            self.steps,
        )
        self.entry_stack.append(entry)
        self.prog_base = F18_ENTRY_PROGRAM[entry]
        self.holder = F18_ENTRY_HOLDER[entry]
        self.memory.write_u64(self.holder, self.prog_base)
        self.halted = False
        self.return_value = 0
        self.current_idx = None
        self.steps = 0
        self.flags = {"eq": False, "lt": False, "lo": False}
        self._init_registers()
        self.memory.write_u32(self.state, 0)
        while not self.halted and self.steps < 12000:
            self._step()
        if not self.halted:
            raise F18PureError(f"F18 entry {entry} exceeded step limit")
        result = self.return_value
        self.entry_stack.pop()
        (
            self.x,
            self.sp,
            self.flags,
            self.prog_base,
            self.holder,
            self.halted,
            self.return_value,
            self.current_idx,
            self.steps,
        ) = saved
        return result

    def _step(self) -> None:
        record = self.x[0] & MASK64
        raw = self.memory.read(record, F18_RECORD_SIZE)
        handler = _u64(raw, 0x28)
        self.current_idx = handler
        if handler == 0xBD:
            source = _u8(raw)
            self.return_value = self.memory.read_u64(self.regfile + source * 8) & MASK32
            self.memory.write_u32(self.state, self.return_value)
            self.halted = True
            self.steps += 1
            self.total_steps += 1
            return
        code = F18_HANDLER_CODE.get(handler)
        if code is None:
            raise F18PureError(f"missing embedded F18 handler: 0x{handler:x}")
        next_handler: int | None = None
        for mnemonic, op_str in code:
            next_handler = self._execute(mnemonic, op_str)
            if next_handler is not None or self.halted:
                break
        if next_handler is None and not self.halted:
            raise F18PureError(f"F18 handler 0x{handler:x} did not dispatch")
        if not self.halted:
            next_record = self.x[0] & MASK64
            if not self.prog_base <= next_record < self.prog_base + len(F18_PROGRAMS[self.prog_base]):
                raise F18PureError(f"F18 handler produced invalid record pointer: 0x{next_record:x}")
        self.steps += 1
        self.total_steps += 1

    def run(self) -> None:
        result = self._run_entry(42)
        if result != 0x18:
            raise F18PureError(f"unexpected F18 root return: 0x{result:x}")
        self.return_value = result

    def raw20(self) -> bytes:
        return self.memory.read(self.workspace + OUTPUT_OFFSET, 20)


def _apply_outer_byte_adjustment(raw20: bytes, dynamic48: bytes) -> bytes:
    """Native FIELD_SER last byte is raw[-1] XOR 1 (P2333 live 15/15).

    The older signed(d48[4:8]) ±1 rule coincides with XOR 1 on the gold
    vectors (raw LSB matches the sign bit) but misses live wraps.
    """
    del dynamic48
    result = bytearray(raw20)
    result[-1] ^= 1
    return bytes(result)


def run_f18_pure(context: F18RuntimeContext) -> F18RunResult:
    vm = _F18Vm(context)
    vm.run()
    raw = vm.raw20()
    value = _apply_outer_byte_adjustment(raw, context.dynamic48)
    return F18RunResult(
        value20=value,
        raw20=raw,
        steps=vm.total_steps,
        return_value=vm.return_value,
    )


def generate_f18_pure(context: F18RuntimeContext) -> bytes:
    return run_f18_pure(context).value20


__all__ = [
    "F18PureError",
    "F18RuntimeContext",
    "F18RunResult",
    "generate_f18_pure",
    "run_f18_pure",
]
