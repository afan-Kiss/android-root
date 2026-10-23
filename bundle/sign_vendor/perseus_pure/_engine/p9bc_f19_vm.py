"""Pure F19 VM execution from explicit runtime state.

The program and handler semantics are fixed constants. Runtime memory is
rebased into synthetic ranges so captured native addresses never become part
of the result.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from typing import Sequence

from .p9bc_f19_static import (
    F19_HANDLER_CODE,
    F19_PROGRAM2_BYTES,
    F19_PROGRAM2_ORIGINAL_BASE,
    F19_RECORD_COUNT,
    F19_RECORD_SIZE,
)

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
PROGRAM_BASE = 0x100000
WORKSPACE_BASE = 0x200000
REGFILE_BASE = 0x300000
HOLDER_BASE = 0x400000
DISPATCH_BASE = 0x500000
HANDLER_TOKEN_BASE = 0x600000
WORKSPACE_SIZE = 0x7000
REGFILE_SIZE = 0x800
TABLE_OFFSET = 0x50C8
TABLE_SIZE = 0x390
SOURCE_BUFFER_OFFSET = 0x5688
SOURCE_OFFSET = 0x5690
SOURCE_SIZE = 32
SOURCE_REGION_SIZE = 0x60


class F19PureError(ValueError):
    """Raised when F19 runtime state is incomplete or inconsistent."""


@dataclass(frozen=True)
class F19RuntimeContext:
    """Dynamic state consumed by the final F19 VM program.

    ``regfile_slots`` are the initial 64-bit slots 0..29. If the slots still
    contain native pointers, provide the corresponding runtime bases so the
    VM can rebase them. A caller may instead provide already-normalized slot
    values using the synthetic ranges documented by this module.
    """

    workspace_table: bytes
    source_region: bytes
    regfile_slots: Sequence[int]
    workspace_base: int | None = None
    regfile_base: int | None = None
    program_base: int | None = None

    def __post_init__(self) -> None:
        table = bytes(self.workspace_table)
        source = bytes(self.source_region)
        slots = tuple(int(value) & MASK64 for value in self.regfile_slots)
        if len(table) < 0x378:
            raise F19PureError(
                f"workspace_table must contain at least 0x378 bytes, got 0x{len(table):x}"
            )
        if len(source) < SOURCE_REGION_SIZE:
            raise F19PureError(
                f"source_region must contain at least 0x{SOURCE_REGION_SIZE:x} bytes, got 0x{len(source):x}"
            )
        if len(slots) < 30:
            raise F19PureError(f"regfile_slots must contain at least 30 values, got {len(slots)}")
        object.__setattr__(self, "workspace_table", table[:TABLE_SIZE].ljust(TABLE_SIZE, b"\0"))
        object.__setattr__(self, "source_region", source[:SOURCE_REGION_SIZE])
        object.__setattr__(self, "regfile_slots", slots[:30])

    @property
    def source32(self) -> bytes:
        return self.source_region[:SOURCE_SIZE]


@dataclass(frozen=True)
class F19RunResult:
    serialized: bytes
    source32_after: bytes
    steps: int
    return_value: int


def _u8(data: bytes | bytearray, offset: int = 0) -> int:
    return data[offset]


def _u16(data: bytes | bytearray, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes | bytearray, offset: int = 0) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _parse_imm(token: str) -> int:
    token = token.strip()
    if token.startswith("#"):
        token = token[1:]
    sign = -1 if token.startswith("-") else 1
    if token.startswith(("-", "+")):
        token = token[1:]
    return sign * int(token, 0)


def _split_operands(text: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for position, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:position].strip())
            start = position + 1
    result.append(text[start:].strip())
    return [item for item in result if item]


def _reg_index(name: str) -> int | None:
    match = re.fullmatch(r"[xw]([0-9]|[12][0-9]|3[01])", name.strip().lower())
    return int(match.group(1)) if match else None


def _reg_width(name: str) -> int:
    name = name.strip().lower()
    if name in {"wzr", "xzr"}:
        return 32 if name == "wzr" else 64
    return 32 if name.startswith("w") else 64


class _Memory:
    def __init__(self) -> None:
        self.ranges: list[tuple[int, bytearray, str]] = []

    def map(self, base: int, data: bytes | bytearray, name: str) -> None:
        self.ranges.append((base, bytearray(data), name))

    def _find(self, address: int, size: int) -> tuple[int, bytearray, str]:
        address &= MASK64
        for base, data, name in reversed(self.ranges):
            if base <= address and address + size <= base + len(data):
                return base, data, name
        raise F19PureError(f"F19 VM unmapped memory: 0x{address:x}+0x{size:x}")

    def read(self, address: int, size: int) -> bytes:
        base, data, _ = self._find(address, size)
        offset = (address & MASK64) - base
        return bytes(data[offset : offset + size])

    def write(self, address: int, value: bytes) -> None:
        base, data, _ = self._find(address, len(value))
        offset = (address & MASK64) - base
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

    def write_u32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value & MASK32))

    def write_u64(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<Q", value & MASK64))


class _F19Vm:
    def __init__(self, context: F19RuntimeContext) -> None:
        self.context = context
        self.memory = _Memory()
        self.x = [0] * 31
        self.flags = {"eq": False, "lt": False, "lo": False}
        self.steps = 0
        self.halted = False
        self.return_value = 0
        self.program = self._relocated_program()
        self._map_memory()
        self._init_registers()

    def _relocated_program(self) -> bytes:
        program = bytearray(F19_PROGRAM2_BYTES)
        original_start = F19_PROGRAM2_ORIGINAL_BASE
        original_end = original_start + len(program)
        for offset in range(0, len(program), 8):
            value = _u64(program, offset)
            if original_start <= value < original_end:
                struct.pack_into(
                    "<Q", program, offset, PROGRAM_BASE + value - original_start
                )
        return bytes(program)

    def _rebase_slot(self, value: int) -> int:
        if self.context.workspace_base is not None:
            start = int(self.context.workspace_base)
            if start <= value < start + WORKSPACE_SIZE:
                return WORKSPACE_BASE + value - start
        if self.context.regfile_base is not None:
            start = int(self.context.regfile_base)
            if start <= value < start + REGFILE_SIZE:
                return REGFILE_BASE + value - start
        if self.context.program_base is not None:
            start = int(self.context.program_base)
            if start <= value < start + len(self.program):
                return PROGRAM_BASE + value - start
        return value & MASK64

    def _map_memory(self) -> None:
        workspace = bytearray(WORKSPACE_SIZE)
        table = bytearray(self.context.workspace_table)
        for offset in range(0, len(table) - 7, 8):
            value = _u64(table, offset)
            rebased = self._rebase_slot(value)
            if rebased != value:
                struct.pack_into("<Q", table, offset, rebased)
        workspace[TABLE_OFFSET : TABLE_OFFSET + TABLE_SIZE] = table
        workspace[SOURCE_OFFSET : SOURCE_OFFSET + SOURCE_REGION_SIZE] = self.context.source_region
        self.memory.map(PROGRAM_BASE, self.program, "program")
        self.memory.map(WORKSPACE_BASE, workspace, "workspace")
        self.memory.map(REGFILE_BASE, b"\0" * REGFILE_SIZE, "regfile")
        self.memory.map(HOLDER_BASE, struct.pack("<Q", PROGRAM_BASE), "holder")
        self.memory.map(DISPATCH_BASE, b"\0" * (0x400 * 8), "dispatch")

        for index, value in enumerate(self.context.regfile_slots):
            self.memory.write_u64(REGFILE_BASE + index * 8, self._rebase_slot(value))
        for index in range(0x400):
            self.memory.write_u64(
                DISPATCH_BASE + index * 8,
                HANDLER_TOKEN_BASE + index * 8,
            )
        self.memory.write_u32(WORKSPACE_BASE + 0xC, 0)

    def _init_registers(self) -> None:
        self.x[0] = PROGRAM_BASE
        self.x[1] = WORKSPACE_BASE
        self.x[19] = WORKSPACE_BASE
        self.x[20] = HOLDER_BASE
        self.x[23] = WORKSPACE_BASE + 0xC
        self.x[24] = REGFILE_BASE
        self.x[25] = DISPATCH_BASE

    def _read_reg(self, name: str) -> int:
        name = name.strip().lower()
        if name in {"wzr", "xzr"}:
            return 0
        if name == "sp":
            return 0
        index = _reg_index(name)
        if index is None:
            raise F19PureError(f"unsupported F19 register: {name}")
        value = self.x[index]
        return value & (MASK32 if name.startswith("w") else MASK64)

    def _write_reg(self, name: str, value: int) -> None:
        name = name.strip().lower()
        if name in {"wzr", "xzr"}:
            return
        if name == "sp":
            return
        index = _reg_index(name)
        if index is None:
            raise F19PureError(f"unsupported F19 register: {name}")
        self.x[index] = value & (MASK32 if name.startswith("w") else MASK64)

    def _parse_memory_operand(self, text: str) -> tuple[int, int, str]:
        match = re.fullmatch(r"\[(.*?)\](?:\s*,\s*(#[^,]+))?", text.strip())
        if not match:
            raise F19PureError(f"unsupported F19 memory operand: {text}")
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
            raise F19PureError(f"unsupported F19 load: {mnemonic}")
        self._write_reg(destination, value)
        if post:
            self._write_reg(base_name, self._read_reg(base_name) + post)

    def _store(self, mnemonic: str, source: str, operand: str) -> None:
        address, post, base_name = self._parse_memory_operand(operand)
        value = self._read_reg(source)
        if mnemonic == "strb":
            self.memory.write(address, bytes((value & 0xFF,)))
        elif mnemonic == "strh":
            self.memory.write(address, struct.pack("<H", value & 0xFFFF))
        elif mnemonic == "str":
            if source.startswith("w"):
                self.memory.write(address, struct.pack("<I", value & MASK32))
            else:
                self.memory.write(address, struct.pack("<Q", value & MASK64))
        else:
            raise F19PureError(f"unsupported F19 store: {mnemonic}")
        if post:
            self._write_reg(base_name, self._read_reg(base_name) + post)

    def _operand_value(self, token: str, width: int) -> int:
        token = token.strip()
        if token.startswith("#"):
            return _parse_imm(token) & ((1 << width) - 1)
        return self._read_reg(token) & ((1 << width) - 1)

    def _cmp(self, left: str, right: str) -> None:
        width = _reg_width(left)
        a = self._operand_value(left, width)
        b = self._operand_value(right, width)
        self.flags["eq"] = a == b
        self.flags["lo"] = a < b
        self.flags["lt"] = _signed(a, width) < _signed(b, width)

    def _helper_3011b4(self, record: int) -> None:
        def operand(pointer: int) -> tuple[int, int, int]:
            raw = self.memory.read(pointer, 3)
            return raw[0], raw[1], raw[2]

        add_src, add_mid, add_dst = operand(self.memory.read_u64(record))
        copy2_src, _, copy2_dst = operand(self.memory.read_u64(record + 8))
        copy1_src, _, copy1_dst = operand(self.memory.read_u64(record + 0x10))
        self.memory.write_u64(REGFILE_BASE + copy1_dst * 8, self.memory.read_u64(REGFILE_BASE + copy1_src * 8))
        self.memory.write_u64(REGFILE_BASE + copy2_dst * 8, self.memory.read_u64(REGFILE_BASE + copy2_src * 8))
        value = (self.memory.read_u32(REGFILE_BASE + add_src * 8) + self.memory.read_u32(REGFILE_BASE + add_mid * 8)) & MASK32
        self.memory.write_u64(REGFILE_BASE + add_dst * 8, _signed(value, 32) & MASK64)
        self.memory.write_u32(WORKSPACE_BASE + 0xC, self.memory.read_u32(WORKSPACE_BASE + 0xC) + 4)
        self.x[0] = 1
        self.x[1] = WORKSPACE_BASE + 0xC

    def _helper_304b08(self, record: int) -> None:
        operand_or = self.memory.read(self.memory.read_u64(record + 8), 3)
        source0, source1, destination = operand_or
        merged = self.memory.read_u64(REGFILE_BASE + source0 * 8) | self.memory.read_u64(REGFILE_BASE + source1 * 8)
        self.memory.write_u64(REGFILE_BASE + destination * 8, merged)
        immediate = self.memory.read(self.memory.read_u64(record), 4)
        self.memory.write_u64(
            REGFILE_BASE + immediate[1] * 8,
            _signed(_u16(immediate, 2), 16) & MASK64,
        )
        self.memory.write_u32(WORKSPACE_BASE + 0xC, self.memory.read_u32(WORKSPACE_BASE + 0xC) + 3)
        self.x[0] = 1
        self.x[1] = WORKSPACE_BASE + 0xC

    def _helper_307524(self, record: int) -> None:
        def operand(pointer: int) -> tuple[int, int, int]:
            raw = self.memory.read(pointer, 4)
            return raw[0], raw[1], _signed(_u16(raw, 2), 16)

        load_a = operand(self.memory.read_u64(record + 0x10))
        load_b = operand(self.memory.read_u64(record + 8))
        store_c = operand(self.memory.read_u64(record))
        a_base = self.memory.read_u64(REGFILE_BASE + load_a[0] * 8)
        b_base = self.memory.read_u64(REGFILE_BASE + load_b[0] * 8)
        self.memory.write_u64(REGFILE_BASE + load_a[1] * 8, self.memory.read_u64(a_base + load_a[2]))
        self.memory.write_u64(REGFILE_BASE + load_b[1] * 8, self.memory.read_u64(b_base + load_b[2]))
        c_base = self.memory.read_u64(REGFILE_BASE + store_c[0] * 8)
        c_source = self.memory.read_u64(REGFILE_BASE + store_c[1] * 8)
        self.memory.write(c_base + store_c[2], struct.pack("<I", c_source & MASK32))
        self.memory.write_u32(WORKSPACE_BASE + 0xC, self.memory.read_u32(WORKSPACE_BASE + 0xC) + 4)
        self.x[0] = 1
        self.x[1] = WORKSPACE_BASE + 0xC

    def _helper(self, target: int, record: int) -> None:
        if target == 0x3011B4:
            self._helper_3011b4(record)
        elif target == 0x304B08:
            self._helper_304b08(record)
        elif target == 0x307524:
            self._helper_307524(record)
        else:
            raise F19PureError(f"unsupported F19 native helper: 0x{target:x}")

    def _execute(self, mnemonic: str, op_str: str, handler: int) -> int | None:
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
            left_value = self._operand_value(left, width)
            right_value = self._operand_value(right, width)
            value = {"and": left_value & right_value, "orr": left_value | right_value, "eor": left_value ^ right_value}[mnemonic]
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
            destination, condition = operands
            self._write_reg(destination, 1 if self.flags[condition.strip().lower()] else 0)
            return None
        if mnemonic == "csel":
            destination, true_value, false_value, condition = operands
            selected = true_value if self.flags[condition.strip().lower()] else false_value
            self._write_reg(destination, self._read_reg(selected))
            return None
        if mnemonic == "sdiv":
            destination, left, right = operands
            a = _signed(self._read_reg(left), 64)
            b = _signed(self._read_reg(right), 64)
            value = 0 if b == 0 else (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
            self._write_reg(destination, value)
            return None
        if mnemonic == "msub":
            destination, left, right, addend = operands
            self._write_reg(destination, self._read_reg(addend) - self._read_reg(left) * self._read_reg(right))
            return None
        if mnemonic == "smaddl":
            destination, left, right, addend = operands
            value = _signed(self._read_reg(left), 32) * _signed(self._read_reg(right), 32) + self._read_reg(addend)
            self._write_reg(destination, value)
            return None
        if mnemonic == "bl":
            self._helper(_parse_imm(operands[0]), self.x[0])
            return None
        if mnemonic == "br":
            token = self._read_reg(operands[0])
            if not HANDLER_TOKEN_BASE <= token < HANDLER_TOKEN_BASE + 0x400 * 8 or token % 8:
                raise F19PureError(f"unresolved F19 handler target: 0x{token:x}")
            next_handler = (token - HANDLER_TOKEN_BASE) // 8
            return next_handler
        if mnemonic == "ret":
            self.halted = True
            return None
        raise F19PureError(f"unsupported F19 handler 0x{handler:x}: {mnemonic} {op_str}")

    def step(self) -> None:
        record = self.x[0] & MASK64
        raw = self.memory.read(record, F19_RECORD_SIZE)
        handler = _u64(raw, 0x28)
        if handler == 0xBD:
            source_slot = _u8(raw)
            self.return_value = self.memory.read_u64(REGFILE_BASE + source_slot * 8) & MASK32
            self.memory.write_u32(WORKSPACE_BASE + 0xC, self.return_value)
            self.halted = True
            return
        code = F19_HANDLER_CODE.get(handler)
        if code is None:
            raise F19PureError(f"missing embedded F19 handler: 0x{handler:x}")
        next_handler: int | None = None
        for mnemonic, op_str in code:
            next_handler = self._execute(mnemonic, op_str, handler)
            if next_handler is not None or self.halted:
                break
        if next_handler is None and not self.halted:
            raise F19PureError(f"F19 handler 0x{handler:x} did not dispatch")
        if not self.halted:
            self.x[0] = self._next_record_from_counter_or_handler(next_handler)
        self.steps += 1

    def _next_record_from_counter_or_handler(self, handler: int) -> int:
        # Handlers compute x0 from the counter and holder. The value is already
        # in x0 after the final smaddl; this method only validates the result.
        next_record = self.x[0] & MASK64
        if not PROGRAM_BASE <= next_record < PROGRAM_BASE + len(self.program):
            raise F19PureError(f"F19 handler produced invalid record pointer: 0x{next_record:x}")
        return next_record

    def run(self, max_steps: int = 5000) -> None:
        while not self.halted and self.steps < max_steps:
            self.step()
        if not self.halted:
            raise F19PureError(f"F19 VM exceeded {max_steps} steps")

    def source32_after(self) -> bytes:
        return self.memory.read(WORKSPACE_BASE + SOURCE_OFFSET, SOURCE_SIZE)


def serialize_f19_source(source32: bytes) -> bytes:
    source = bytes(source32)
    if len(source) != SOURCE_SIZE:
        raise F19PureError(f"source32 must contain exactly {SOURCE_SIZE} bytes")
    return b"".join(source[offset : offset + 4][::-1] for offset in range(0, SOURCE_SIZE, 4))


def run_f19_pure(context: F19RuntimeContext) -> F19RunResult:
    vm = _F19Vm(context)
    vm.run()
    source = vm.source32_after()
    return F19RunResult(
        serialized=serialize_f19_source(source),
        source32_after=source,
        steps=vm.steps,
        return_value=vm.return_value,
    )


def generate_f19_pure(context: F19RuntimeContext) -> bytes:
    """Calculate the 32-byte F19 field from explicit runtime state."""
    return run_f19_pure(context).serialized


__all__ = [
    "F19PureError",
    "F19RuntimeContext",
    "F19RunResult",
    "generate_f19_pure",
    "run_f19_pure",
    "serialize_f19_source",
    "F19_RECORD_COUNT",
    "F19_RECORD_SIZE",
]
