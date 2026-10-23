from __future__ import annotations

from typing import Any, Mapping, Sequence

from .mssdk_init import MssdkInit
from .p9bc_f18_static import F18_DYNAMIC_SIZE
from .p9bc_f18_vm import F18RuntimeContext
from .p9bc_f19_vm import F19RuntimeContext, SOURCE_REGION_SIZE


def _ensure_bytes(value: bytes | bytearray) -> bytes:
    return bytes(value)


def build_f18_runtime(
    *,
    dynamic48: bytes | bytearray | None = None,
    slot9: bytes | bytearray | None = None,
    head32: bytes | bytearray | None = None,
    tail16: bytes | bytearray | None = None,
    iv: bytes | bytearray | None = None,
    suffix: bytes | bytearray | None = None,
) -> F18RuntimeContext:
    if dynamic48 is None and slot9 is not None:
        slot9_bytes = _ensure_bytes(slot9)
        if len(slot9_bytes) < F18_DYNAMIC_SIZE:
            raise ValueError(
                f"slot9 must contain at least {F18_DYNAMIC_SIZE} bytes, got {len(slot9_bytes)}"
            )
        dynamic48 = slot9_bytes[:F18_DYNAMIC_SIZE]
    if dynamic48 is None and head32 is not None and tail16 is not None:
        head = _ensure_bytes(head32)
        tail = _ensure_bytes(tail16)
        if len(head) != 32:
            raise ValueError(f"head32 must contain exactly 32 bytes, got {len(head)}")
        if len(tail) != 16:
            raise ValueError(f"tail16 must contain exactly 16 bytes, got {len(tail)}")
        dynamic48 = head + tail
    if dynamic48 is None:
        raise ValueError("dynamic48, slot9, or head32+tail16 is required")

    kwargs: dict[str, bytes] = {"dynamic48": _ensure_bytes(dynamic48)}
    if iv is not None:
        kwargs["iv"] = _ensure_bytes(iv)
    if suffix is not None:
        kwargs["suffix"] = _ensure_bytes(suffix)
    return F18RuntimeContext(**kwargs)


def source32_from_final_src16(final_src16: bytes | bytearray) -> bytes:
    raw = _ensure_bytes(final_src16)
    if len(raw) != 16:
        raise ValueError(f"final_src16 must contain exactly 16 bytes, got {len(raw)}")
    return raw.ljust(32, b"\0")


def source_region_from_source32(
    source32: bytes | bytearray | None = None,
    *,
    final_src16: bytes | bytearray | None = None,
    source_region: bytes | bytearray | None = None,
) -> bytes:
    if source_region is not None:
        raw = _ensure_bytes(source_region)
        if len(raw) < SOURCE_REGION_SIZE:
            return raw.ljust(SOURCE_REGION_SIZE, b"\0")
        return raw[:SOURCE_REGION_SIZE]
    if source32 is None and final_src16 is not None:
        source32 = source32_from_final_src16(final_src16)
    if source32 is None:
        raise ValueError("source32, final_src16, or source_region is required")
    raw = _ensure_bytes(source32)
    if len(raw) != 32:
        raise ValueError(f"source32 must contain exactly 32 bytes, got {len(raw)}")
    return raw.ljust(SOURCE_REGION_SIZE, b"\0")


def build_f19_runtime(
    *,
    workspace_table: bytes | bytearray | None = None,
    regfile_slots: Sequence[int] | None = None,
    workspace_base: int | None = None,
    regfile_base: int | None = None,
    program_base: int | None = None,
    source32: bytes | bytearray | None = None,
    final_src16: bytes | bytearray | None = None,
    source_region: bytes | bytearray | None = None,
    level2_state: Mapping[str, Any] | None = None,
) -> F19RuntimeContext:
    if level2_state is not None:
        init = MssdkInit.from_capture(level2_state)
        if workspace_table is None:
            workspace_table = init.workspace_table
        if regfile_slots is None:
            regfile_slots = init.regfile_slots
        if workspace_base is None:
            workspace_base = init.workspace_base
        if regfile_base is None:
            regfile_base = init.regfile_base
        if program_base is None:
            program_base = init.program_base
        if source_region is None and source32 is None and final_src16 is None:
            source_region = init.source_region

    if workspace_table is None:
        raise ValueError("workspace_table is required")
    if regfile_slots is None:
        raise ValueError("regfile_slots is required")

    return F19RuntimeContext(
        workspace_table=_ensure_bytes(workspace_table),
        source_region=source_region_from_source32(
            source32,
            final_src16=final_src16,
            source_region=source_region,
        ),
        regfile_slots=tuple(int(slot) for slot in regfile_slots),
        workspace_base=workspace_base,
        regfile_base=regfile_base,
        program_base=program_base,
    )
