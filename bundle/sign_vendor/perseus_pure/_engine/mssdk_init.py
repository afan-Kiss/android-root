"""MSSDK init pure-calc surface.

Layers
------
1. **Session object** (CLOSED): SO+0x2CBA1C session_init — see mssdk_session.py
2. **Cold bootstrap** (IN PROGRESS): JNI ms.bd.c.f3.a state machine that eventually
   materializes F19 workspace_table / regfile baselines / tokens.
3. **Per-request writers** (OPEN): dynamic48 / source_region — not part of init.

This module exposes a stable API that DynamicStateProvider / callers can use:

  init = MssdkInit.session_only()          # pure, no device
  init = MssdkInit.from_capture(json)      # hydrate Level-2 from Frida
  state = init.build_level2_state()        # dict suitable for DynamicStateProvider

Cold-bootstrap pure derivation of workspace_table is the remaining work; until
then ``from_capture`` / ``from_workspace_bytes`` are the supported paths, while
``session_only`` still gives a correct native-equivalent session object.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .mssdk_session import SESSION_BUF_SIZE, SessionView, session_init_bytes, verify_session_init_layout

# JNI / state-machine IDs recovered in mssdk_device_registration
BOOTSTRAP_HTTP_SCHEME = 0x1000001
REQUEST_OPTION = 0x200000D
REQUEST_SECURITY_HEADER = 0x3000001
REQUEST_SESSION_FINALIZE = 0x3000003

F19_WORKSPACE_SIZE = 0x7000
F19_TABLE_OFFSET = 0x50C8
F19_TABLE_SIZE = 0x390
F19_SOURCE_OFFSET = 0x5690
F19_SOURCE_SIZE = 0x60
F19_REGFILE_SLOT_COUNT = 30
F19_REGFILE_OFFSET = 0x6070

_LEVEL2_ALIASES = {
    "workspace_table": (
        "workspace_table_hex",
        "f19_workspace_table_hex",
        "workspace_table",
        "f19_workspace_table",
    ),
    "source_region": (
        "source_region_hex",
        "f19_source_region_hex",
        "source_region",
        "f19_source_region",
        "source",
    ),
    "regfile_slots": (
        "regfile_slots",
        "f19_regfile_slots",
        "regfile",
        "f19_regfile",
    ),
    "workspace_base": ("workspace_base", "f19_workspace_base"),
    "regfile_base": ("regfile_base", "f19_regfile_base"),
    "program_base": ("program_base", "f19_program_base"),
}


def _first(payload: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = payload.get(name)
        if value is not None:
            return value
    return None


def _level2_bytes(value: Any, name: str) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("hex:"):
            text = text[4:]
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError(f"{name} must be hex or bytes") from exc
    raise TypeError(f"{name} must be hex or bytes, got {type(value).__name__}")


def _level2_u64(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def normalize_level2_state(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize captured MSSDK Level-2 material.

    Capture tools have emitted several field aliases. This one boundary accepts
    those aliases, validates the minimum native layout, and returns the
    canonical JSON-ready shape used by both cold-bootstrap persistence and
    ``MssdkInit.from_capture``.
    """
    if not isinstance(payload, Mapping):
        raise TypeError("Level-2 state must be a mapping")

    table = _level2_bytes(_first(payload, _LEVEL2_ALIASES["workspace_table"]), "workspace_table")
    source = _level2_bytes(_first(payload, _LEVEL2_ALIASES["source_region"]), "source_region")
    slots_raw = _first(payload, _LEVEL2_ALIASES["regfile_slots"])

    slots: list[int] | None = None
    if isinstance(slots_raw, (list, tuple)):
        slots = [_level2_u64(value, "regfile_slots") or 0 for value in slots_raw]
    elif slots_raw is not None:
        raw = _level2_bytes(slots_raw, "regfile_slots") or b""
        if len(raw) % 8:
            raise ValueError("regfile_slots byte material must be u64-aligned")
        slots = [
            int.from_bytes(raw[index : index + 8], "little")
            for index in range(0, len(raw), 8)
        ]

    if table is not None and len(table) < F19_TABLE_SIZE:
        raise ValueError(f"workspace_table must contain at least {F19_TABLE_SIZE:#x} bytes")
    if source is not None and len(source) < F19_SOURCE_SIZE:
        raise ValueError(f"source_region must contain at least {F19_SOURCE_SIZE:#x} bytes")
    if slots is not None and len(slots) < F19_REGFILE_SLOT_COUNT:
        raise ValueError(
            f"regfile_slots must contain at least {F19_REGFILE_SLOT_COUNT} u64 values"
        )

    out: dict[str, Any] = {}
    if table is not None:
        out["workspace_table_hex"] = table[:F19_TABLE_SIZE].hex()
    if source is not None:
        out["source_region_hex"] = source[:F19_SOURCE_SIZE].hex()
    if slots is not None:
        out["regfile_slots"] = [hex(value) for value in slots[:F19_REGFILE_SLOT_COUNT]]
    for name in ("workspace_base", "regfile_base", "program_base"):
        value = _level2_u64(_first(payload, _LEVEL2_ALIASES[name]), name)
        if value is not None:
            out[name] = hex(value)
    for key in (
        "device_id",
        "sec_device_token",
        "openudid",
        "derived_from_device_id",
        "derived_from_install_id",
        "session_header_hex",
        "session_slots_hex",
    ):
        if key in payload and payload[key] not in (None, ""):
            out[key] = payload[key]
    return out


@dataclass
class MssdkBootstrapPlan:
    """Ordered cold-start stages. Pure producers fill stage results over time."""

    stages: list[dict[str, Any]] = field(default_factory=lambda: [
        {
            "id": hex(BOOTSTRAP_HTTP_SCHEME),
            "name": "bootstrap/http-scheme-query",
            "status": "observed",
            "pure": False,
            "note": "JNI f3.a obfuscated (br x1+0x38); capture-only today",
        },
        {
            "id": hex(REQUEST_OPTION),
            "name": "request-option",
            "status": "observed",
            "pure": False,
        },
        {
            "id": "session_object",
            "name": "session_init SO+0x2CBA1C",
            "status": "closed",
            "pure": True,
            "note": "byte-exact stack session object",
        },
        {
            "id": "workspace_materialize",
            "name": "F19 workspace_table fill",
            "status": "open_vm_internal",
            "pure": False,
            "note": (
                "No native literal/store of +0x50C8 in libmetasec_ml (P9IM scan). "
                "Table is filled by bootstrap/VM programs. Native workspace offset "
                "registrar ~SO+0x45e580 maps +0x5690/+0x5100 into x19 workspace. "
                "Level-2 closed via capture (best high-entropy x1 workspace)."
            ),
        },
        {
            "id": hex(REQUEST_SECURITY_HEADER),
            "name": "request-security-header-generation",
            "status": "observed",
            "pure": False,
        },
        {
            "id": hex(REQUEST_SESSION_FINALIZE),
            "name": "request-session-finalize",
            "status": "observed",
            "pure": False,
        },
    ])


@dataclass
class MssdkInit:
    """Pure MSSDK init facade."""

    session: SessionView
    workspace: Optional[bytearray] = None
    workspace_table: Optional[bytes] = None
    source_region: Optional[bytes] = None
    regfile_slots: Optional[list[int]] = None
    workspace_base: Optional[int] = None
    regfile_base: Optional[int] = None
    program_base: Optional[int] = None
    sec_device_token: Optional[str] = None
    device_id: Optional[str] = None
    medusa_field13_input: Optional[bytes] = None
    plan: MssdkBootstrapPlan = field(default_factory=MssdkBootstrapPlan)
    meta: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ ctors
    @classmethod
    def session_only(cls, size: int = SESSION_BUF_SIZE) -> "MssdkInit":
        return cls(session=SessionView.create(size), meta={"mode": "session_only", "ts": time.time()})

    @classmethod
    def from_workspace_bytes(
        cls,
        workspace: bytes,
        *,
        workspace_base: Optional[int] = None,
        regfile_base: Optional[int] = None,
        program_base: Optional[int] = None,
        sec_device_token: Optional[str] = None,
        device_id: Optional[str] = None,
        medusa_field13_input: Optional[bytes] = None,
    ) -> "MssdkInit":
        if len(workspace) < F19_TABLE_OFFSET + F19_TABLE_SIZE:
            raise ValueError("workspace too small for table")
        ws = bytearray(workspace)
        table = bytes(ws[F19_TABLE_OFFSET : F19_TABLE_OFFSET + F19_TABLE_SIZE])
        source = None
        if len(ws) >= F19_SOURCE_OFFSET + F19_SOURCE_SIZE:
            source = bytes(ws[F19_SOURCE_OFFSET : F19_SOURCE_OFFSET + F19_SOURCE_SIZE])
        slots = None
        # Prefer regfile at +0x6070 when present (session-slot style); else None.
        if len(ws) >= F19_REGFILE_OFFSET + F19_REGFILE_SLOT_COUNT * 8:
            slots = [
                int.from_bytes(
                    ws[
                        F19_REGFILE_OFFSET + i * 8 :
                        F19_REGFILE_OFFSET + (i + 1) * 8
                    ],
                    "little",
                )
                for i in range(F19_REGFILE_SLOT_COUNT)
            ]
        return cls(
            session=SessionView.create(),
            workspace=ws,
            workspace_table=table,
            source_region=source,
            regfile_slots=slots,
            workspace_base=workspace_base,
            regfile_base=regfile_base if regfile_base is not None else (
                (workspace_base + F19_REGFILE_OFFSET) if workspace_base is not None else None
            ),
            program_base=program_base,
            sec_device_token=sec_device_token,
            device_id=device_id,
            medusa_field13_input=medusa_field13_input,
            meta={"mode": "from_workspace_bytes", "ts": time.time()},
        )

    @classmethod
    def from_capture(cls, payload: Mapping[str, Any]) -> "MssdkInit":
        """Hydrate from P9IK / capture_dynamic_runtime_state JSON."""
        level2 = normalize_level2_state(payload)
        table = _level2_bytes(level2.get("workspace_table_hex"), "workspace_table")
        source = _level2_bytes(level2.get("source_region_hex"), "source_region")
        slots = [
            _level2_u64(value, "regfile_slots") or 0
            for value in level2.get("regfile_slots", [])
        ] or None

        ws = None
        if table is not None:
            ws = bytearray(F19_WORKSPACE_SIZE)
            ws[F19_TABLE_OFFSET : F19_TABLE_OFFSET + F19_TABLE_SIZE] = table
            if source is not None:
                ws[F19_SOURCE_OFFSET : F19_SOURCE_OFFSET + F19_SOURCE_SIZE] = source
            if slots is not None:
                for index, slot in enumerate(slots):
                    start = F19_REGFILE_OFFSET + index * 8
                    ws[start : start + 8] = slot.to_bytes(8, "little", signed=False)

        field13 = _level2_bytes(
            payload.get("medusa_field13_input") or payload.get("field13_input"),
            "medusa_field13_input",
        )
        return cls(
            session=SessionView.create(),
            workspace=ws,
            workspace_table=table,
            source_region=source,
            regfile_slots=slots,
            workspace_base=_level2_u64(level2.get("workspace_base"), "workspace_base"),
            regfile_base=_level2_u64(level2.get("regfile_base"), "regfile_base"),
            program_base=_level2_u64(level2.get("program_base"), "program_base"),
            sec_device_token=payload.get("sec_device_token"),
            device_id=payload.get("device_id"),
            medusa_field13_input=field13,
            meta={"mode": "from_capture", "ts": time.time()},
        )

    @classmethod
    def from_capture_file(cls, path: str | Path) -> "MssdkInit":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # Accept either flat snapshot or {samples:[{models:[...]}]}
        if isinstance(data, dict) and any(
            name in data for name in _LEVEL2_ALIASES["workspace_table"]
        ):
            return cls.from_capture(data)
        if isinstance(data, dict) and data.get("vm"):
            for sample in data["vm"]:
                for model in sample.get("models") or []:
                    if model.get("model") == "x1_as_workspace" and model.get("workspace_table_hex"):
                        payload = {
                            "workspace_table_hex": model.get("workspace_table_hex"),
                            "source_region_hex": model.get("source_region_hex") or model.get("source_head"),
                            "workspace_base": model.get("workspace"),
                        }
                        return cls.from_capture(payload)
        raise ValueError(f"unsupported capture format: {path}")

    # ----------------------------------------------------------------- queries
    def session_ok(self) -> bool:
        return not verify_session_init_layout(bytes(self.session.buf))

    def has_workspace_table(self) -> bool:
        return bool(self.workspace_table) and len(self.workspace_table) == F19_TABLE_SIZE

    def bootstrap_status(self) -> dict[str, Any]:
        response_ready = bool(self.sec_device_token and self.device_id)
        workspace_ready = self.has_workspace_table()
        return {
            "session_init_pure": True,
            "session_layout_ok": self.session_ok(),
            "workspace_table_ready": workspace_ready,
            "cold_bootstrap_pure": False,
            "cold_bootstrap_replayable": response_ready and workspace_ready,
            "registration_request_pure": True,
            "registration_response_required": not response_ready,
            "registration_response_ready": response_ready,
            "workspace_materialized": workspace_ready,
            "plan": self.plan.stages,
            "meta": self.meta,
        }

    def build_level2_state(self) -> dict[str, Any]:
        """Shape expected by dynamic_state_provider session cache."""
        out: dict[str, Any] = {
            "captured_at_ms": int(time.time() * 1000),
            "session_header_hex": self.session.snapshot_header().hex(),
            "session_slots_hex": self.session.slot_table_hex(16),
        }
        if self.workspace_table is not None:
            out["f19_workspace_table_hex"] = self.workspace_table.hex()
            out["workspace_table_hex"] = self.workspace_table.hex()
        if self.source_region is not None:
            out["f19_source_region_hex"] = self.source_region.hex()
            out["source_region_hex"] = self.source_region.hex()
        if self.regfile_slots is not None:
            out["f19_regfile_slots"] = [hex(v) for v in self.regfile_slots]
            out["regfile_slots"] = out["f19_regfile_slots"]
        if self.workspace_base is not None:
            out["f19_workspace_base"] = hex(self.workspace_base)
            out["workspace_base"] = out["f19_workspace_base"]
        if self.regfile_base is not None:
            out["f19_regfile_base"] = hex(self.regfile_base)
            out["regfile_base"] = out["f19_regfile_base"]
        if self.program_base is not None:
            out["f19_program_base"] = hex(self.program_base)
            out["program_base"] = out["f19_program_base"]
        if self.sec_device_token is not None:
            out["sec_device_token"] = self.sec_device_token
        if self.device_id is not None:
            out["device_id"] = self.device_id
        if self.medusa_field13_input is not None:
            out["medusa_field13_input"] = self.medusa_field13_input.hex()
        return out

    def build_f19_runtime(
        self,
        *,
        source32: bytes | None = None,
        final_src16: bytes | None = None,
        source_region: bytes | None = None,
    ) -> Any:
        """Build F19RuntimeContext from stored Level-2 material plus source input.

        This keeps the cold-bootstrap boundary explicit: callers may hydrate
        Level-2 once, then construct request-time F19 runtime with source32 or
        the P888-style final_src16 bridge.
        """
        from .runtime_material import build_f19_runtime

        return build_f19_runtime(
            workspace_table=self.workspace_table,
            regfile_slots=self.regfile_slots,
            workspace_base=self.workspace_base,
            regfile_base=self.regfile_base,
            program_base=self.program_base,
            source32=source32,
            final_src16=final_src16,
            source_region=source_region or self.source_region,
        )


def demo_session_init() -> dict[str, Any]:
    init = MssdkInit.session_only()
    return {
        "header_hex": init.session.snapshot_header().hex(),
        "layout_errors": verify_session_init_layout(bytes(init.session.buf)),
        "status": init.bootstrap_status(),
        "session_bytes": len(session_init_bytes()),
    }
