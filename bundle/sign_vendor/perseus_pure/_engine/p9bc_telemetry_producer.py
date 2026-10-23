"""Deterministic request-level telemetry material builder.

This separates the recovered wire codec from capture replay. It can build a
new protobuf/JSON pair from a caller-supplied schema profile and request
context. Unknown native-only fields remain explicit; no stale capture is
silently reused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import time
from typing import Any

from .p9bc_telemetry_codec import (
    ProtoField,
    build_json_chunk,
    build_protobuf,
    encode_zigzag64,
    parse_protobuf,
    replace_perseus_inner_clock_samples,
    replace_varint_fields,
)
from .p9bc_f19_vm import (
    F19PureError,
    F19RuntimeContext,
    generate_f19_pure as _generate_f19_vm,
)
from .p9bc_f18_vm import (
    F18PureError,
    F18RuntimeContext,
    generate_f18_pure as _generate_f18_vm,
)
V39_MAGIC = bytes.fromhex("6b9a2b2a429baf9181ca026ac236a4fe")
LICENSE_ID = "1588093228"
SDK_VERSION_STR = "v04.10.01-ml-android"
SDK_VERSION = 67764480
# Identity fields must not be overwritten by request_fields / app_version / timestamp.
IDENTITY_LOCKED_FIELDS = frozenset({1, 4, 5, 6, 7, 8, 9, 16})


def _fixed_bytes(value: bytes | bytearray, name: str, size: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TelemetryProducerError(f"{name} must be bytes")
    result = bytes(value)
    if len(result) != size:
        raise TelemetryProducerError(
            f"{name} must contain exactly {size} bytes, got {len(result)}"
        )
    return result


def generate_f13_pure(
    f12_value: int,
    *,
    random_prefix: bytes | bytearray | None = None,
    template: bytes | None = None,
) -> bytes:
    """Generate the verified 20-byte field13 shape without template replay."""
    _ = template
    prefix = os.urandom(18) if random_prefix is None else _fixed_bytes(
        random_prefix, "f13 random_prefix", 18
    )
    x = f12_value & 0xFF
    return prefix + bytes([x, x ^ 0x34])


def generate_f14_pure(
    value: bytes | bytearray | None = None,
    *,
    template: bytes | None = None,
) -> bytes:
    """Generate a six-byte native-shaped field14 without template replay."""
    if template is not None:
        raise TelemetryProducerError("f14 template replay is not supported")
    return os.urandom(6) if value is None else _fixed_bytes(value, "f14_value", 6)


def generate_f18_pure(context: F18RuntimeContext) -> bytes:
    """Calculate byte-exact f18 from explicit final-VM runtime state."""
    try:
        return _generate_f18_vm(context)
    except F18PureError as exc:
        raise TelemetryProducerError(str(exc)) from exc


def generate_f19_pure(context: F19RuntimeContext) -> bytes:
    """Calculate byte-exact f19 from explicit final-VM runtime state."""
    try:
        return _generate_f19_vm(context)
    except F19PureError as exc:
        raise TelemetryProducerError(str(exc)) from exc


# Device-level constants confirmed across 10 telemetry samples (9 captures +
# p9bd_ev27). These are stable across requests and only change on device
# re-registration or app reinstall.
DEVICE_LEVEL_JSON_CONSTANTS = {
    "cmr": 16777216,
    "cmr2": 16777216,
    "vpn": 0,
    "sts": 59,
    "tk": True,
}

# Phone mill-less search proto: f21=369, counters use 694367, f16 is 25-char
# MSSDK token (not the 151-char x-tt-dt). JSON ab_test is device-stable.
MILL_COUNTER_SENTINEL = 694367
CALL_TYPE_SEARCH = 369
DEVICE_LEVEL_AB_TEST = {
    "hit": [
        "5665351", "8068441", "8886468", "12306218", "13627108",
        "13719264", "14803483", "15208455", "15682318", "1576",
    ],
}

# lp field structure: "<type>|<device_id_field>|<t1>|<t2>|<t3>"
# lp[0]=type (2 = device-class), lp[1]=device_stable_id, lp[2..4]=time-varying
DEVICE_LEVEL_LP_PREFIX = ("2", "520830913191")

# fl field structure: 10 |-separated u32 values
# fl[0/1/7/8]=0 (constant zeros), fl[2..6][9] are time-varying
DEVICE_LEVEL_FL_ZERO_INDICES = (0, 1, 7, 8)


@dataclass(frozen=True)
class TelemetryRequestContext:
    build: str
    device_id: str
    app_version: str
    timestamp: int
    request_fields: dict[int, int | bytes] = field(default_factory=dict)
    json_fields: dict[str, Any] = field(default_factory=dict)
    inner_field28_ms: int | None = None
    inner_field40_ms: int | None = None
    f13_counter: int | None = None
    f19_runtime: F19RuntimeContext | None = None
    pure_calc: bool = False
    f18_runtime: F18RuntimeContext | None = None
    f18_value: bytes | None = None
    f13_value: bytes | None = None
    f13_random_prefix: bytes | None = None
    f14_value: bytes | None = None
    f19_value: bytes | None = None
    license_id: str = LICENSE_ID
    sdk_version_str: str = SDK_VERSION_STR
    sdk_version: int = SDK_VERSION
    sec_device_token: str = ""
    counters: dict[str, int] | None = None
    query_len: int = 0
    unknown29: int = 0


@dataclass(frozen=True)
class TelemetryMaterial:
    protobuf: bytes
    json: bytes
    source: str = "generated"


@dataclass
class TelemetryClockSession:
    """Native-equivalent clock state for fresh requests."""

    initialized_epoch_ms: int = field(default_factory=lambda: time.time_ns() // 1_000_000)

    def sample(self, now_epoch_ms: int | None = None) -> tuple[int, int]:
        current = time.time_ns() // 1_000_000 if now_epoch_ms is None else int(now_epoch_ms)
        if current < self.initialized_epoch_ms:
            raise TelemetryProducerError("telemetry clock moved before session initialization")
        return current, self.initialized_epoch_ms


class TelemetryProducerError(ValueError):
    pass


def _field(number: int, value: int | bytes) -> ProtoField:
    if isinstance(value, int):
        return ProtoField(number, 0, value)
    return ProtoField(number, 2, bytes(value))


def _sint_field(number: int, value: int) -> ProtoField:
    return ProtoField(number, 0, encode_zigzag64(int(value)))


def _str_field(number: int, value: str) -> ProtoField:
    return ProtoField(number, 2, str(value).encode("utf-8"))


def _bytes_field(number: int, value: bytes) -> ProtoField:
    return ProtoField(number, 2, bytes(value))


def field16_token(token: str | None) -> str:
    """Medusa/Perseus f16 is the 25-char MSSDK token, not 151-char x-tt-dt."""
    text = str(token or "")
    if 20 <= len(text) <= 32:
        return text
    return ""


def field16_from_device(device: Any) -> str:
    return field16_token(
        getattr(device, "medusa_field16", None) or getattr(device, "sec_device_token", None)
    )


def mill_counters(counters: dict[str, int] | None) -> dict[str, int]:
    src = counters or {}

    def _one(name: str) -> int:
        val = int(src.get(name, 0) or 0)
        if name == "sign_count":
            return val or 1
        # Phone mill-less omits unknown4 (proto3 default 0). Session dumps
        # sometimes stash mill-internal 7; encoding it inflates WRAP 325→328.
        if name == "unknown4":
            return 0
        return val or MILL_COUNTER_SENTINEL

    return {name: _one(name) for name in (
        "sign_count", "report_count", "setting_count", "unknown4", "unknown5",
    )}


def _counters_bytes(counters: dict[str, int] | None) -> bytes:
    from .proto import MedushaAlgorithmCount

    payload = mill_counters(counters)
    message = MedushaAlgorithmCount(
        sign_count=payload["sign_count"],
        report_count=payload["report_count"],
        setting_count=payload["setting_count"],
        unknown4=payload["unknown4"],
        unknown5=payload["unknown5"],
    )
    return bytes(message)


def build_from_scratch_fields(ctx: TelemetryRequestContext) -> list[ProtoField]:
    """Assemble Perseus protobuf_chunk from DeviceProfile-class context, no capture template."""
    ts = int(ctx.timestamp)
    rand = ctx.request_fields.get(3)
    if not isinstance(rand, int):
        rand = int.from_bytes(os.urandom(4), "little") & 0x7FFFFFFF
    fields = [
        _bytes_field(1, V39_MAGIC),
        _sint_field(2, 7),
        _sint_field(3, rand),
        _str_field(4, ctx.build or "1128"),
        _str_field(5, ctx.device_id),
        _str_field(6, ctx.license_id or LICENSE_ID),
        _str_field(7, ctx.app_version),
        _str_field(8, ctx.sdk_version_str or SDK_VERSION_STR),
        _sint_field(9, SDK_VERSION if ctx.sdk_version is None else int(ctx.sdk_version)),
        _bytes_field(10, bytes(8)),
        _sint_field(12, ts),
        _bytes_field(15, _counters_bytes(ctx.counters)),
        _str_field(16, field16_token(ctx.sec_device_token)),
        _sint_field(17, ts),
        _str_field(20, "1"),
        _sint_field(21, CALL_TYPE_SEARCH),
        _sint_field(28, int(ctx.query_len or 0)),
        _sint_field(29, int(ctx.unknown29 or 0)),
    ]
    return [item for item in fields if not (item.number == 16 and item.value == b"")]


def build_json_from_scratch(ctx: TelemetryRequestContext) -> dict[str, Any]:
    obj = {
        "ab_test": {"hit": list(DEVICE_LEVEL_AB_TEST["hit"])},
        "build": ctx.build,
        "device_id": ctx.device_id,
        "app_version": ctx.app_version,
        "timestamp": ctx.timestamp,
        "un_h": 0,
        "kd": 0,
        "do": 0,
        "fkd": 0,
        "pd": 0,
        "lp": build_lp_field(0, 0, 0),
        "fl": build_fl_field([0, 0, 0, 0, 0, 0]),
    }
    return apply_device_level_json_constants(obj)


def _overlay_request_fields(fields: list[ProtoField], ctx: TelemetryRequestContext) -> list[ProtoField]:
    replacements = {
        number: value
        for number, value in ctx.request_fields.items()
        if number not in IDENTITY_LOCKED_FIELDS
    }
    if not replacements:
        return fields
    out: list[ProtoField] = []
    seen: set[int] = set()
    for item in fields:
        if item.number in replacements:
            out.append(_field(item.number, replacements[item.number]))
            seen.add(item.number)
        else:
            out.append(item)
    for number, value in replacements.items():
        if number not in seen:
            out.append(_field(number, value))
    return out


def _apply_clock_samples(proto: bytes, field28_ms: int, field40_ms: int) -> bytes:
    proto = replace_varint_fields(
        proto,
        {
            21: encode_zigzag64(int(field28_ms)),
            28: encode_zigzag64(int(field40_ms)),
        },
    )
    try:
        proto = replace_perseus_inner_clock_samples(
            proto, field28_ms=int(field28_ms), field40_ms=int(field40_ms)
        )
    except ValueError:
        pass
    return proto


def apply_device_level_json_constants(
    obj: dict[str, Any],
    *,
    lp_prefix: tuple[str, str] = DEVICE_LEVEL_LP_PREFIX,
    fl_zero_indices: tuple[int, ...] = DEVICE_LEVEL_FL_ZERO_INDICES,
    constants: dict[str, Any] = DEVICE_LEVEL_JSON_CONSTANTS,
) -> dict[str, Any]:
    """Inject confirmed device-level constants into a telemetry JSON object."""
    for key, value in constants.items():
        obj[key] = value

    lp_value = obj.get("lp")
    if isinstance(lp_value, str):
        parts = lp_value.split("|")
        if len(parts) >= 2:
            parts[0] = lp_prefix[0]
            parts[1] = lp_prefix[1]
            obj["lp"] = "|".join(parts)
        else:
            obj["lp"] = "|".join([*lp_prefix, *parts])

    fl_value = obj.get("fl")
    if isinstance(fl_value, str):
        parts = fl_value.split("|")
        while len(parts) < 10:
            parts.append("0")
        for idx in fl_zero_indices:
            if idx < len(parts):
                parts[idx] = "0"
        obj["fl"] = "|".join(parts)

    return obj


def build_lp_field(t1: int, t2: int, t3: int, *, prefix: tuple[str, str] = DEVICE_LEVEL_LP_PREFIX) -> str:
    """Build a complete lp field from time-varying components."""
    return "|".join([prefix[0], prefix[1], str(t1), str(t2), str(t3)])


def build_fl_field(
    time_varying: list[int],
    *,
    zero_indices: tuple[int, ...] = DEVICE_LEVEL_FL_ZERO_INDICES,
) -> str:
    """Build a complete fl field from time-varying components.

    time_varying must provide values for indices 2, 3, 4, 5, 6, 9 in that
    order.
    """
    if len(time_varying) != 6:
        raise TelemetryProducerError(
            f"fl time_varying must have 6 values (for indices 2,3,4,5,6,9), got {len(time_varying)}"
        )
    parts = ["0"] * 10
    tv_iter = iter(time_varying)
    for idx in range(10):
        if idx in zero_indices:
            continue
        parts[idx] = str(next(tv_iter))
    return "|".join(parts)


def build_request_telemetry(
    ctx: TelemetryRequestContext,
    *,
    protobuf_template: bytes | None = None,
    json_template: bytes | None = None,
    required_fields: tuple[int, ...] = (),
    clock_session: TelemetryClockSession | None = None,
    now_epoch_ms: int | None = None,
) -> TelemetryMaterial:
    """Build a new telemetry pair while failing closed on unresolved fields."""
    missing = [str(n) for n in required_fields if n not in ctx.request_fields]
    if missing:
        raise TelemetryProducerError("missing request telemetry fields: " + ", ".join(missing))

    if protobuf_template is None:
        fields = build_from_scratch_fields(ctx)
        fields = _overlay_request_fields(fields, ctx)
    else:
        fields = parse_protobuf(protobuf_template)
        fields = _overlay_request_fields(fields, ctx)

    field_numbers = {item.number for item in fields}
    if 12 in field_numbers and 17 not in field_numbers:
        f12 = next(item for item in fields if item.number == 12)
        fields.append(_field(17, int(f12.value)))
    if 20 not in field_numbers:
        fields.append(_field(20, b"1"))

    if ctx.f13_counter is not None and not ctx.pure_calc:
        f13_value = generate_f13_pure(ctx.f13_counter)
        fields = [item for item in fields if item.number != 13] + [_field(13, f13_value)]

    if ctx.pure_calc:
        if 12 not in field_numbers:
            raise TelemetryProducerError("pure_calc requires request field 12 for field13")
        if ctx.f19_runtime is None and ctx.f19_value is None:
            raise TelemetryProducerError("pure_calc requires f19_runtime context")
        if ctx.f18_runtime is None and ctx.f18_value is None:
            raise TelemetryProducerError("pure_calc requires f18_runtime context or f18_value")
        if ctx.f13_value is not None:
            field13 = _fixed_bytes(ctx.f13_value, "f13_value", 20)
        elif ctx.f13_counter is not None:
            field13 = generate_f13_pure(
                int(next(item.value for item in fields if item.number == 12)),
                random_prefix=ctx.f13_random_prefix,
            )
        else:
            raise TelemetryProducerError(
                "pure_calc requires f13_value or f13_counter"
            )
        field14 = generate_f14_pure(ctx.f14_value)
        exact = {13: field13, 14: field14}
        if ctx.f18_value is not None:
            exact[18] = _fixed_bytes(ctx.f18_value, "f18_value", 20)
        else:
            exact[18] = generate_f18_pure(ctx.f18_runtime)
        if ctx.f19_value is not None:
            exact[19] = _fixed_bytes(ctx.f19_value, "f19_value", 32)
        else:
            exact[19] = generate_f19_pure(ctx.f19_runtime)
        fields = [item for item in fields if item.number not in exact]
        fields.extend(_field(number, exact[number]) for number in (13, 14, 18, 19))

    proto = build_protobuf(fields)

    explicit_clock = ctx.inner_field28_ms is not None or ctx.inner_field40_ms is not None
    if explicit_clock and clock_session is not None:
        raise TelemetryProducerError("use either explicit inner clock samples or clock_session, not both")
    if clock_session is not None:
        field28_ms, field40_ms = clock_session.sample(now_epoch_ms)
        # Phone mill-less proto keeps f21=call_type 369 and f28=query length.
        # Wall-clock samples only belong in nested field12 when that exists.
        try:
            proto = replace_perseus_inner_clock_samples(
                proto, field28_ms=int(field28_ms), field40_ms=int(field40_ms)
            )
        except ValueError:
            pass
    elif explicit_clock:
        if ctx.inner_field28_ms is None or ctx.inner_field40_ms is None:
            raise TelemetryProducerError("inner field28/40 clock samples must be supplied together")
        try:
            proto = replace_perseus_inner_clock_samples(
                proto,
                field28_ms=int(ctx.inner_field28_ms),
                field40_ms=int(ctx.inner_field40_ms),
            )
        except ValueError:
            pass

    if json_template is None:
        obj = build_json_from_scratch(ctx)
    else:
        obj = json.loads(bytes(json_template).decode())
        if not isinstance(obj, dict):
            raise TelemetryProducerError("telemetry JSON template must be object")

    obj.update(ctx.json_fields)
    obj.setdefault("build", ctx.build)
    obj.setdefault("device_id", ctx.device_id)
    obj.setdefault("app_version", ctx.app_version)
    obj.setdefault("timestamp", ctx.timestamp)
    apply_device_level_json_constants(obj)
    return TelemetryMaterial(proto, build_json_chunk(obj))
