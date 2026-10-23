from __future__ import annotations

import binascii
import hashlib
import json as json_lib
import logging
import os
import random
from typing import Any
from urllib.parse import urlsplit

from .errors import MissingDeviceStateError, InvalidMaterialError
from .models import DeviceProfile, RequestInput, decode_bytes
from ._engine.argusEncrypt import encrypt_argus
from ._engine.gorgonEncrypt import encrypt_gorgon
from ._engine.heliosEncrypt import encrypt_helios
from ._engine.khronosEncrypt import encrypt_khronos
from ._engine.ladonEncrypt import gen_ladon_v39
from ._engine.extra import SM3, md5sum
from ._engine.medusaEncrypt import gen_medusa_proto_v39, gen_medusa_v39_base64
from ._engine.proto import MedushaAlgorithmCount
from ._engine.p9bc_field13_independent_profile import generate_field13 as generate_perseus_field13
from ._engine.p9bc_payload_transform import build_payload_plaintext, transform_payload
from ._engine.p9bc_scatter_e_profile import generate_source19
from ._engine.p9bc_scatter_mask import generate_scatter_mask_from_plaintext
from ._engine.p9bc_transform_random import generate_rand_value
from ._engine.perseus_custom_base64 import V39_ALPHABETS
from ._engine.perseus_record import build_record
from ._engine.perseus_custom_base64 import encode as encode_perseus
from ._engine.p9bc_f18_vm import F18RuntimeContext
from ._engine.p9bc_f19_vm import F19RuntimeContext
from ._engine.p9bc_telemetry_producer import (
    TelemetryClockSession,
    TelemetryProducerError,
    TelemetryRequestContext,
    build_request_telemetry,
    field16_from_device,
    mill_counters,
)
from ._engine.ticketguard_ree import TicketGuardDeviceState

logger = logging.getLogger(__name__)


def _signed_crc32(data: bytes) -> int:
    value = binascii.crc32(data) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _plain_sign_body(body: bytes | None) -> bytes:
    """Mill signs over the *decompressed* body: zstd frame → inflate, else raw.

    Matches sscronet_millless_search.py:_plain_sign_body. f14/f18/f19 all hash
    over this plaintext, so a compressed request.body must be inflated first or
    the SM3/md5 inputs diverge from the phone and the request sharks.
    """
    raw = body or b""
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(raw, max_output_size=10_000_000)
        except Exception:
            return raw
    return raw


def _pad_medusa_proto(proto: bytes, want: int = 269) -> bytes:
    """Keep native field bytes. Fake field30 `x` padding sharks mill-less WRAP."""
    _ = want
    return proto


def _pad_perseus_json(protobuf_chunk: bytes, json_chunk: bytes, want_payload: int = 661) -> bytes:
    """Do not stuff dummy `k=xxx` to hit a WRAP size. Live mill-less Perseus is 912-916."""
    _ = protobuf_chunk
    _ = want_payload
    try:
        obj = json_lib.loads(json_chunk)
    except Exception:
        return json_chunk
    if isinstance(obj, dict):
        obj.pop("k", None)
        return json_lib.dumps(obj, separators=(",", ":")).encode("utf-8")
    return json_chunk


def _decode_runtime_bytes(value: Any, name: str) -> bytes:
    try:
        decoded = decode_bytes(value, name)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise InvalidMaterialError(f"{name} is not valid encoded bytes: {exc}") from exc
    if decoded is None:
        raise InvalidMaterialError(f"{name} is required")
    return decoded


def _runtime_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise InvalidMaterialError(f"{name} must be an integer")
    try:
        if isinstance(value, str):
            text = value.strip()
            if text.lower().startswith(("0x", "+0x", "-0x")):
                return int(text, 16)
            return int(text, 10)
        return int(value)
    except (TypeError, ValueError) as exc:
        raise InvalidMaterialError(f"{name} must be an integer") from exc


def _coerce_f18_runtime(value: Any) -> F18RuntimeContext | None:
    if value is None:
        return None
    if isinstance(value, F18RuntimeContext):
        return value
    if not isinstance(value, dict):
        raise InvalidMaterialError("f18_runtime must be an object")
    try:
        from ._engine.runtime_material import build_f18_runtime

        kwargs: dict[str, bytes | None] = {}
        for name in ("dynamic48", "slot9", "head32", "tail16", "iv", "suffix"):
            if value.get(name) is not None:
                kwargs[name] = _decode_runtime_bytes(value[name], f"f18_runtime.{name}")
        return build_f18_runtime(**kwargs)
    except InvalidMaterialError:
        raise
    except (TypeError, ValueError) as exc:
        raise InvalidMaterialError(f"invalid f18_runtime: {exc}") from exc


def _coerce_f19_runtime(value: Any) -> F19RuntimeContext | None:
    if value is None:
        return None
    if isinstance(value, F19RuntimeContext):
        return value
    if not isinstance(value, dict):
        raise InvalidMaterialError("f19_runtime must be an object")
    try:
        from ._engine.runtime_material import build_f19_runtime

        runtime_kwargs: dict[str, Any] = {
            "workspace_base": _runtime_int(value.get("workspace_base"), "f19_runtime.workspace_base"),
            "regfile_base": _runtime_int(value.get("regfile_base"), "f19_runtime.regfile_base"),
            "program_base": _runtime_int(value.get("program_base"), "f19_runtime.program_base"),
        }
        if value.get("workspace_table") is not None:
            runtime_kwargs["workspace_table"] = _decode_runtime_bytes(
                value["workspace_table"], "f19_runtime.workspace_table"
            )
        if value.get("source_region") is not None:
            runtime_kwargs["source_region"] = _decode_runtime_bytes(
                value["source_region"], "f19_runtime.source_region"
            )
        if value.get("source32") is not None:
            runtime_kwargs["source32"] = _decode_runtime_bytes(
                value["source32"], "f19_runtime.source32"
            )
        if value.get("final_src16") is not None:
            runtime_kwargs["final_src16"] = _decode_runtime_bytes(
                value["final_src16"], "f19_runtime.final_src16"
            )
        raw_slots = value.get("regfile_slots")
        if raw_slots is not None:
            if not isinstance(raw_slots, (list, tuple)):
                raise InvalidMaterialError("f19_runtime.regfile_slots must be an array")
            slots = tuple(
                _runtime_int(slot, f"f19_runtime.regfile_slots[{index}]")
                for index, slot in enumerate(raw_slots)
            )
            if any(slot is None for slot in slots):
                raise InvalidMaterialError("f19_runtime.regfile_slots contains a null value")
            runtime_kwargs["regfile_slots"] = tuple(int(slot) for slot in slots)
        if value.get("level2_state") is not None:
            if not isinstance(value["level2_state"], dict):
                raise InvalidMaterialError("f19_runtime.level2_state must be an object")
            runtime_kwargs["level2_state"] = value["level2_state"]
        return build_f19_runtime(**runtime_kwargs)
    except InvalidMaterialError:
        raise
    except (TypeError, ValueError) as exc:
        raise InvalidMaterialError(f"invalid f19_runtime: {exc}") from exc


def _coerce_f19_value(value: Any) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidMaterialError("f19_runtime must be an object")
    try:
        from ._engine.p9bc_f19_vm import serialize_f19_source
        from ._engine.runtime_material import source32_from_final_src16

        if value.get("field32") is not None:
            return _decode_runtime_bytes(value["field32"], "f19_runtime.field32")
        if value.get("source32") is not None:
            source32 = _decode_runtime_bytes(value["source32"], "f19_runtime.source32")
            return serialize_f19_source(source32)
        if value.get("final_src16") is not None:
            final_src16 = _decode_runtime_bytes(value["final_src16"], "f19_runtime.final_src16")
            return serialize_f19_source(source32_from_final_src16(final_src16))
        return None
    except InvalidMaterialError:
        raise
    except (TypeError, ValueError) as exc:
        raise InvalidMaterialError(f"invalid f19_runtime: {exc}") from exc


class QishenPureEngine:
    """Delivery facade. Dynamic device state is explicit and never synthesized."""

    def __init__(self, device: DeviceProfile):
        self.device = device
        self._compact_fields: dict[str, Any] | None = None

    def generate_classic(self, request: RequestInput) -> dict[str, str]:
        query = urlsplit(request.url).query
        xg_rand = random.randint(0, 0xFFFF) if request.xg_rand is None else int(request.xg_rand)
        return {
            "X-Khronos": encrypt_khronos(ts=request.timestamp),
            "X-Argus": encrypt_argus(url=request.url, khronos=request.timestamp),
            "X-Gorgon": encrypt_gorgon(body=request.body, query=query, khronos=request.timestamp, xg_rand=xg_rand, dataType=None),
            "X-Helios": encrypt_helios(khronos=request.timestamp, rand=request.helios_rand),
            "X-Ladon": gen_ladon_v39(raw=request.ladon_raw),
        }

    def _resolve_medusa_query_body_ts_hash(self, request: RequestInput) -> bytes:
        """Return live Medusa proto field13 (20B).

        Order:
          1) explicit ``medusa_query_body_ts_hash`` (request/device)
          2) mill-less ``medusa_first16`` / ``medusa_mill_ws`` / ``medusa_wide64``
          3) ``medusa_field13_closure`` → static closure assemble
          4) legacy ``medusa_field13_seed_snaps`` → assemble_from_seed_snaps / assemble_from_w
          5) dest=10 mill-walk / fill XOR when request seed+gap and device tab/tbl match
          6) shape-only urandom first16 + assemble lag=1 (NOT 出货; live W=M^ROR(TAB,k+5))
          7) optional cold_pure_v1 SHA256 placeholder (not live-exact)
        Do **not** use ``SHA1(medusa_field13_input)``.
        Delivery accepts de-lived P2055 closure material and preserves the old
        seed-snap naming as a backward-compatible alias.
        """
        value = request.medusa_query_body_ts_hash or self.device.medusa_query_body_ts_hash
        if value is not None:
            raw = bytes(value)
            if len(raw) != 20:
                raise InvalidMaterialError(
                    f"medusa_query_body_ts_hash must contain exactly 20 bytes, got {len(raw)}"
                )
            return raw

        first16 = getattr(request, "medusa_first16", None)
        if first16 is not None:
            raw16 = bytes(first16)
            if len(raw16) != 16:
                raise InvalidMaterialError(
                    f"medusa_first16 must contain exactly 16 bytes, got {len(raw16)}"
                )
            from ._engine.millless import field13_20b_from_first16

            return field13_20b_from_first16(raw16, int(request.timestamp), lag=1)

        mill_ws = getattr(request, "medusa_mill_ws", None)
        if mill_ws is not None:
            from ._engine.millless import field13_20b_from_ws

            return field13_20b_from_ws(bytes(mill_ws), int(request.timestamp), lag=1)

        wide64 = getattr(request, "medusa_wide64", None)
        if wide64 is not None:
            from ._engine.millless import field13_20b_from_wide64

            return field13_20b_from_wide64(bytes(wide64), int(request.timestamp), lag=1)

        closure = getattr(request, "medusa_field13_closure", None)
        legacy_snaps = getattr(request, "medusa_field13_seed_snaps", None)
        for material_name, material in (
            ("medusa_field13_closure", closure),
            ("medusa_field13_seed_snaps", legacy_snaps),
        ):
            if not isinstance(material, dict) or not material:
                continue
            try:
                from ._engine.medusa_field13_assemble import assemble_from_material_dict

                return assemble_from_material_dict(material, timestamp=request.timestamp)
            except InvalidMaterialError:
                raise
            except Exception as e:
                raise InvalidMaterialError(f"{material_name} assemble failed: {e}") from e

        seed = getattr(request, "medusa_seed", None)
        gap = getattr(request, "medusa_gap", None)
        tab = getattr(self.device, "medusa_tab", None)
        tbl = getattr(self.device, "medusa_tbl", None)
        if seed is not None and gap is not None:
            try:
                from ._engine.medusa_field13_assemble import (
                    assemble_from_material_dict,
                    k_from_ts,
                    TAB_LIVE,
                )
                from ._engine.medusa_field13_leaves import (
                    fill_gap_ready,
                    mill_d10_ready,
                    k_from_mill_d10_gap,
                    k_from_fill_gap,
                    _as_bytes,
                )

                gap_b = _as_bytes(gap, "gap")
                tab4 = [int(x) for x in (tab[:4] if tab else TAB_LIVE)]
                material = {
                    "seed": seed,
                    "gap": gap,
                    "tab": tab4,
                    "lag": 1,
                }
                k = k_from_mill_d10_gap(gap_b)
                if k is None:
                    k = k_from_fill_gap(gap_b, tab4)
                if k is None and tbl is not None and request.timestamp:
                    k = k_from_ts(int(request.timestamp), int(tbl))
                    material["tbl"] = int(tbl)
                    material["wall_ts"] = int(request.timestamp)
                if k is not None:
                    material["k"] = k
                if k is not None and (
                    fill_gap_ready(gap_b, k, tab4) or mill_d10_ready(gap_b, k)
                ):
                    return assemble_from_material_dict(material, timestamp=request.timestamp)
            except InvalidMaterialError:
                raise
            except Exception:
                pass
        use_cold = (
            bool(getattr(request, "medusa_cold_pure_v1", False))
            or bool(getattr(self.device, "medusa_cold_pure_v1", False))
            or (seed is not None and gap is not None)
        )
        if use_cold and self.device.device_id and request.timestamp:
            try:
                from ._engine.medusa_field13_cold import derive_query_body_ts_hash_cold

                tab = getattr(self.device, "medusa_tab", None)
                tbl = getattr(self.device, "medusa_tbl", None)
                return derive_query_body_ts_hash_cold(
                    device_id=self.device.device_id,
                    timestamp_sec=int(request.timestamp),
                    body=request.body or b"",
                    app_version=self.device.app_version or "",
                    tab=list(tab) if tab else None,
                    tbl=None if tbl is None else int(tbl),
                    seed=seed,
                    gap=gap,
                )
            except Exception as e:
                raise InvalidMaterialError(f"medusa cold_pure_v1 derive failed: {e}") from e

        from ._engine.millless import field13_20b_millless

        return field13_20b_millless(int(request.timestamp), lag=1)

    def _resolve_hash_rand(self, request: RequestInput) -> int:
        """Shared WRAP seed: Medusa hash_rand == Perseus transform_random.

        Both feed ``get_key_hash(V39_SIGN_KEY, rand)``. hash_rand is on the
        X-Medusa wire (LE u32 split across header/tail); Perseus xmxor is not.
        A second CSPRNG draw makes Perseus ciphertext unrecoverable from Medusa.
        Fresh value matches ``gen_medusa_v39_raw`` (os.urandom 4B LE).
        """
        compact = getattr(self, "_compact_fields", None)
        if isinstance(compact, dict) and compact.get("hash_rand") is not None:
            return int(compact["hash_rand"])

        transform_random = request.transform_random
        hash_rand = request.medusa_hash_rand
        if (
            transform_random is not None
            and hash_rand is not None
            and int(transform_random) != int(hash_rand)
        ):
            raise InvalidMaterialError(
                "transform_random and medusa_hash_rand must be the same u32"
            )
        if hash_rand is not None:
            value = int(hash_rand)
        elif transform_random is not None:
            value = int(transform_random)
        else:
            value = int.from_bytes(os.urandom(4), "little")

        if isinstance(compact, dict):
            compact["hash_rand"] = value
        return value

    def _build_compact_fields(self, request: RequestInput) -> dict[str, bytes]:
        """One compact WRAP field set for both Medusa proto and Perseus protobuf.

        Live mill emits Medusa+Perseus from the same WRAP session. sign() used
        to call telemetry twice (fresh urandom f13/f14/f19) and SM3-VM f18 for
        Perseus vs millless_lanusk for Medusa — dual-swap sharks that split.
        first16 inside f13 is still mill-session import (urandom shape-only).
        """
        from ._engine.millless import millless_lanusk_hash

        query = urlsplit(request.url).query.encode("utf-8")
        # 真机 mill 回调实测公式 (sscronet_millless_search.py:410/560):
        #   f14 = SM3(query)[:6]                     (纯算, 不是 urandom)
        #   f19 = SM3(query + md5(plain_body) + b"1") (纯算, 不是 source32 运行时熵)
        # body 必须是解压后的明文 (mill 用 _plain_sign_body: zstd 则解压)
        plain = _plain_sign_body(request.body)
        body_hash = md5sum(plain) if plain else bytes(16)
        f13 = self._resolve_medusa_query_body_ts_hash(request)
        f14 = SM3(query).digest()[:6]
        f18 = millless_lanusk_hash(body=plain)
        f19 = SM3(query + body_hash + b"1").digest()
        if len(f13) != 20:
            raise InvalidMaterialError(f"compact f13 must be 20B, got {len(f13)}")
        if len(f18) != 20:
            raise InvalidMaterialError("X-Medusa f18 millless_lanusk_hash must be 20B")
        if len(f19) != 32:
            raise InvalidMaterialError("compact f19 must be 32B")
        return {"f13": f13, "f14": f14, "f18": f18, "f19": f19}

    def _assemble_medusa_proto(self, request: RequestInput, fields: dict[str, bytes]) -> bytes:
        missing=[]
        if not self.device.device_id: missing.append("device_id")
        if not self.device.app_version: missing.append("app_version")
        if not self.device.sec_device_token: missing.append("sec_device_token")
        if self.device.medusa_counters is None: missing.append("medusa_counters")
        if missing:
            raise MissingDeviceStateError("X-Medusa missing device/session state: " + ", ".join(missing))
        counters=self.device.medusa_counters
        required=("sign_count","report_count","setting_count","unknown4","unknown5")
        absent=[k for k in required if k not in counters]
        if absent:
            raise MissingDeviceStateError("medusa_counters missing: " + ", ".join(absent))
        query = urlsplit(request.url).query.encode("utf-8")
        plain = _plain_sign_body(request.body)
        body_hash = md5sum(plain) if plain else bytes(16)
        proto=gen_medusa_proto_v39(
            rand=random.randint(0,0xFFFFFFFF) if request.medusa_rand is None else int(request.medusa_rand),
            khronos=request.timestamp, device_id=self.device.device_id, app_version=self.device.app_version,
            query_body_ts_hash=fields["f13"], query_sm3=fields["f14"],
            request=MedushaAlgorithmCount(**mill_counters(counters)),
            sec_device_token=field16_from_device(self.device),
            unknown28=len(query), unknown29=_signed_crc32(body_hash),
            lanusk_hash=fields["f18"],
            query_body_hash_sm3=fields["f19"],
            call_type=369,
        )
        return _pad_medusa_proto(proto, 269)

    def generate_medusa(self, request: RequestInput) -> str:
        fields = getattr(self, "_compact_fields", None)
        if not fields:
            fields = self._build_compact_fields(request)
        proto = fields.get("proto")
        if not proto:
            proto = self._assemble_medusa_proto(request, fields)
            if getattr(self, "_compact_fields", None) is fields:
                fields["proto"] = proto
        query_sm3 = SM3(urlsplit(request.url).query.encode("utf-8")).digest()
        body_hash = md5sum(request.body) if request.body else bytes(16)
        return gen_medusa_v39_base64(
            proto, request.timestamp, query_sm3, body_hash,
            hash_rand=self._resolve_hash_rand(request), xm_rand=request.medusa_xm_rand,
            random_mask=request.medusa_random_mask, header_extension=request.medusa_header_extension,
            fix_byte_mode=0,
        )

    def generate_medusa_quasi_pure(
        self,
        request: RequestInput,
        *,
        cache: Any = None,
        device_model: str = "PGZ110",
        setting_count: int | None = None,
    ) -> str:
        """X-Medusa 准纯算入口: device profile 缺 counters 时用缓存或 sentinel 兜底

        - 有 counters → ``generate_medusa``（缺 mill W 时 urandom first16 只凑外形，出货会 shark）
        - 缺 counters → sentinel 补全后再签
        - ``medusa_field13_input`` (12B) 不再冒充 proto field13

        Args:
            request: 请求输入（须含 medusa_query_body_ts_hash，除非 device 已带）
            cache: 可选的 DeviceStateCache, 用于回填 setting_count 等
            device_model: 设备型号, 用于选取已知 12B builder 样本 (默认 PGZ110)
            setting_count: 显式 setting_count, 覆盖缓存/sentinel
        """
        has_counters = self.device.medusa_counters is not None
        if has_counters:
            return self.generate_medusa(request)

        missing = ["medusa_counters"]
        logger.warning(
            "X-Medusa 准纯算模式: device_id=%s 缺少 %s, 使用缓存/sentinel 兜底",
            self.device.device_id, ", ".join(missing),
        )

        # 委托 QuasiPureMedusaProvider 补全并签名 (懒导入避免循环依赖)
        from .quasi_pure import QuasiPureMedusaProvider
        field13 = self.device.medusa_field13_input
        if field13 is None and cache is not None:
            field13 = cache.get_field13_input(self.device.device_id)
        sc = setting_count
        if sc is None and cache is not None:
            sc = cache.get_setting_count(self.device.device_id)

        provider = QuasiPureMedusaProvider(
            device_id=self.device.device_id,
            app_version=self.device.app_version,
            sec_device_token=self.device.sec_device_token,
            field13_input=field13,
            setting_count=sc,
            device_model=device_model,
            cache=cache,
        )
        return provider.generate_medusa(request)

    def generate_perseus(self, request: RequestInput) -> str:
        # Auto-generate protobuf_chunk and json_chunk if not provided (P9BL integration)
        protobuf_chunk = request.protobuf_chunk
        json_chunk = request.json_chunk
        owned_compact = False
        if protobuf_chunk is None or json_chunk is None:
            compact = getattr(self, "_compact_fields", None)
            if compact is None and protobuf_chunk is None:
                compact = self._build_compact_fields(request)
                self._compact_fields = compact
                owned_compact = True
            try:
                pb, js = self._generate_telemetry_chunks(request)
                proto = compact.get("proto") if compact else None
                if proto is None and compact:
                    try:
                        proto = self._assemble_medusa_proto(request, compact)
                        compact["proto"] = proto
                    except MissingDeviceStateError:
                        proto = None
                protobuf_chunk = protobuf_chunk if protobuf_chunk is not None else (proto or pb)
                json_chunk = json_chunk if json_chunk is not None else js
            finally:
                if owned_compact:
                    self._compact_fields = None
        json_chunk = _pad_perseus_json(protobuf_chunk, json_chunk)

        transform_random = self._resolve_hash_rand(request)
        if request.raw_seed is None:
            # Derive raw_seed from the generated/provided chunks
            from ._engine.p9bc_scatter_seed_generator import generate_raw_seed
            from ._engine.medusaEncrypt import V39_SIGN_KEY, xmxor
            from ._engine.extra import get_key_hash
            plaintext = build_payload_plaintext(protobuf_chunk, json_chunk)
            key = get_key_hash(V39_SIGN_KEY, transform_random)[0]
            xmxor_payload = bytes(xmxor(bytearray(plaintext), bytearray(key)))
            raw_seed = generate_raw_seed(xmxor_payload)
        else:
            raw_seed = request.raw_seed

        selector = (request.timestamp & 3) if request.selector is None else int(request.selector)
        if selector not in range(4):
            raise InvalidMaterialError("selector must be 0, 1, 2 or 3")
        source19 = generate_source19(raw_seed, selector)
        field13 = generate_perseus_field13(source19)
        random_value = generate_rand_value() if request.random_value is None else int(request.random_value)
        plaintext = build_payload_plaintext(protobuf_chunk, json_chunk)
        if len(plaintext) < 153:
            raise InvalidMaterialError(
                f"X-Perseus payload plaintext must contain at least 153 bytes, got {len(plaintext)}"
            )
        scatter_mask = generate_scatter_mask_from_plaintext(source19, plaintext, transform_random)
        payload = transform_payload(plaintext, transform_random, scatter_mask)
        record = build_record(random_value, field13, payload)
        return encode_perseus(record, V39_ALPHABETS[selector]).decode("ascii")

    def _generate_telemetry_chunks(self, request: RequestInput) -> tuple[bytes, bytes]:
        """Auto-generate protobuf_chunk and json_chunk using telemetry producer (P9BL).

        Missing F18/F19 are mill-less filled. Compact WRAP sign() injects
        millless_lanusk f18 + shared f13/f14/f19 via ``_compact_fields``.
        Explicit ``f18_runtime`` still uses the SM3 telemetry VM (tests).
        """
        compact = getattr(self, "_compact_fields", None)
        f18_value = None if not compact else compact.get("f18")
        f18_runtime = _coerce_f18_runtime(request.f18_runtime)
        if f18_runtime is None and f18_value is None:
            from ._engine.f18_deriver import derive_f18_context

            derived = derive_f18_context(
                device_id=self.device.device_id or "0",
                timestamp_sec=int(request.timestamp),
                url=request.url,
                body=request.body,
                client_key64=self.device.client_key64,
            )
            f18_runtime = F18RuntimeContext(derived.dynamic48)
        f19_value = _coerce_f19_value(request.f19_runtime)
        f19_runtime = None if f19_value is not None else _coerce_f19_runtime(request.f19_runtime)
        if f19_value is None and f19_runtime is None:
            if compact and compact.get("f19"):
                f19_value = compact["f19"]
            else:
                from ._engine.millless import field32_from_source32, source32_local

                f19_value = field32_from_source32(source32_local())
        # f13 pure-calc: enable f13 generation from f12 value (X = f12 & 0xFF)
        # The actual f12 value comes from request_fields[12] in the producer
        f13_counter = 1  # non-None enables f13 pure-calc mode
        f13_value = None if not compact else compact.get("f13")
        f14_value = None if not compact else compact.get("f14")

        ctx = TelemetryRequestContext(
            build="1128",
            device_id=self.device.device_id or "0",
            app_version=self.device.app_version or "39.4.0",
            timestamp=request.timestamp,
            json_fields={
                "timestamp": request.timestamp,
            },
            f13_counter=f13_counter,
            f13_value=f13_value,
            f14_value=f14_value,
            f18_runtime=f18_runtime,
            f18_value=f18_value,
            f19_runtime=f19_runtime,
            f19_value=f19_value,
            pure_calc=True,
            license_id="1588093228",
            sdk_version_str="v04.10.01-ml-android",
            sdk_version=67764480,
            sec_device_token=field16_from_device(self.device),
            counters=self.device.medusa_counters,
            query_len=len(urlsplit(request.url).query.encode("utf-8")),
            unknown29=_signed_crc32(md5sum(request.body) if request.body else bytes(16)),
        )
        try:
            material = build_request_telemetry(
                ctx,
                clock_session=TelemetryClockSession(),
            )
        except TelemetryProducerError as exc:
            raise InvalidMaterialError(str(exc)) from exc
        return material.protobuf, material.json

    def generate(self, request: RequestInput, *, include_medusa: bool=True, include_perseus: bool=True) -> dict[str,str]:
        out=self.generate_classic(request)
        compact = None
        if include_medusa or include_perseus:
            compact = self._build_compact_fields(request)
            self._compact_fields = compact
            self._resolve_hash_rand(request)
        try:
            if include_medusa: out["X-Medusa"]=self.generate_medusa(request)
            if include_perseus: out["X-Perseus"]=self.generate_perseus(request)
            return out
        finally:
            self._compact_fields = None

    def generate_ticket_guard(self, ticket: str, path: str, timestamp: int) -> dict[str,str]:
        if not self.device.ticket_guard:
            raise MissingDeviceStateError("Ticket-Guard enrollment state is not configured")
        return TicketGuardDeviceState(**self.device.ticket_guard).request_headers(ticket,path,timestamp)

