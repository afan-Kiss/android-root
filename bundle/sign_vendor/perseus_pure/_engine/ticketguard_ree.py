"""Pure Python equivalents of Ticket Guard's REE primitives.

The current Douyin build stores a 32-byte P-256 private scalar as uppercase
hex. REE request authentication uses ECDH then HKDF-SHA256, then HMAC-SHA256.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


CURVE = ec.SECP256R1()

# Production Ticket Guard "ecies-server" P-256 point (CN=ecies-server).
# Recovered from device enrollment X.509 / query_server_cert.public_key.
DEFAULT_SERVER_PUBLIC_KEY_HEX = (
    "0484DA59433E57DCF11ABEE49E475E183879D1633E7085DD46BB241A2213F7E83F"
    "D9BB2F910B21CBF10A01316910876D0F240822BF02B678157FEA0A86D90244E8"
)

# Shared 32-byte suffix on production ts.1.* / key_sign (server identity, not device).
DEFAULT_TS_SIGN_SUFFIX = (
    "c4fbe87d2319cf05318624ceda14911ca406dedbebeddb2e30fce8d4fa02575d"
)

GET_CLIENT_CERT_URL = (
    "https://security.snssdk.com/passport/ticket_guard/get_client_cert/"
)
GET_SEC_TS_URL = "https://aweme.snssdk.com/passport/user_info/get_sec_ts/"

FormPoster = Callable[..., Any]


def _epoch_ms(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise EnrollmentError(f"{name} must be an integer timestamp")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise EnrollmentError(f"{name} must be an integer timestamp") from exc
    if parsed <= 0:
        raise EnrollmentError(f"{name} must be positive")
    return parsed * 1000 if parsed < 10_000_000_000 else parsed


def _required_text(payload: Mapping[str, Any], names: tuple[str, ...], label: str) -> str:
    for name in names:
        value = payload.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    raise EnrollmentError(f"TEE static material missing {label}")


def _normalize_tee_public_key(value: str) -> str:
    text = value.strip().replace("\n", "").replace("\r", "")
    if text.startswith("pub."):
        text = text[4:]
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.b64decode(text, validate=True)
        except (ValueError, TypeError) as exc:
            raise EnrollmentError("tee_pub_key must be a P-256 point in hex or base64") from exc
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)
    except ValueError as exc:
        raise EnrollmentError("tee_pub_key is not a valid P-256 point") from exc
    return base64.b64encode(raw).decode("ascii")


@dataclass(frozen=True)
class TeeStaticSignResult:
    """Validated device-produced Ticket-Guard TEE static material.

    This represents imported TEE output only. REE enrollment fields and REE
    HMAC state remain owned by :class:`TicketGuardDeviceState`.
    """

    tee_pub_key: str
    static_ts_sign: str
    key_sign: str
    sec_ts: str
    static_sign: str
    server_time_ms: int
    ttl_ms: int | None = None
    expires_at_ms: int | None = None

    @classmethod
    def from_material(
        cls,
        payload: str | bytes | Path | Mapping[str, Any],
    ) -> "TeeStaticSignResult":
        if isinstance(payload, Path):
            payload = payload.read_text(encoding="utf-8")
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8")
        if isinstance(payload, str):
            if not payload.lstrip().startswith(("{", "[")):
                try:
                    source = Path(payload)
                    if source.is_file():
                        payload = source.read_text(encoding="utf-8")
                except OSError:
                    pass
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise EnrollmentError("TEE static material must be JSON") from exc
        if not isinstance(payload, Mapping):
            raise EnrollmentError("TEE static material is not an object")
        nested = payload.get("data") or payload.get("result")
        data = nested if isinstance(nested, Mapping) else payload
        tee_pub_key = _normalize_tee_public_key(
            _required_text(data, ("tee_pub_key", "tee_public_key"), "tee_pub_key")
        )
        static_ts_sign = _required_text(
            data, ("static_ts_sign", "bd_ticket_guard_static_ts_sign"), "static_ts_sign"
        )
        key_sign = _required_text(data, ("key_sign", "bd_ticket_guard_key_sign"), "key_sign")
        sec_ts = _required_text(data, ("sec_ts", "server_sec_ts"), "sec_ts")
        if not sec_ts.startswith("#"):
            sec_ts = "#" + sec_ts
        static_sign = _required_text(
            data, ("static_sign", "sign", "bd_ticket_guard_static_sign"), "static_sign"
        )
        server_time = _epoch_ms(
            _required_text(data, ("server_time", "server_time_ms", "timestamp"), "server_time"),
            "server_time",
        )
        ttl_value = next(
            (data[name] for name in ("ttl_ms", "ttl", "ttl_s") if data.get(name) is not None),
            None,
        )
        ttl_ms = None
        if ttl_value is not None:
            try:
                ttl_ms = int(str(ttl_value).strip())
            except (TypeError, ValueError) as exc:
                raise EnrollmentError("ttl must be an integer") from exc
            if data.get("ttl_ms") is None:
                ttl_ms *= 1000
            if ttl_ms <= 0:
                raise EnrollmentError("ttl must be positive")
        expires_value = next(
            (data[name] for name in ("expires_at_ms", "expires_at", "expire_at") if data.get(name) is not None),
            None,
        )
        expires_at_ms = _epoch_ms(expires_value, "expires_at") if expires_value is not None else None
        if expires_at_ms is not None and expires_at_ms < server_time:
            raise EnrollmentError("expires_at must be after server_time")
        return cls(
            tee_pub_key=tee_pub_key,
            static_ts_sign=static_ts_sign,
            key_sign=key_sign,
            sec_ts=sec_ts,
            static_sign=static_sign,
            server_time_ms=server_time,
            ttl_ms=ttl_ms,
            expires_at_ms=expires_at_ms,
        )

    def is_fresh(self, now_ms: int | None = None) -> bool:
        now = int(time.time() * 1000) if now_ms is None else int(now_ms)
        expires = self.expires_at_ms
        if expires is None and self.ttl_ms is not None:
            expires = self.server_time_ms + self.ttl_ms
        return expires is None or now <= expires

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def enrollment_request_tag(*, init: bool = True) -> str:
    """Match TicketGuardNetworkHelper.LIZJ: `t={0|1};n=1`."""
    return f"t={0 if init else 1};n=1"


def _invoke_poster(
    poster: FormPoster,
    url: str,
    form: dict[str, str],
    headers: Mapping[str, str] | None = None,
):
    if headers:
        try:
            return poster(url, form, headers=dict(headers))
        except TypeError:
            try:
                return poster(url, form, dict(headers))
            except TypeError:
                pass
    return poster(url, form)


@dataclass
class TicketGuardDeviceState:
    private_key_hex: str
    server_public_key_hex: str | None = None
    client_cert: str | None = None
    static_ts_sign: str | None = None
    key_sign: str | None = None
    sec_ts: str | None = None
    iteration_version: int = 3
    server_cert: str | None = None
    server_sn: str | None = None
    enrollment_cert: str | None = None
    ts_sign_ree: str | None = None
    static_sign: str | None = None
    tee_static_result: TeeStaticSignResult | None = None

    def __post_init__(self) -> None:
        if isinstance(self.tee_static_result, Mapping):
            self.tee_static_result = TeeStaticSignResult.from_material(
                self.tee_static_result
            )
        if self.tee_static_result is not None:
            result = self.tee_static_result
            self.client_cert = encode_client_cert_header(result.tee_pub_key)
            self.static_ts_sign = result.static_ts_sign
            self.key_sign = result.key_sign
            self.sec_ts = result.sec_ts
            self.static_sign = result.static_sign

    @classmethod
    def create(cls):
        return cls(private_key_hex=generate_private_key_hex())

    @property
    def public_key_hex(self):
        return public_key_hex(self.private_key_hex)

    @property
    def public_key_base64(self):
        return base64.b64encode(bytes.fromhex(self.public_key_hex)).decode("ascii")

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path):
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        tee = payload.get("tee_static_result")
        if isinstance(tee, Mapping):
            payload["tee_static_result"] = TeeStaticSignResult(**tee)
        return cls(**payload)

    def resolved_server_public_key_hex(self) -> str:
        if self.server_public_key_hex:
            return normalize_public_key_hex(self.server_public_key_hex)
        if self.server_cert:
            return public_key_hex_from_certificate(self.server_cert)
        return DEFAULT_SERVER_PUBLIC_KEY_HEX

    def require_enrolled(self):
        missing = [name for name in (
            "client_cert", "static_ts_sign", "key_sign", "sec_ts",
        ) if not getattr(self, name)]
        if missing:
            raise ValueError("Ticket Guard enrollment is incomplete: " + ", ".join(missing))
        self.resolved_server_public_key_hex()
        return self

    @property
    def ree_enrolled(self) -> bool:
        try:
            self.require_enrolled()
        except ValueError:
            return False
        return True

    @property
    def tee_static_ready(self) -> bool:
        return bool(self.tee_static_result and self.tee_static_result.is_fresh())

    @property
    def request_ready(self) -> bool:
        return self.ree_enrolled and (
            self.tee_static_result is None or self.tee_static_ready
        )

    def status(self) -> dict[str, Any]:
        return {
            "ree_enrolled": self.ree_enrolled,
            "tee_static_ready": self.tee_static_ready,
            "request_ready": self.request_ready,
            "tee_static_expires_at_ms": (
                self.tee_static_result.expires_at_ms if self.tee_static_result else None
            ),
        }

    def resolved_ts_sign_ree(self) -> str:
        value = self.ts_sign_ree or self.static_ts_sign
        if not value:
            raise ValueError("Ticket Guard enrollment is incomplete: ts_sign_ree")
        return value

    def request_headers(self, ticket: str, path: str, timestamp: int):
        self.require_enrolled()
        if self.tee_static_result is not None and not self.tee_static_ready:
            raise ValueError("Ticket Guard TEE static material is expired")
        return {
            "bd-ticket-guard-version": "3",
            "bd-ticket-guard-iteration-version": str(self.iteration_version),
            "bd-ticket-guard-ree-public-key": self.public_key_base64,
            "bd-ticket-guard-client-cert": self.client_cert,
            "bd-ticket-guard-static-ts-sign": self.static_ts_sign,
            "bd-ticket-guard-key-sign": self.key_sign,
            "bd-ticket-guard-sec-ts": self.sec_ts,
            **({
                "bd-ticket-guard-static-sign": self.static_sign,
            } if self.static_sign else {}),
            "bd-ticket-guard-client-data": build_client_data(
                ticket, path, timestamp, self.private_key_hex,
                self.resolved_server_public_key_hex(), self.resolved_ts_sign_ree(),
            ),
        }

    def apply_enrollment_response(self, payload: str | bytes | Mapping[str, Any]):
        parsed = parse_enrollment_response(payload)
        self.enrollment_cert = parsed["cert"]
        if parsed["server_cert"]:
            self.server_cert = parsed["server_cert"]
            try:
                self.server_public_key_hex = public_key_hex_from_certificate(
                    parsed["server_cert"]
                )
            except ValueError:
                pass
        if parsed["server_sn"]:
            self.server_sn = parsed["server_sn"]
        if parsed.get("sec_ts"):
            self.apply_sec_ts(parsed["sec_ts"])
        if parsed.get("key_sign"):
            self.key_sign = parsed["key_sign"]
        if parsed.get("static_ts_sign"):
            self.static_ts_sign = parsed["static_ts_sign"]
        if parsed.get("ts_sign_ree"):
            self.ts_sign_ree = parsed["ts_sign_ree"]
        return self

    def apply_sec_ts(self, value: str | Mapping[str, Any] | None):
        if value is None:
            return self
        if isinstance(value, Mapping):
            data = value.get("data") if isinstance(value.get("data"), Mapping) else value
            extracted = None
            if isinstance(data, Mapping):
                extracted = data.get("sec_ts") or data.get("server_sec_ts")
            if not extracted:
                raise ValueError("sec_ts response has no sec_ts")
            value = str(extracted)
        text = str(value).strip()
        if text and not text.startswith("#"):
            text = "#" + text
        self.sec_ts = text
        return self

    def use_ree_client_cert_header(self):
        """Non-TEE header: Base64('pub.' + Base64(uncompressed REE point))."""
        self.client_cert = encode_client_cert_header(bytes.fromhex(self.public_key_hex))
        return self

    def bind_ree_ts_sign(self, content: bytes, *, suffix: str = DEFAULT_TS_SIGN_SUFFIX):
        """Store ts_sign_ree = ts.1. || HMAC-SHA256(aes, content) || server suffix."""
        digest = ree_hmac(
            derive_aes_key(self.private_key_hex, self.resolved_server_public_key_hex()),
            content,
        )
        self.ts_sign_ree = format_ts_sign(digest, suffix)
        return self

    def bind_ree_key_sign(self, *, suffix: str = DEFAULT_TS_SIGN_SUFFIX):
        digest = ree_hmac(
            derive_aes_key(self.private_key_hex, self.resolved_server_public_key_hex()),
            bytes.fromhex(self.public_key_hex),
        )
        self.key_sign = format_key_sign(digest, suffix)
        return self

    def apply_tee_static_sign_cache(
        self,
        payload: str | bytes | Path | Mapping[str, Any],
    ):
        """Import validated device-produced TEE static material."""
        result = TeeStaticSignResult.from_material(payload)
        self.tee_static_result = result
        self.client_cert = encode_client_cert_header(result.tee_pub_key)
        self.static_ts_sign = result.static_ts_sign
        self.key_sign = result.key_sign
        self.sec_ts = result.sec_ts
        self.static_sign = result.static_sign
        return self

    def refresh_sec_ts(
        self,
        poster: FormPoster,
        *,
        scene: str = "boot",
        extra_headers: Mapping[str, str] | None = None,
    ) -> str:
        """Fetch a fresh sec_ts from get_sec_ts and apply it to state."""
        headers = {"x-tt-request-tag": enrollment_request_tag(init=False)}
        if extra_headers:
            headers.update(dict(extra_headers))
        payload = _invoke_poster(
            poster, GET_SEC_TS_URL, {"update_scene": scene}, headers,
        )
        self.apply_sec_ts(payload)
        if not self.sec_ts:
            raise EnrollmentError("get_sec_ts returned no sec_ts")
        return self.sec_ts

    def finalize_ree_enrollment(
        self,
        *,
        bind_timestamp: int | None = None,
        sec_ts: str | Mapping[str, Any] | None = None,
        suffix: str = DEFAULT_TS_SIGN_SUFFIX,
    ):
        """Fill REE-mode static headers so require_enrolled() passes.

        Native 39.4 TEE devices overlay pub.TEE / static_ts_sign / key_sign from
        TeeStaticSignResult instead of these REE stand-ins.
        """
        if sec_ts is not None:
            self.apply_sec_ts(sec_ts)
        if not self.client_cert:
            self.use_ree_client_cert_header()
        ts = int(bind_timestamp if bind_timestamp is not None else time.time())
        if not self.ts_sign_ree:
            self.bind_ree_ts_sign(str(ts).encode("utf-8"), suffix=suffix)
        if not self.static_ts_sign:
            self.static_ts_sign = self.ts_sign_ree
        if not self.key_sign:
            self.bind_ree_key_sign(suffix=suffix)
        return self

    def enroll(
        self,
        poster: FormPoster,
        *,
        include_server_data: bool = True,
        extra_form: Mapping[str, str] | None = None,
        extra_headers: Mapping[str, str] | None = None,
        synthesize_ree_cert_header: bool = True,
        finalize: bool = True,
        sec_ts: str | Mapping[str, Any] | None = None,
        bind_timestamp: int | None = None,
        csr_mode: str = "public_key",
        common_name: str | None = None,
        fetch_sec_ts: bool | str = False,
    ):
        return enroll_with_poster(
            self,
            poster,
            include_server_data=include_server_data,
            extra_form=extra_form,
            extra_headers=extra_headers,
            synthesize_ree_cert_header=synthesize_ree_cert_header,
            finalize=finalize,
            sec_ts=sec_ts,
            bind_timestamp=bind_timestamp,
            csr_mode=csr_mode,
            common_name=common_name,
            fetch_sec_ts=fetch_sec_ts,
        )


def generate_private_key_hex() -> str:
    key = ec.generate_private_key(CURVE)
    value = key.private_numbers().private_value
    return value.to_bytes(32, "big").hex().upper()


def load_private_key(private_key_hex: str) -> ec.EllipticCurvePrivateKey:
    raw = bytes.fromhex(private_key_hex)
    if len(raw) != 32:
        raise ValueError("REE private key must be exactly 32 bytes")
    return ec.derive_private_key(int.from_bytes(raw, "big"), CURVE)


def public_key_hex(private_key_hex: str, compressed: bool = False) -> str:
    key = load_private_key(private_key_hex).public_key()
    fmt = (
        serialization.PublicFormat.CompressedPoint
        if compressed
        else serialization.PublicFormat.UncompressedPoint
    )
    return key.public_bytes(serialization.Encoding.X962, fmt).hex().upper()


def sign(content: bytes, private_key_hex: str) -> bytes:
    """Match DeltaSignerVerifier.Sign: SHA-256 then P-256 ECDSA/DER."""
    return load_private_key(private_key_hex).sign(content, ec.ECDSA(hashes.SHA256()))


def sign_base64(content: bytes, private_key_hex: str) -> str:
    return base64.b64encode(sign(content, private_key_hex)).decode("ascii")


def verify(content: bytes, signature: bytes, public_key_hex_value: str) -> bool:
    try:
        raw = bytes.fromhex(public_key_hex_value)
        key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)
        key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, TypeError):
        return False
    except Exception:
        return False


def normalize_public_key_hex(value: str) -> str:
    raw = bytes.fromhex(value.strip().replace(" ", ""))
    key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex().upper()


def public_key_hex_from_certificate(value: str | bytes) -> str:
    """Extract the uncompressed P-256 point from a Ticket Guard server cert.

    Accepts PEM, DER, hex DER, a raw 33/65-byte point, or the enrollment JSON
    blob (`cert_string` / `public_key`) stored as sp_key_server_cert.
    """
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore").strip() or None
        raw = value
    else:
        text = value.strip()
        raw = None
    if text and text.startswith("{"):
        data = json.loads(text)
        if data.get("public_key"):
            return normalize_public_key_hex(str(data["public_key"]))
        if data.get("cert_string"):
            return public_key_hex_from_certificate(str(data["cert_string"]))
        raise ValueError("server cert JSON has no public_key or cert_string")
    if text and text.startswith(("04", "02", "03")) and len(text) in (66, 130):
        return normalize_public_key_hex(text)
    cert = _load_x509(text, raw)
    public = cert.public_key()
    if not isinstance(public, EllipticCurvePublicKey):
        raise ValueError("server certificate public key is not EC")
    return public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex().upper()


def _load_x509(text: str | None, raw: bytes | None):
    candidates: list[bytes] = []
    if text:
        if "BEGIN CERTIFICATE" in text:
            return x509.load_pem_x509_certificate(text.encode("ascii"))
        try:
            candidates.append(base64.b64decode(text, validate=True))
        except (ValueError, TypeError):
            pass
        try:
            candidates.append(bytes.fromhex(text))
        except ValueError:
            pass
    if raw:
        candidates.append(raw)
    for blob in candidates:
        if not blob:
            continue
        try:
            return x509.load_der_x509_certificate(blob)
        except ValueError:
            continue
    raise ValueError("unable to parse Ticket Guard server certificate")


def derive_aes_key(private_key_hex: str, server_public_key_hex: str) -> bytes:
    """Match native Delta.generateAesKey.

    Shared secret is the P-256 ECDH x-coordinate. AES-256 material is
    RFC 5869 HKDF-SHA256 with omitted salt (HashLen zeros), empty info,
    and L=32. Java ReeKeyHelper then HMAC-SHA256s this key (LX/19wE.LJIILL).
    """
    private = load_private_key(private_key_hex)
    public = ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, bytes.fromhex(normalize_public_key_hex(server_public_key_hex))
    )
    shared = private.exchange(ec.ECDH(), public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"").derive(shared)


def ree_hmac(aes_key: bytes, content: bytes) -> bytes:
    """Match X.19wE.LJIILL: HMAC-SHA256."""
    return hmac.new(aes_key, content, hashlib.sha256).digest()


def request_content(ticket: str, path: str, timestamp: int) -> bytes:
    return f"ticket={ticket}&path={path}&timestamp={timestamp}".encode("utf-8")


def build_client_data(
    ticket: str,
    path: str,
    timestamp: int,
    private_key_hex: str,
    server_public_key_hex: str,
    ts_sign_ree: str,
) -> str:
    """Build the base64 JSON used by bd-ticket-guard-client-data."""
    aes_key = derive_aes_key(private_key_hex, server_public_key_hex)
    req_sign = ree_hmac(aes_key, request_content(ticket, path, timestamp))
    payload = {
        "req_content": "ticket,path,timestamp",
        "timestamp": timestamp,
        "ts_sign": "",
        "ts_sign_ree": ts_sign_ree,
        "req_sign": "",
        "req_sign_ree": base64.b64encode(req_sign).decode("ascii"),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.b64encode(raw).decode("ascii")


class EnrollmentError(ValueError):
    pass


def build_csr_der(private_key_hex: str, *, common_name: str | None = None) -> bytes:
    """P-256 PKCS#10 CSR (SHA-256 / ECDSA). Empty DN unless common_name is set."""
    key = load_private_key(private_key_hex)
    if common_name:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    else:
        name = x509.Name([])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def csr_string(
    private_key_hex: str,
    *,
    common_name: str | None = None,
    mode: str = "public_key",
) -> str:
    """CSR string posted as UTF-8 then Base64 (Android Base64.NO_WRAP).

    Native LJJI() has no PKCS#10 in zdplib; it returns GetPublicKeyUncompressed
    hex. `mode='pkcs10'` keeps a standard P-256 CSR as Base64(DER).
    """
    if mode == "pkcs10":
        return base64.b64encode(build_csr_der(private_key_hex, common_name=common_name)).decode("ascii")
    if mode != "public_key":
        raise ValueError("csr mode must be public_key or pkcs10")
    return public_key_hex(private_key_hex)


def csr_form_value(csr_text: str) -> str:
    """Android Base64.NO_WRAP of UTF-8(csr_string) for form field `csr`."""
    return base64.b64encode(csr_text.encode("utf-8")).decode("ascii")


def encode_client_cert_header(public_key_material: str | bytes) -> str:
    """Match native header: Base64(UTF-8('pub.' + newline-stripped material)).

    On TEE devices `material` is Base64(uncompressed TEE P-256 point).
    REE-only enrollment uses the REE uncompressed point the same way.
    """
    if isinstance(public_key_material, bytes):
        if public_key_material.startswith(b"pub."):
            text = public_key_material.decode("ascii")
        elif len(public_key_material) in (33, 65) and public_key_material[0] in (2, 3, 4):
            text = "pub." + base64.b64encode(public_key_material).decode("ascii")
        else:
            text = "pub." + public_key_material.decode("ascii")
    else:
        text = public_key_material.strip()
        if text.startswith("04") or text.startswith(("02", "03")):
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                raw = b""
            if len(raw) in (33, 65):
                text = "pub." + base64.b64encode(raw).decode("ascii")
        if not text.startswith("pub."):
            text = "pub." + text
    text = text.replace("\n", "").replace("\r", "")
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_client_cert_point(header_value: str) -> bytes:
    body = base64.b64decode(header_value)
    if body.startswith(b"pub."):
        body = body[4:]
    point = base64.b64decode(body)
    if len(point) not in (33, 65):
        raise ValueError("client_cert does not wrap a P-256 point")
    return point


def format_ts_sign(digest: bytes, suffix: str = DEFAULT_TS_SIGN_SUFFIX) -> str:
    if len(digest) != 32:
        raise ValueError("ts_sign digest must be 32 bytes")
    return f"ts.1.{digest.hex()}{suffix.lower()}"


def format_key_sign(digest: bytes, suffix: str = DEFAULT_TS_SIGN_SUFFIX) -> str:
    if len(digest) != 32:
        raise ValueError("key_sign digest must be 32 bytes")
    return digest.hex() + suffix.lower()


def parse_enrollment_response(payload: str | bytes | Mapping[str, Any]) -> dict[str, str | None]:
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, Mapping):
        raise EnrollmentError("enrollment response is not an object")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        data = payload
    cert = str(data.get("cert") or "")
    if not cert:
        raise EnrollmentError("enrollment response missing data.cert")
    server_cert = data.get("server_cert")
    server_sn = data.get("server_sn")
    return {
        "cert": cert,
        "server_cert": str(server_cert) if server_cert else None,
        "server_sn": str(server_sn) if server_sn else None,
        "sec_ts": str(data["sec_ts"]) if data.get("sec_ts") else None,
        "key_sign": str(data["key_sign"]) if data.get("key_sign") else None,
        "static_ts_sign": str(data.get("static_ts_sign") or data.get("ts_sign") or "") or None,
        "ts_sign_ree": str(data["ts_sign_ree"]) if data.get("ts_sign_ree") else None,
    }


def urllib_form_poster(
    url: str,
    form: dict[str, str],
    *,
    timeout: float = 30,
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    request = Request(url, data=urlencode(form).encode("utf-8"), method="POST")
    merged = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        merged.update(dict(headers))
    for key, value in merged.items():
        request.add_header(key, value)
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body)


def enroll_with_poster(
    state: TicketGuardDeviceState | None,
    poster: FormPoster,
    *,
    include_server_data: bool = True,
    extra_form: Mapping[str, str] | None = None,
    extra_headers: Mapping[str, str] | None = None,
    synthesize_ree_cert_header: bool = True,
    finalize: bool = True,
    sec_ts: str | Mapping[str, Any] | None = None,
    bind_timestamp: int | None = None,
    csr_mode: str = "public_key",
    common_name: str | None = None,
    fetch_sec_ts: bool | str = False,
) -> TicketGuardDeviceState:
    """POST CSR to get_client_cert, apply certs, then finalize REE static headers.

    Native extras: form `csr` + optional `server_data=1`, header
    `x-tt-request-tag: t={0|1};n=1`. `finalize=True` fills client_cert /
    ts_sign / key_sign. `sec_ts` comes from the enrollment response, `sec_ts=`,
    or `fetch_sec_ts=True` (poster GET_SEC_TS_URL); otherwise
    require_enrolled() still fails.
    """
    if state is None:
        state = TicketGuardDeviceState.create()
    csr = csr_string(state.private_key_hex, common_name=common_name, mode=csr_mode)
    form = {"csr": csr_form_value(csr)}
    if include_server_data:
        form["server_data"] = "1"
    if extra_form:
        form.update(dict(extra_form))
    headers = {
        "x-tt-request-tag": enrollment_request_tag(init=include_server_data),
    }
    if extra_headers:
        headers.update(dict(extra_headers))
    payload = _invoke_poster(poster, GET_CLIENT_CERT_URL, form, headers)
    state.apply_enrollment_response(payload)
    if synthesize_ree_cert_header and not state.client_cert:
        state.use_ree_client_cert_header()
    if fetch_sec_ts and not sec_ts and not state.sec_ts:
        scene = fetch_sec_ts if isinstance(fetch_sec_ts, str) else "boot"
        sec_payload = _invoke_poster(
            poster, GET_SEC_TS_URL, {"update_scene": scene}, headers,
        )
        state.apply_sec_ts(sec_payload)
    if finalize:
        state.finalize_ree_enrollment(bind_timestamp=bind_timestamp, sec_ts=sec_ts)
    return state


enroll = enroll_with_poster


__all__ = [
    "DEFAULT_SERVER_PUBLIC_KEY_HEX",
    "DEFAULT_TS_SIGN_SUFFIX",
    "GET_CLIENT_CERT_URL",
    "GET_SEC_TS_URL",
    "EnrollmentError",
    "TeeStaticSignResult",
    "TicketGuardDeviceState",
    "enrollment_request_tag",
    "public_key_hex_from_certificate",
]


if __name__ == "__main__":
    private = generate_private_key_hex()
    public = public_key_hex(private)
    sample = secrets.token_bytes(64)
    signature = sign(sample, private)
    print("private_key_hex=", private)
    print("public_key_hex=", public)
    print("signature_base64=", base64.b64encode(signature).decode("ascii"))
    print("verified=", verify(sample, signature, public))
