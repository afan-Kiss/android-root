"""Pure-Python framing for the confirmed v39 Perseus record."""

from __future__ import annotations

import struct


VERSION = 1
FIELD13_MARKER = 13


def build_header(random_value: int, *, version: int = VERSION) -> bytes:
    if not 0 <= version <= 0xFFFFFFFF:
        raise ValueError("version must fit uint32")
    if not 0 <= random_value <= 0xFFFFFFFF:
        raise ValueError("random_value must fit uint32")
    return struct.pack("<II", version, random_value)


def build_record(random_value: int, field13: bytes, payload: bytes) -> bytes:
    if len(field13) != FIELD13_MARKER:
        raise ValueError("v39 Perseus field13 must contain exactly 13 bytes")
    return build_header(random_value) + bytes((FIELD13_MARKER,)) + field13 + payload


def parse_record(record: bytes) -> tuple[int, bytes, bytes]:
    if len(record) < 22:
        raise ValueError("Perseus record is truncated")
    version, random_value = struct.unpack_from("<II", record)
    if version != VERSION:
        raise ValueError(f"unsupported Perseus record version: {version}")
    field_length = record[8]
    if field_length != FIELD13_MARKER or len(record) < 9 + field_length:
        raise ValueError(f"invalid Perseus field length: {field_length}")
    return random_value, record[9:22], record[22:]
