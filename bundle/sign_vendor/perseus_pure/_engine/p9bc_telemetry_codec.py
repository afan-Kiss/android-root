"""Typed, order-preserving codec for the Perseus telemetry chunks."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from .p9bc_payload_transform import encode_varint

@dataclass(frozen=True)
class ProtoField:
    number: int
    wire_type: int
    value: int | bytes

def decode_varint(data: bytes, offset: int) -> tuple[int,int]:
    value=0;shift=0
    while offset<len(data):
        byte=data[offset];offset+=1;value|=(byte&0x7f)<<shift
        if byte<0x80:return value,offset
        shift+=7
    raise ValueError("truncated varint")

def parse_protobuf(data: bytes) -> list[ProtoField]:
    fields=[];offset=0
    while offset<len(data):
        tag,offset=decode_varint(data,offset);number=tag>>3;wire=tag&7
        if number==0:raise ValueError("invalid protobuf field zero")
        if wire==0:value,offset=decode_varint(data,offset)
        elif wire==1:value=int.from_bytes(data[offset:offset+8],"little");offset+=8
        elif wire==2:
            length,offset=decode_varint(data,offset);value=data[offset:offset+length];offset+=length
        elif wire==5:value=int.from_bytes(data[offset:offset+4],"little");offset+=4
        else:raise ValueError(f"unsupported wire type {wire}")
        fields.append(ProtoField(number,wire,value))
    return fields

def build_protobuf(fields: list[ProtoField]) -> bytes:
    out=bytearray()
    for field in fields:
        out+=encode_varint((field.number<<3)|field.wire_type)
        if field.wire_type==0:out+=encode_varint(int(field.value))
        elif field.wire_type==1:out+=int(field.value).to_bytes(8,"little")
        elif field.wire_type==2:
            value=bytes(field.value);out+=encode_varint(len(value))+value
        elif field.wire_type==5:out+=int(field.value).to_bytes(4,"little")
        else:raise ValueError(f"unsupported wire type {field.wire_type}")
    return bytes(out)

def parse_json_chunk(data: bytes) -> dict[str,Any]:
    value=json.loads(data.decode("utf-8"))
    if not isinstance(value,dict):raise ValueError("Perseus JSON chunk must be an object")
    return value

def build_json_chunk(value: dict[str,Any]) -> bytes:
    # Native samples use compact JSON and insertion order.
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=False).encode("utf-8")


def encode_zigzag64(value: int) -> int:
    """Encode a signed 64-bit integer to protobuf ZigZag domain."""
    if not -(1 << 63) <= value < (1 << 63):
        raise OverflowError("signed 64-bit value out of range")
    return (value << 1) ^ (value >> 63)

def decode_zigzag64(value: int) -> int:
    """Decode an unsigned protobuf ZigZag value."""
    if value < 0:
        raise ValueError("zigzag value must be unsigned")
    return (value >> 1) ^ -(value & 1)

def replace_varint_fields(data: bytes, replacements: dict[int, int]) -> bytes:
    """Order-preserving replacement for existing/additional varint fields."""
    fields=parse_protobuf(data); out=[]; seen=set()
    for field in fields:
        if field.number in replacements:
            if field.wire_type != 0:
                raise ValueError(f"protobuf field {field.number} is not varint")
            out.append(ProtoField(field.number,0,int(replacements[field.number])))
            seen.add(field.number)
        else:
            out.append(field)
    for number,value in replacements.items():
        if number not in seen: out.append(ProtoField(number,0,int(value)))
    return build_protobuf(out)

def replace_perseus_inner_clock_samples(data: bytes, *, field28_ms: int, field40_ms: int) -> bytes:
    """Replace outer field12 inner clock samples using confirmed sint64 encoding."""
    outer=parse_protobuf(data); out=[]; replaced=False
    for field in outer:
        if field.number==12 and field.wire_type==2 and not replaced:
            inner=replace_varint_fields(bytes(field.value),{28:encode_zigzag64(field28_ms),40:encode_zigzag64(field40_ms)})
            out.append(ProtoField(12,2,inner)); replaced=True
        else: out.append(field)
    if not replaced: raise ValueError("Perseus telemetry outer field12 unavailable")
    return build_protobuf(out)
