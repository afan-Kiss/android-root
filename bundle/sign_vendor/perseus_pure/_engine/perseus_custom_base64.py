"""Encode and decode Perseus with a captured shuffled Base64 alphabet."""

from __future__ import annotations

import base64


STANDARD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# The v39 VM state page exposes four fixed shuffled alphabets. The selected
# pointer is page_base + 0x11 + 0x40 * index.
V39_ALPHABETS = (
    b"RUi5XVzoEfmtTMHNC4AhaLwcnQS+7Jgs9PlbrWxkuvF18yYjeOq/K23d0BDZ6pGI",
    b"LFOH7gSlYcbaijkWpfR62ICGNqesUBxVMm1/Q+0ZrhwnAz9TD4yv8udK3JXt5EoP",
    b"7XMBIYL+SHvPyO9dRbQ1tVunw/aZK3soj4ciGf86xDeT2gNmpkzEUhCA05WrFJlq",
    b"e/wOg5xKjuq0HkmGaWbr7VZSUMT4JoXzQ18lBc9yNYpFAhDLs3EnCP+RIivd6t2f",
)

V39_SELECTOR_IMMEDIATE_BASE = 0xA11
V39_SELECTOR_IMMEDIATE_STRIDE = 0x40



def alphabet_index_from_timestamp(timestamp: int) -> int:
    """Return the v39 alphabet selector used by the native VM.

    The same request Unix-seconds selector stored in VM table[10] selects both
    the scatter branch and one of the four fixed Base64 alphabets.
    """
    timestamp = int(timestamp)
    if timestamp < 0:
        raise ValueError("timestamp must be non-negative")
    return timestamp & 3


def alphabet_from_timestamp(timestamp: int) -> bytes:
    return V39_ALPHABETS[alphabet_index_from_timestamp(timestamp)]

def _table(source: bytes, target: bytes) -> bytes:
    if len(source) != 64 or len(target) != 64 or len(set(source)) != 64:
        raise ValueError("Base64 alphabet must be a 64-byte permutation")
    return bytes.maketrans(source, target)


def encode(data: bytes, alphabet: bytes) -> bytes:
    return base64.b64encode(data).translate(_table(STANDARD, alphabet))


def decode(data: bytes | str, alphabet: bytes) -> bytes:
    encoded = data.encode("ascii") if isinstance(data, str) else data
    return base64.b64decode(encoded.translate(_table(alphabet, STANDARD)), validate=True)


def alphabet_index_from_pointer(pointer: int) -> int:
    return ((pointer & 0xFF) - 0x11) // 0x40


def alphabet_from_pointer(pointer: int) -> bytes:
    index = alphabet_index_from_pointer(pointer)
    if not 0 <= index < len(V39_ALPHABETS):
        raise ValueError(f"invalid v39 alphabet pointer low byte: 0x{pointer & 0xff:02x}")
    return V39_ALPHABETS[index]


def alphabet_index_from_selector_instruction(instruction: bytes) -> int:
    """Decode the v39 vpc-74 selector instruction.

    The four program variants are materialized during VM program loading.
    Their signed immediate selects page offsets 0xa11, 0xa51, 0xa91 or
    0xad1; each points at one of the four fixed alphabets.
    """
    if len(instruction) < 4:
        raise ValueError("selector instruction must contain at least four bytes")
    if instruction[1] != 8:
        raise ValueError(f"selector destination slot must be 8, got {instruction[1]}")
    immediate = int.from_bytes(instruction[2:4], "little", signed=True)
    delta = immediate - V39_SELECTOR_IMMEDIATE_BASE
    if delta < 0 or delta % V39_SELECTOR_IMMEDIATE_STRIDE:
        raise ValueError(f"invalid v39 selector immediate: 0x{immediate & 0xffff:04x}")
    index = delta // V39_SELECTOR_IMMEDIATE_STRIDE
    if not 0 <= index < len(V39_ALPHABETS):
        raise ValueError(f"invalid v39 alphabet index: {index}")
    return index


def alphabet_from_selector_instruction(instruction: bytes) -> bytes:
    return V39_ALPHABETS[alphabet_index_from_selector_instruction(instruction)]


def encode_with_selector_instruction(data: bytes, instruction: bytes) -> bytes:
    return encode(data, alphabet_from_selector_instruction(instruction))
