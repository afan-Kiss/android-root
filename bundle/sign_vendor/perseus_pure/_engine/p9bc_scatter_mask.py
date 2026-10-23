"""Pure producer for the v39 X-Perseus 19-byte scatter mask."""
from __future__ import annotations
from .medusaEncrypt import V39_MASK_BIT_ORDER, V39_SIGN_KEY, xmxor
from .p9bc_payload_transform import _payload_key

SOURCE_LENGTH=19
CURRENT_SOURCE_BIT_BY_OUTPUT_BIT={0:7,1:3,2:6,3:4,4:1,5:2,6:0}

def generate_scatter_mask(source:bytes,pre_scatter:bytes)->bytes:
    if len(source)!=SOURCE_LENGTH: raise ValueError("scatter source must contain 19 bytes")
    if len(pre_scatter)<1+SOURCE_LENGTH*8: raise ValueError("pre-scatter payload is too short")
    mask=bytearray(SOURCE_LENGTH)
    for group in range(SOURCE_LENGTH):
        for output_bit,source_bit in CURRENT_SOURCE_BIT_BY_OUTPUT_BIT.items():
            old=(pre_scatter[1+group*8+output_bit]>>V39_MASK_BIT_ORDER[output_bit])&1
            desired=(source[group]>>source_bit)&1
            if old^desired: mask[group]|=1<<output_bit
        # The eighth selected bit crosses into the next u64 iteration.
        # It comes from next_source.bit5; the final group retains the old bit.
        if group+1<SOURCE_LENGTH:
            output_bit=7
            old=(pre_scatter[1+group*8+output_bit]>>V39_MASK_BIT_ORDER[output_bit])&1
            desired=(source[group+1]>>5)&1
            if old^desired: mask[group]|=1<<output_bit
    return bytes(mask)

def generate_scatter_mask_from_plaintext(source:bytes,plaintext:bytes,transform_random:int,sign_key:bytes=V39_SIGN_KEY)->bytes:
    key=_payload_key(transform_random,sign_key)
    pre=bytes(xmxor(bytearray(plaintext),bytearray(key)))
    return generate_scatter_mask(source,pre)


__all__ = ["generate_scatter_mask", "generate_scatter_mask_from_plaintext"]
