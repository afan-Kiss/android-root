# -*- encoding: utf-8 -*-
"""Pure v39 X-Argus implementation.

Native MSSDK (PGZ110 / aweme 39.4) emits X-Argus as standard Base64 of the
sign-time Unix seconds packed as little-endian uint32. Confirmed on:

- SSL/H2 classic traffic (feed/settings): p9u887 18/18
- f3.a output for /aweme/v2/search/general/single/: 8/8

The header does **not** depend on URL, query ``ts``, or body. Native search
often leaves URL ``ts`` stale while X-Khronos / X-Argus use the current
sign timestamp. Callers must pass that same second-level khronos used for
X-Khronos.
"""
import base64
import time


def encrypt_argus(url: str = "", headers: dict = None, khronos: int = 0) -> str:
    """Return native-shaped X-Argus: Base64(khronos uint32 LE).

    ``url`` and ``headers`` are accepted for API compatibility and ignored.
    """
    del url, headers
    if not khronos:
        khronos = int(time.time())
    raw = int(khronos).to_bytes(4, "little", signed=False)
    return base64.b64encode(raw).decode()


if __name__ == "__main__":
    print(encrypt_argus(khronos=1782059386))
