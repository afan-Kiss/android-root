"""Pure producer model for the v39 X-Perseus transform random value.

The native chain is::

    SO+0x2c46cc -> SO+0x2800cc -> libc rand()

``SO+0x2800cc`` lazily seeds libc once with ``gettimeofday().tv_sec``.
During payload construction three consecutive wrapper results are produced and
XMXOR uses the middle result.  Exact replay of an already-running Android
process requires its libc PRNG state; generation of a fresh valid request only
requires a value in libc ``rand()``'s output domain.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable

RAND_MAX = 0x7FFFFFFF
WRAPPER_VALUE_COUNT = 3
TRANSFORM_RANDOM_WRAPPER_INDEX = 1


def validate_rand_output(value: int) -> int:
    """Validate and normalize one Android libc ``rand()`` result."""
    value = int(value)
    if not 0 <= value <= RAND_MAX:
        raise ValueError(f"rand output must be in [0, {RAND_MAX:#x}]")
    return value


def select_transform_random(wrapper_values: Iterable[int]) -> int:
    """Return the middle value from the native three-wrapper sequence."""
    values = tuple(validate_rand_output(value) for value in wrapper_values)
    if len(values) != WRAPPER_VALUE_COUNT:
        raise ValueError(
            f"expected {WRAPPER_VALUE_COUNT} wrapper values, got {len(values)}"
        )
    return values[TRANSFORM_RANDOM_WRAPPER_INDEX]


def generate_rand_value(
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> int:
    """Generate a fresh record/header random value in libc rand()'s domain."""
    return validate_rand_output(randbelow(RAND_MAX + 1))


def generate_transform_random(
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> int:
    """Generate a fresh value with the same range as Android libc ``rand()``.

    ``randbelow`` is injectable for deterministic tests.  This intentionally
    does not pretend to replay another process's hidden libc PRNG state.
    """
    return generate_rand_value(randbelow)


@dataclass(frozen=True)
class PerseusRandFlow:
    """Known five-call request flow around X-Perseus construction.

    Captures consistently expose a prelude call, three calls through
    ``SO+0x2c46cc``, and a later record/header call.  Additional unrelated calls
    may occur elsewhere in the process, so this object models the local flow,
    not the entire process-global libc state.
    """

    prelude: int
    wrapper_values: tuple[int, int, int]
    record: int

    def __post_init__(self) -> None:
        validate_rand_output(self.prelude)
        select_transform_random(self.wrapper_values)
        validate_rand_output(self.record)

    @property
    def transform_random(self) -> int:
        return select_transform_random(self.wrapper_values)
