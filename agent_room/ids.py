"""Message identity.

RFC 9562 UUIDv7, generated here rather than imported: Python 3.12's `uuid`
module has no `uuid7`, and the design (§3) wants the time-ordered prefix so
identifiers sort roughly chronologically. Adding a third-party dependency for
twenty lines of bit-packing would cost more than it saves, so this module
implements the layout directly and `uuid.UUID` validates the result.

Identity comes from the generator, never from hashing content — that is what
`envelope_sha256` is for, and conflating the two is the mistake the design
correction at cb13177 removed.
"""

import os
import time
import uuid

UUID_VERSION = 7


def uuid7(*, when_ms: int | None = None) -> str:
    """Return a new UUIDv7 string.

    Layout per RFC 9562 §5.7: 48-bit big-endian Unix timestamp in
    milliseconds, 4-bit version, 12 bits random, 2-bit variant, 62 bits
    random.
    """
    ts = int(time.time() * 1000) if when_ms is None else int(when_ms)
    if not 0 <= ts < 1 << 48:
        raise ValueError(f"timestamp out of 48-bit range: {ts}")

    rand = int.from_bytes(os.urandom(10), "big")  # 80 bits, 74 of them used
    rand_a = (rand >> 62) & 0xFFF
    rand_b = rand & ((1 << 62) - 1)

    value = (
        (ts << 80)
        | (UUID_VERSION << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return str(uuid.UUID(int=value))


def is_uuid7(value: str) -> bool:
    """True iff `value` parses as a UUID and declares version 7."""
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed.version == UUID_VERSION


def timestamp_ms(value: str) -> int:
    """Extract the embedded millisecond timestamp from a UUIDv7."""
    if not is_uuid7(value):
        raise ValueError(f"not a UUIDv7: {value!r}")
    return uuid.UUID(str(value)).int >> 80
