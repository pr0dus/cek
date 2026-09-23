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
import re
import time
import uuid

UUID_VERSION = 7

#: Textual identity has exactly one spelling: lower-case, hyphenated, version
#: nibble 7, RFC 4122 variant. `uuid.UUID()` happily parses unhyphenated,
#: upper-case, braced and urn: forms, which would let the same identity be
#: committed under several distinct paths and defeat room-wide uniqueness.
CANONICAL_UUID7_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


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


def is_uuid7(value) -> bool:
    """True iff `value` is a UUIDv7 in its one canonical textual form."""
    if not isinstance(value, str) or not CANONICAL_UUID7_RE.match(value):
        return False
    try:
        return uuid.UUID(value).version == UUID_VERSION
    except ValueError:
        return False


def timestamp_ms(value: str) -> int:
    """Extract the embedded millisecond timestamp from a UUIDv7."""
    if not is_uuid7(value):
        raise ValueError(f"not a UUIDv7: {value!r}")
    return uuid.UUID(str(value)).int >> 80
