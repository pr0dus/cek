"""Canonical serialisation and envelope integrity.

The digest is only meaningful if every participant serialises identically, so
the canonical form is pinned here and asserted in tests rather than left to
each writer's json defaults.

Canonical form: UTF-8, sorted keys, compact separators, no insignificant
whitespace, `ensure_ascii=False` (so a non-ASCII body hashes the same whether
or not a writer happens to escape it).

`envelope_sha256` covers every immutable envelope field except itself — a
digest cannot cover its own value.
"""

import hashlib
import json
from typing import Any, Mapping

from .errors import IntegrityError, SchemaError

DIGEST_FIELD = "envelope_sha256"
SEPARATORS = (",", ":")


def _reject_duplicate_keys(pairs):
    """Object hook that refuses repeated keys.

    Python's decoder silently keeps the last value, so `{"type":"claim",
    "type":"approval"}` would hash and validate as one thing while a different
    reader saw another. At an audited boundary that ambiguity is a defect.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise SchemaError(f"duplicate JSON key {key!r} in stored artifact")
        seen.add(key)
    return dict(pairs)


def strict_loads(text: str):
    """Parse JSON, rejecting duplicate object keys."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def canonical_bytes(obj: Any) -> bytes:
    """Serialise `obj` to the pinned canonical form."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=SEPARATORS,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_text(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def digest_payload(envelope: Mapping[str, Any]) -> dict:
    """The envelope minus its own digest field."""
    return {k: v for k, v in envelope.items() if k != DIGEST_FIELD}


def envelope_digest(envelope: Mapping[str, Any]) -> str:
    """Full 64-character SHA-256 over the canonical envelope."""
    return hashlib.sha256(canonical_bytes(digest_payload(envelope))).hexdigest()


def seal(envelope: Mapping[str, Any]) -> dict:
    """Return a copy of `envelope` carrying its computed digest."""
    sealed = dict(envelope)
    sealed[DIGEST_FIELD] = envelope_digest(envelope)
    return sealed


def verify(envelope: Mapping[str, Any]) -> None:
    """Raise `IntegrityError` unless the recorded digest matches the content.

    Called on every read. A mismatch means the artifact changed after commit,
    which append-only history forbids.
    """
    recorded = envelope.get(DIGEST_FIELD)
    if not recorded:
        raise IntegrityError(
            f"message {envelope.get('message_id')!r} has no {DIGEST_FIELD}"
        )
    actual = envelope_digest(envelope)
    if actual != recorded:
        raise IntegrityError(
            f"digest mismatch for message {envelope.get('message_id')!r}: "
            f"recorded {recorded}, computed {actual}"
        )
