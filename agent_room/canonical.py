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
from collections.abc import Mapping
from typing import Any

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


def _reject_constant(name: str):
    """NaN/Infinity are JavaScript extensions, not JSON, and never round-trip."""
    raise SchemaError(f"stored JSON contains the non-standard constant {name}")


def strict_loads(text: str):
    """Parse JSON, rejecting duplicate keys and non-standard constants.

    Malformed stored JSON must surface as a SchemaError: a raw
    JSONDecodeError would escape the Agent Room contract the CLI relies on.
    """
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise SchemaError(f"stored artifact is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise SchemaError("stored artifact nests too deeply to parse") from exc


def canonical_bytes(obj: Any) -> bytes:
    """Serialise `obj` to the pinned canonical form.

    Every serialisation failure is converted: an unsupported type, a
    non-finite float, a lone surrogate that cannot be UTF-8 encoded, or a
    cycle must all fail as SchemaError rather than leaking TypeError /
    ValueError / UnicodeEncodeError to the caller.
    """
    try:
        text = json.dumps(
            obj,
            sort_keys=True,
            separators=SEPARATORS,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"value is not canonically serialisable: {exc}") from exc
    except RecursionError as exc:
        raise SchemaError("value nests too deeply to serialise") from exc
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchemaError(
            f"value contains text that is not encodable as UTF-8 "
            f"(lone surrogate?): {exc}"
        ) from exc


def canonical_text(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def require_mapping(envelope: Any, label: str = "envelope") -> Mapping:
    """A stored root must be a JSON object.

    `null`, arrays, numbers, booleans and bare strings are valid JSON but not
    valid envelopes. Without this they reach `.get()` / `.items()` and escape
    as a raw AttributeError or TypeError, which the CLI does not contract to
    catch.
    """
    if not isinstance(envelope, Mapping):
        raise SchemaError(
            f"{label} must be a JSON object, got "
            f"{type(envelope).__name__} {envelope!r}"
        )
    return envelope


def digest_payload(envelope: Mapping[str, Any]) -> dict:
    """The envelope minus its own digest field."""
    require_mapping(envelope)
    return {k: v for k, v in envelope.items() if k != DIGEST_FIELD}


def envelope_digest(envelope: Mapping[str, Any]) -> str:
    """Full 64-character SHA-256 over the canonical envelope."""
    return hashlib.sha256(canonical_bytes(digest_payload(envelope))).hexdigest()


def seal(envelope: Mapping[str, Any]) -> dict:
    """Return a copy of `envelope` carrying its computed digest."""
    require_mapping(envelope)
    sealed = dict(envelope)
    sealed[DIGEST_FIELD] = envelope_digest(envelope)
    return sealed


def verify(envelope: Mapping[str, Any]) -> None:
    """Raise `IntegrityError` unless the recorded digest matches the content.

    Called on every read. A mismatch means the artifact changed after commit,
    which append-only history forbids.
    """
    require_mapping(envelope)
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
