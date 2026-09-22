"""Canonical serialisation and envelope integrity.

The digest is worthless if two participants canonicalise differently, and the
append-only guarantee is worthless if a silent edit goes undetected on read.
Both are pinned here rather than trusted.
"""

import json

import pytest

from agent_room import canonical
from agent_room.errors import IntegrityError


def test_canonical_form_is_pinned():
    """Sorted keys, compact separators, no whitespace, non-ASCII preserved."""
    obj = {"b": 1, "a": "ünïcode", "nested": {"z": True, "y": None}}
    assert canonical.canonical_text(obj) == (
        '{"a":"ünïcode","b":1,"nested":{"y":null,"z":true}}'
    )


def test_canonical_form_is_key_order_independent():
    """Two writers emitting the same content in different order agree."""
    a = {"one": 1, "two": 2, "three": 3}
    b = {"three": 3, "two": 2, "one": 1}
    assert canonical.canonical_bytes(a) == canonical.canonical_bytes(b)
    assert canonical.envelope_digest(a) == canonical.envelope_digest(b)


def test_digest_excludes_itself():
    """A digest cannot cover its own value."""
    env = {"message_id": "x", "body": {"text": "hi"}}
    expected = canonical.envelope_digest(env)
    sealed = canonical.seal(env)
    assert sealed["envelope_sha256"] == expected
    assert canonical.envelope_digest(sealed) == expected


def test_digest_is_full_length_sha256():
    """Full 64 hex chars — truncation is what the design correction removed."""
    sealed = canonical.seal({"a": 1})
    assert len(sealed["envelope_sha256"]) == 64
    int(sealed["envelope_sha256"], 16)


def test_verify_accepts_untampered_envelope():
    canonical.verify(canonical.seal({"a": 1, "b": [1, 2, 3]}))


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda e: e.update({"body": {"text": "tampered"}}), id="body"),
        pytest.param(lambda e: e.update({"message_id": "other"}), id="identity"),
        pytest.param(lambda e: e.pop("timestamp"), id="field-removed"),
        pytest.param(lambda e: e.update({"extra": "added"}), id="field-added"),
    ],
)
def test_tampering_is_detected_on_read(mutate):
    """Any change to a sealed envelope must fail loudly."""
    sealed = canonical.seal(
        {"message_id": "m1", "timestamp": "2026-09-22T10:00:00Z", "body": {"text": "hi"}}
    )
    mutate(sealed)
    with pytest.raises(IntegrityError):
        canonical.verify(sealed)


def test_missing_digest_is_rejected():
    with pytest.raises(IntegrityError):
        canonical.verify({"message_id": "m1"})


def test_store_read_detects_tampering(store, room):
    """Editing a committed artifact behind the store's back is caught."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    path = store.workdir / posted["path"]

    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["body"] = {"text": "rewritten history"}
    path.write_text(canonical.canonical_text(envelope), encoding="utf-8")
    store._git("add", posted["path"])
    store._commit("tamper")

    with pytest.raises(IntegrityError):
        store.read("t1", posted["message_id"])
