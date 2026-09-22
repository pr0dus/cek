"""Envelope contract and epistemic rules.

Two rule sets live here and are deliberately kept apart:

*Envelope validation* is structural — does the message carry the fields the
Issue #1 contract requires, with the right shapes.

*Claim validation* is epistemic, and reuses `PROCESS.md`'s ledger vocabulary
verbatim. There is no generic `validated` state. `supported` is evidence-
scoped, never universal truth, so it demands a stated scope, a revision
condition, and an admissible evidence basis. Citing evidence never promotes a
claim by itself — only a later message asserting the change can.
"""

from typing import Any, Mapping

import re

from .errors import (
    ClaimStateError,
    ForbiddenOperation,
    SchemaError,
    UnresolvedReference,
)
from .ids import is_uuid7

SCHEMA_VERSION = 1

MESSAGE_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
    "question", "challenge", "proposed_test",
    "answer", "retraction",
    "decision_request", "approval", "rejection", "handoff",
})

#: Withheld from agent-facing post/reply for Issues #2-#4 (design §6).
#: Mechanical human authority is Issue #5's problem, so rather than pretend to
#: verify a human we simply do not expose these types to an agent.
AGENT_FORBIDDEN_TYPES = frozenset({"approval", "rejection"})

#: Conversation flow only. Carries no epistemic weight.
LIFECYCLE_STATUS = frozenset({"open", "answered", "superseded", "withdrawn"})

#: PROCESS.md ledger vocabulary, used verbatim.
CLAIM_STATUS = frozenset({"proposed", "challenged", "supported", "retracted"})

EVIDENCE_KINDS = frozenset({"repo", "run", "external", "agent_output"})

#: LLM_OUTPUT != EVIDENCE. An agent's own output may be referenced, but it
#: cannot be what supports a claim, nor can it close a challenge.
INADMISSIBLE_FOR_SUPPORT = frozenset({"agent_output"})
ADMISSIBLE_FOR_SUPPORT = EVIDENCE_KINDS - INADMISSIBLE_FOR_SUPPORT

#: A pinned commit must be a full Git object ID: 40 hex for SHA-1, 64 for
#: SHA-256. An abbreviation is not an immutable identity - it can become
#: ambiguous as a repository grows, and it reads as a commit while not being
#: one.
FULL_COMMIT_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

#: A thread_id becomes a Git path segment and is parsed back out of
#: `git log --name-status` output line by line. Anything Git would quote or
#: escape - whitespace, control characters, separators, non-ASCII - could break
#: that parse or make a committed message undiscoverable, so the vocabulary is
#: deliberately narrow: ASCII letters/digits then letters/digits/./_/-, first
#: character alphanumeric (excluding leading dots), bounded at 64 characters.
THREAD_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
THREAD_ID_MAX = 64

REQUIRED_FIELDS = (
    "schema_version", "message_id", "timestamp", "sender", "recipient",
    "project", "thread_id", "type", "body", "status",
    "reply_requested", "human_approval_required",
)

#: Types that assert something and may therefore carry a `claim` object.
ASSERTION_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SchemaError(message)


def validate_evidence(evidence: Any) -> None:
    _require(isinstance(evidence, list), "evidence must be a list")
    seen_ids: set = set()
    for i, ref in enumerate(evidence):
        _require(isinstance(ref, dict), f"evidence[{i}] must be an object")
        ref_id = ref.get("id")
        if ref_id is not None:
            # Shape first: these ids are used as dict/set keys during basis
            # resolution, so an array or object would escape as a raw
            # TypeError instead of a controlled schema error.
            _require(
                isinstance(ref_id, str) and ref_id.strip() != "",
                f"evidence[{i}].id must be a non-empty string, got "
                f"{type(ref_id).__name__} {ref_id!r}",
            )
            # Duplicate ids would collapse when basis entries are resolved,
            # making admissibility depend on list order - an inadmissible
            # entry could hide behind an admissible one with the same id.
            _require(
                ref_id not in seen_ids,
                f"evidence[{i}].id {ref_id!r} is duplicated; evidence ids must "
                "be unique within a message",
            )
            seen_ids.add(ref_id)
        kind = ref.get("kind")
        _require(
            kind in EVIDENCE_KINDS,
            f"evidence[{i}].kind {kind!r} not in {sorted(EVIDENCE_KINDS)}",
        )
        if kind in ("repo", "run"):
            commit = ref.get("commit")
            _require(
                bool(commit),
                f"evidence[{i}] of kind {kind!r} must pin an immutable commit",
            )
            _require(
                isinstance(commit, str) and bool(FULL_COMMIT_RE.match(commit)),
                f"evidence[{i}].commit {commit!r} is not a full Git object ID "
                "(40 hex for SHA-1, 64 for SHA-256); an abbreviation is not an "
                "immutable identity",
            )


def message_is_admissible_support(message: dict) -> bool:
    """Documented cross-message admissibility rule.

    A referenced message supports a claim only if it carries at least one
    evidence entry of an admissible kind (`repo`, `run`, `external`). A message
    whose evidence is exclusively `agent_output`, or which carries none at all,
    is never support: that is `LLM_OUTPUT != EVIDENCE` made mechanical, and it
    is what stops two agents citing each other into `supported`.
    """
    for ref in message.get("evidence") or []:
        if isinstance(ref, dict) and ref.get("kind") in ADMISSIBLE_FOR_SUPPORT:
            return True
    return False


def validate_claim(claim, evidence=None, resolver=None, *, check_references: bool = True) -> None:
    """Apply PROCESS.md's ledger rules to a claim object.

    `check_references=False` performs structural checks only, skipping
    cross-message resolution. It exists so a message can be loaded raw while
    another message's references are being resolved, which is what keeps graph
    validation from recursing without bound.
    """
    _require(isinstance(claim, dict), "claim must be an object")
    status = claim.get("status")
    if status not in CLAIM_STATUS:
        raise ClaimStateError(
            f"claim.status {status!r} not in {sorted(CLAIM_STATUS)}; "
            "there is no generic 'validated' state"
        )

    if status != "supported":
        return

    # PROCESS.md rule 1: supported is evidence-scoped, never universal truth.
    if not str(claim.get("scope") or "").strip():
        raise ClaimStateError("claim.status 'supported' requires a non-empty scope")
    # PROCESS.md rule 3: no revision condition means 'proposed' at best.
    if not str(claim.get("revision_condition") or "").strip():
        raise ClaimStateError(
            "claim.status 'supported' requires a non-empty revision_condition"
        )

    basis = claim.get("evidence_basis") or []
    _require(isinstance(basis, list), "claim.evidence_basis must be a list")
    if not basis:
        raise ClaimStateError(
            "claim.status 'supported' requires a non-empty evidence_basis"
        )

    # Same reasoning as evidence ids: a basis entry is used as a lookup key,
    # so its shape must be checked before it is used as one.
    seen_basis: set = set()
    for i, entry in enumerate(basis):
        if not isinstance(entry, str) or entry.strip() == "":
            raise ClaimStateError(
                f"claim.evidence_basis[{i}] must be a non-empty string, got "
                f"{type(entry).__name__} {entry!r}"
            )
        if entry in seen_basis:
            raise ClaimStateError(
                f"claim.evidence_basis[{i}] {entry!r} is duplicated; a basis "
                "entry must be cited once"
            )
        seen_basis.add(entry)

    in_message = {
        ref["id"]: ref
        for ref in (evidence or [])
        if isinstance(ref, dict) and ref.get("id")
    }

    for entry in basis:
        # 1. An id naming evidence carried by this very message.
        ref = in_message.get(entry)
        if ref is not None:
            if ref.get("kind") in INADMISSIBLE_FOR_SUPPORT:
                raise ClaimStateError(
                    f"evidence {entry!r} is of kind {ref.get('kind')!r}, which is "
                    "not admissible support for 'supported' "
                    "(LLM_OUTPUT != EVIDENCE)"
                )
            continue

        # 2. Otherwise it must resolve to another message in the store.
        if not check_references:
            continue
        if resolver is None:
            raise UnresolvedReference(
                f"evidence_basis {entry!r} names neither evidence carried by this "
                "message nor anything resolvable; no resolver was available to "
                "check it, so it fails closed"
            )
        referenced = resolver.resolve_message(entry)
        if referenced is None:
            raise UnresolvedReference(
                f"evidence_basis {entry!r} does not resolve to evidence in this "
                "message or to any message in the store"
            )
        if not message_is_admissible_support(referenced):
            raise ClaimStateError(
                f"message {entry!r} carries no admissible evidence "
                f"({sorted(ADMISSIBLE_FOR_SUPPORT)}), so it cannot support a "
                "claim; agent output alone is never support"
            )


def validate_envelope(
    envelope: Mapping[str, Any],
    *,
    agent_facing: bool = True,
    resolver: Any = None,
    check_references: bool = True,
) -> None:
    """Structural and epistemic validation. Raises rather than repairing.

    `resolver` supplies `resolve_message(message_id)`. When present, references
    are resolved for real: a parent must exist and share the thread, and every
    evidence basis entry must resolve and be admissible.

    `check_references=False` restricts validation to this envelope alone. Reads
    use it for the raw phase so that resolving one message's references cannot
    recurse into resolving the referenced message's own references.
    """
    _require(isinstance(envelope, dict), "envelope must be an object")

    missing = [f for f in REQUIRED_FIELDS if f not in envelope]
    _require(not missing, f"envelope missing required fields: {missing}")

    _require(
        envelope["schema_version"] == SCHEMA_VERSION,
        f"unsupported schema_version {envelope['schema_version']!r}",
    )
    _require(
        is_uuid7(envelope["message_id"]),
        f"message_id {envelope['message_id']!r} is not a UUIDv7",
    )

    mtype = envelope["type"]
    _require(mtype in MESSAGE_TYPES, f"unknown message type {mtype!r}")
    if agent_facing and mtype in AGENT_FORBIDDEN_TYPES:
        raise ForbiddenOperation(
            f"agent-facing operations cannot author {mtype!r} messages; "
            "mechanical human authority arrives in Issue #5"
        )

    _require(
        envelope["status"] in LIFECYCLE_STATUS,
        f"status {envelope['status']!r} not in {sorted(LIFECYCLE_STATUS)}",
    )

    for field in ("thread_id", "timestamp"):
        _require(
            isinstance(envelope[field], str) and envelope[field].strip(),
            f"{field} must be a non-empty string",
        )
    _require(
        bool(THREAD_ID_RE.match(envelope["thread_id"])),
        f"thread_id {envelope['thread_id']!r} is not a safe path segment: "
        f"expected 1-{THREAD_ID_MAX} ASCII characters matching "
        "[A-Za-z0-9][A-Za-z0-9._-]*",
    )

    for field in ("sender", "recipient", "project", "body"):
        _require(isinstance(envelope[field], dict), f"{field} must be an object")
    _require(bool(envelope["sender"].get("agent")), "sender.agent is required")

    for field in ("reply_requested", "human_approval_required"):
        _require(isinstance(envelope[field], bool), f"{field} must be a boolean")

    parent = envelope.get("parent_id")
    if parent is not None:
        _require(is_uuid7(parent), f"parent_id {parent!r} is not a UUIDv7")

    # A challenge or retraction that references nothing cannot be audited
    # back to what it contests or withdraws.
    if mtype in ("challenge", "retraction"):
        _require(
            envelope.get("parent_id") is not None,
            f"a {mtype} must reference the message_id it "
            f"{'contests' if mtype == 'challenge' else 'retracts'}",
        )

    # The design says decision_request always implies human approval; accepting
    # it with the flag false would let an agent request a decision that no
    # gate is watching for.
    if mtype == "decision_request":
        _require(
            envelope["human_approval_required"] is True,
            "decision_request requires human_approval_required=true",
        )

    if parent is not None and resolver is not None and check_references:
        parent_message = resolver.resolve_message(parent)
        if parent_message is None:
            raise UnresolvedReference(
                f"parent_id {parent!r} does not resolve to a stored message"
            )
        if parent_message["thread_id"] != envelope["thread_id"]:
            raise SchemaError(
                f"parent {parent!r} belongs to thread "
                f"{parent_message['thread_id']!r}, not {envelope['thread_id']!r}; "
                "a reply may not cross threads"
            )

    validate_evidence(envelope.get("evidence", []))

    if "claim" in envelope and envelope["claim"] is not None:
        _require(
            mtype in ASSERTION_TYPES,
            f"message type {mtype!r} may not carry a claim object",
        )
        validate_claim(
            envelope["claim"], envelope.get("evidence", []), resolver,
            check_references=check_references,
        )
