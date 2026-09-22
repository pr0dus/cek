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

from .errors import ClaimStateError, ForbiddenOperation, SchemaError
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
    for i, ref in enumerate(evidence):
        _require(isinstance(ref, dict), f"evidence[{i}] must be an object")
        kind = ref.get("kind")
        _require(
            kind in EVIDENCE_KINDS,
            f"evidence[{i}].kind {kind!r} not in {sorted(EVIDENCE_KINDS)}",
        )
        if kind in ("repo", "run"):
            _require(
                bool(ref.get("commit")),
                f"evidence[{i}] of kind {kind!r} must pin an immutable commit",
            )


def validate_claim(claim: Any, evidence: list | None = None) -> None:
    """Apply PROCESS.md's ledger rules to a claim object."""
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

    # An evidence_basis entry may name another message, or index into this
    # message's own evidence[]. Only the latter is checkable here; agent_output
    # is never admissible support.
    by_id = {}
    for ref in evidence or []:
        if isinstance(ref, dict) and ref.get("id"):
            by_id[ref["id"]] = ref
    for entry in basis:
        ref = by_id.get(entry)
        if ref is not None and ref.get("kind") in INADMISSIBLE_FOR_SUPPORT:
            raise ClaimStateError(
                f"evidence of kind {ref.get('kind')!r} is not admissible support "
                "for 'supported' (LLM_OUTPUT != EVIDENCE)"
            )


def validate_envelope(envelope: Mapping[str, Any], *, agent_facing: bool = True) -> None:
    """Structural and epistemic validation. Raises rather than repairing."""
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
        "/" not in envelope["thread_id"] and not envelope["thread_id"].startswith("."),
        f"thread_id {envelope['thread_id']!r} must be a single safe path segment",
    )

    for field in ("sender", "recipient", "project", "body"):
        _require(isinstance(envelope[field], dict), f"{field} must be an object")
    _require(bool(envelope["sender"].get("agent")), "sender.agent is required")

    for field in ("reply_requested", "human_approval_required"):
        _require(isinstance(envelope[field], bool), f"{field} must be a boolean")

    parent = envelope.get("parent_id")
    if parent is not None:
        _require(is_uuid7(parent), f"parent_id {parent!r} is not a UUIDv7")

    if mtype == "challenge":
        _require(
            envelope.get("parent_id") is not None,
            "a challenge must reference the message_id it contests",
        )

    validate_evidence(envelope.get("evidence", []))

    if "claim" in envelope and envelope["claim"] is not None:
        _require(
            mtype in ASSERTION_TYPES,
            f"message type {mtype!r} may not carry a claim object",
        )
        validate_claim(envelope["claim"], envelope.get("evidence", []))
