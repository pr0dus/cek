"""Envelope contract and epistemic rules.

Two things are proved here. Malformed input fails loudly rather than being
repaired into something plausible. And the epistemic rules from `PROCESS.md`
are mechanical: `supported` cannot be asserted without the scope, revision
condition and admissible evidence that make it meaningful.
"""

import pytest

from agent_room.errors import ClaimStateError, ForbiddenOperation, SchemaError
from agent_room.ids import is_uuid7, timestamp_ms, uuid7
from agent_room.schema import CLAIM_STATUS, LIFECYCLE_STATUS, validate_envelope


def envelope(**overrides):
    base = {
        "schema_version": 1,
        "message_id": uuid7(),
        "timestamp": "2026-09-22T10:00:00Z",
        "sender": {"agent": "claude-code"},
        "recipient": {"broadcast": True},
        "project": {"repo": "pr0dus/concept-evolution-kernel"},
        "thread_id": "t1",
        "type": "observation",
        "body": {"format": "markdown", "text": "hello"},
        "evidence": [],
        "status": "open",
        "reply_requested": False,
        "human_approval_required": False,
    }
    base.update(overrides)
    return base


# -- identity ---------------------------------------------------------------

def test_uuid7_is_version_7_and_time_ordered():
    early = uuid7(when_ms=1_700_000_000_000)
    late = uuid7(when_ms=1_800_000_000_000)
    assert is_uuid7(early) and is_uuid7(late)
    assert early < late, "UUIDv7 must sort chronologically by its timestamp prefix"
    assert timestamp_ms(early) == 1_700_000_000_000


def test_uuid7_values_are_distinct():
    assert len({uuid7(when_ms=1_700_000_000_000) for _ in range(1000)}) == 1000


def test_non_uuid7_message_id_is_rejected():
    with pytest.raises(SchemaError):
        validate_envelope(envelope(message_id="am-20260922-claude-7f3a9c"))


# -- structural -------------------------------------------------------------

def test_valid_envelope_passes():
    validate_envelope(envelope())


@pytest.mark.parametrize("field", [
    "schema_version", "message_id", "timestamp", "sender", "recipient",
    "project", "thread_id", "type", "body", "status",
    "reply_requested", "human_approval_required",
])
def test_every_required_field_is_enforced(field):
    """All Issue #1 fields are required, not merely documented."""
    env = envelope()
    del env[field]
    with pytest.raises(SchemaError):
        validate_envelope(env)


@pytest.mark.parametrize("bad", [
    pytest.param({"type": "gossip"}, id="unknown-type"),
    pytest.param({"status": "validated"}, id="no-generic-validated-lifecycle"),
    pytest.param({"schema_version": 99}, id="unsupported-schema-version"),
    pytest.param({"thread_id": "../escape"}, id="path-traversal-thread-id"),
    pytest.param({"thread_id": ""}, id="empty-thread-id"),
    pytest.param({"reply_requested": "yes"}, id="non-boolean-flag"),
    pytest.param({"sender": {}}, id="sender-without-agent"),
    pytest.param({"evidence": {"kind": "repo"}}, id="evidence-not-a-list"),
    pytest.param({"parent_id": "not-a-uuid"}, id="bad-parent-id"),
])
def test_malformed_envelopes_fail_loudly(bad):
    with pytest.raises(SchemaError):
        validate_envelope(envelope(**bad))


def test_repo_evidence_must_pin_an_immutable_commit():
    with pytest.raises(SchemaError):
        validate_envelope(envelope(evidence=[{"kind": "repo", "path": "a.py"}]))
    validate_envelope(envelope(evidence=[{"kind": "repo", "commit": "40ffdf46", "path": "a.py"}]))


def test_challenge_must_reference_what_it_contests():
    with pytest.raises(SchemaError):
        validate_envelope(envelope(type="challenge"))
    validate_envelope(envelope(type="challenge", parent_id=uuid7()))


# -- approval authority is withheld from agents -----------------------------

@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_agents_cannot_author_approval_or_rejection(mtype):
    """Issues #2-#4: the type is simply not available to an agent."""
    with pytest.raises(ForbiddenOperation):
        validate_envelope(envelope(type=mtype), agent_facing=True)


@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_approval_schema_is_reserved_not_deleted(mtype):
    """Reserved for Issue #5 — structurally valid, just not agent-authorable."""
    validate_envelope(envelope(type=mtype), agent_facing=False)


def test_agents_may_author_decision_request():
    validate_envelope(envelope(type="decision_request", human_approval_required=True))


# -- claim epistemic state --------------------------------------------------

def test_claim_vocabulary_is_exactly_process_md():
    assert CLAIM_STATUS == {"proposed", "challenged", "supported", "retracted"}
    assert "validated" not in CLAIM_STATUS
    assert "validated" not in LIFECYCLE_STATUS


def test_lifecycle_and_claim_state_are_independent():
    """An answered conversation says nothing about epistemic standing."""
    validate_envelope(envelope(
        type="claim", status="answered",
        claim={"status": "proposed"},
    ))


@pytest.mark.parametrize("status", ["validated", "true", "confirmed", ""])
def test_no_parallel_truth_state_is_accepted(status):
    with pytest.raises(ClaimStateError):
        validate_envelope(envelope(type="claim", claim={"status": status}))


def test_supported_requires_scope():
    """PROCESS.md rule 1 — a claim whose scope is unstated cannot be supported."""
    with pytest.raises(ClaimStateError, match="scope"):
        validate_envelope(envelope(type="claim", claim={
            "status": "supported", "revision_condition": "new counterexample",
            "evidence_basis": ["e1"],
        }))


def test_supported_requires_revision_condition():
    """PROCESS.md rule 3 — no revision condition means proposed at best."""
    with pytest.raises(ClaimStateError, match="revision_condition"):
        validate_envelope(envelope(type="claim", claim={
            "status": "supported", "scope": "at commit 40ffdf46",
            "evidence_basis": ["e1"],
        }))


def test_supported_requires_evidence_basis():
    with pytest.raises(ClaimStateError, match="evidence_basis"):
        validate_envelope(envelope(type="claim", claim={
            "status": "supported", "scope": "at commit 40ffdf46",
            "revision_condition": "a counterexample", "evidence_basis": [],
        }))


def test_agent_output_is_not_admissible_support():
    """LLM_OUTPUT != EVIDENCE, enforced rather than asserted."""
    with pytest.raises(ClaimStateError, match="not admissible"):
        validate_envelope(envelope(
            type="claim",
            evidence=[{"id": "e1", "kind": "agent_output", "note": "the other agent agreed"}],
            claim={
                "status": "supported", "scope": "at commit 40ffdf46",
                "revision_condition": "a counterexample", "evidence_basis": ["e1"],
            },
        ))


def test_repo_evidence_is_admissible_support():
    validate_envelope(envelope(
        type="claim",
        evidence=[{"id": "e1", "kind": "repo", "commit": "40ffdf46", "path": "x.py"}],
        claim={
            "status": "supported", "scope": "at commit 40ffdf46",
            "revision_condition": "a counterexample", "evidence_basis": ["e1"],
        },
    ))


def test_citing_evidence_does_not_promote_a_hypothesis():
    """Evidence refs are allowed anywhere and upgrade nothing by themselves."""
    env = envelope(
        type="hypothesis",
        evidence=[{"id": "e1", "kind": "repo", "commit": "40ffdf46", "path": "x.py"}],
        claim={"status": "proposed"},
    )
    validate_envelope(env)
    assert env["claim"]["status"] == "proposed"


@pytest.mark.parametrize("mtype", ["observation", "hypothesis", "claim", "evidence", "test_result"])
def test_any_assertion_type_may_cite_evidence(mtype):
    """Correction from the supervisor review: evidence is not evidence-only."""
    validate_envelope(envelope(
        type=mtype,
        evidence=[{"kind": "repo", "commit": "40ffdf46", "path": "x.py"}],
    ))


def test_non_assertion_types_may_not_carry_a_claim():
    with pytest.raises(SchemaError):
        validate_envelope(envelope(type="question", claim={"status": "proposed"}))
