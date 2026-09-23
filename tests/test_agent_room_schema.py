"""Envelope contract and epistemic rules.

Two things are proved here. Malformed input fails loudly rather than being
repaired into something plausible. And the epistemic rules from `PROCESS.md`
are mechanical: `supported` cannot be asserted without the scope, revision
condition and admissible evidence that make it meaningful.
"""

import pytest

from agent_room.errors import ClaimStateError, ForbiddenOperation, SchemaError
from agent_room.ids import is_uuid7, timestamp_ms, uuid7
from agent_room.decision import binding_digest
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


def decision_envelope(mtype="approval", **overrides):
    """A complete Issue #5 human decision record, bound to a request."""
    request_id = uuid7()
    decision = {
        "decision_schema_version": 1,
        "decision_id": "hd-test-1",
        "decision": "approve" if mtype == "approval" else "reject",
        "decided_at": "2026-09-23T12:00:00Z",
        "request_message_id": request_id,
        "request_envelope_sha256": "c" * 64,
        "action_id": "activate-agent-room-transport",
        "action_scope": "create the production agent-room transport branch",
        "binding": {"snapshot_sha256": "a" * 64,
                    "supervisor_context_sha256": "b" * 64},
    }
    decision["decision_binding_sha256"] = binding_digest(decision)
    base = envelope(
        type=mtype, sender={"agent": "human"}, parent_id=request_id,
        decision=decision,
    )
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
    validate_envelope(envelope(evidence=[{"kind": "repo", "repo": "pr0dus/concept-evolution-kernel", "commit": "40ffdf4617283f4accb3493a8a710c5025c5d3bc", "path": "a.py"}]))


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
    """Authoritative in Issue #5 — valid only with a complete decision record."""
    validate_envelope(decision_envelope(mtype), agent_facing=False)


@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_a_decision_without_a_binding_record_is_refused(mtype):
    """An approval that binds to nothing could never be checked against anything."""
    bare = decision_envelope(mtype)
    del bare["decision"]
    with pytest.raises(SchemaError, match="must carry a 'decision' record"):
        validate_envelope(bare, agent_facing=False)


def test_an_ordinary_message_may_not_carry_a_decision_record():
    with pytest.raises(SchemaError, match="may not carry a 'decision' record"):
        validate_envelope(
            envelope(decision=decision_envelope("approval")["decision"]),
            agent_facing=False,
        )


def test_a_decision_verdict_must_agree_with_its_envelope_type():
    """`approve` carried by a `rejection` is a contradiction, not a preference."""
    mixed = decision_envelope("rejection")
    mixed["decision"]["decision"] = "approve"
    with pytest.raises(SchemaError, match="must be carried by a 'approval'"):
        validate_envelope(mixed, agent_facing=False)


def test_a_decision_must_reply_to_the_request_it_decides():
    orphan = decision_envelope("approval")
    orphan["parent_id"] = uuid7()
    with pytest.raises(SchemaError, match="must reply to the decision_request"):
        validate_envelope(orphan, agent_facing=False)


def test_a_bound_action_needs_both_binding_digests():
    for missing in ("snapshot_sha256", "supervisor_context_sha256"):
        action = {
            "action_id": "merge-infrastructure",
            "scope": "merge PR #8",
            "consequential": True,
            "binding": {"snapshot_sha256": "a" * 64,
                        "supervisor_context_sha256": "b" * 64},
        }
        del action["binding"][missing]
        with pytest.raises(SchemaError, match=f"missing {missing}"):
            validate_envelope(
                envelope(type="decision_request", human_approval_required=True,
                         action=action),
                agent_facing=False,
            )


def test_only_a_decision_request_may_bind_an_action():
    with pytest.raises(SchemaError, match="may not carry an 'action' binding"):
        validate_envelope(
            envelope(action={"action_id": "x", "scope": "y",
                             "consequential": True,
                             "binding": {"snapshot_sha256": "a" * 64,
                                         "supervisor_context_sha256": "b" * 64}}),
            agent_facing=False,
        )


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
            "status": "supported", "scope": "at commit 40ffdf4617283f4accb3493a8a710c5025c5d3bc",
            "evidence_basis": ["e1"],
        }))


def test_supported_requires_evidence_basis():
    with pytest.raises(ClaimStateError, match="evidence_basis"):
        validate_envelope(envelope(type="claim", claim={
            "status": "supported", "scope": "at commit 40ffdf4617283f4accb3493a8a710c5025c5d3bc",
            "revision_condition": "a counterexample", "evidence_basis": [],
        }))


def test_agent_output_is_not_admissible_support():
    """LLM_OUTPUT != EVIDENCE, enforced rather than asserted."""
    with pytest.raises(ClaimStateError, match="not admissible"):
        validate_envelope(envelope(
            type="claim",
            evidence=[{"id": "e1", "kind": "agent_output", "note": "the other agent agreed"}],
            claim={
                "status": "supported", "scope": "at commit 40ffdf4617283f4accb3493a8a710c5025c5d3bc",
                "revision_condition": "a counterexample", "evidence_basis": ["e1"],
            },
        ))


def test_repo_evidence_is_admissible_support():
    validate_envelope(envelope(
        type="claim",
        evidence=[{"id": "e1", "kind": "repo", "repo": "pr0dus/concept-evolution-kernel",
                   "commit": "40ffdf4617283f4accb3493a8a710c5025c5d3bc", "path": "x.py"}],
        claim={
            "status": "supported", "scope": "at commit 40ffdf4617283f4accb3493a8a710c5025c5d3bc",
            "revision_condition": "a counterexample", "evidence_basis": ["e1"],
        },
    ))


def test_citing_evidence_does_not_promote_a_hypothesis():
    """Evidence refs are allowed anywhere and upgrade nothing by themselves."""
    env = envelope(
        type="hypothesis",
        evidence=[{"id": "e1", "kind": "repo", "repo": "pr0dus/concept-evolution-kernel",
                   "commit": "40ffdf4617283f4accb3493a8a710c5025c5d3bc", "path": "x.py"}],
        claim={"status": "proposed"},
    )
    validate_envelope(env)
    assert env["claim"]["status"] == "proposed"


@pytest.mark.parametrize("mtype", ["observation", "hypothesis", "claim", "evidence", "test_result"])
def test_any_assertion_type_may_cite_evidence(mtype):
    """Correction from the supervisor review: evidence is not evidence-only."""
    validate_envelope(envelope(
        type=mtype,
        evidence=[{"kind": "repo", "repo": "pr0dus/concept-evolution-kernel", "commit": "40ffdf4617283f4accb3493a8a710c5025c5d3bc", "path": "x.py"}],
    ))


def test_non_assertion_types_may_not_carry_a_claim():
    with pytest.raises(SchemaError):
        validate_envelope(envelope(type="question", claim={"status": "proposed"}))
