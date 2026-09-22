"""References must resolve: evidence basis, provenance, parent links, ack.

A dangling reference is worse than a missing one — it looks like support or
lineage while being neither. Everything here fails closed rather than writing
an edge that points nowhere.
"""

import pytest

from agent_room import AgentRoom, ParticipantCursor
from agent_room.errors import (
    AgentRoomError,
    ClaimStateError,
    ForbiddenOperation,
    SchemaError,
    UnresolvedReference,
)
from agent_room.ids import uuid7

FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "commit": FULL_SHA, "path": "newi_arc/metrics.py"}


def supported(**over):
    claim = {
        "status": "supported",
        "scope": f"at commit {FULL_SHA}",
        "revision_condition": "a counterexample in the same scope",
    }
    claim.update(over)
    return claim


# -- 4. evidence_basis must actually resolve --------------------------------

def test_nonexistent_basis_fails_closed(room):
    with pytest.raises(UnresolvedReference, match="does not resolve"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            claim=supported(evidence_basis=["no-such-evidence"]),
        )


def test_basis_naming_a_nonexistent_message_fails_closed(room):
    with pytest.raises(UnresolvedReference):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            claim=supported(evidence_basis=[uuid7()]),
        )


def test_in_message_agent_output_is_not_admissible(room):
    with pytest.raises(ClaimStateError, match="not admissible"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            evidence=[{"id": "e1", "kind": "agent_output", "note": "the other agent agreed"}],
            claim=supported(evidence_basis=["e1"]),
        )


def test_in_message_repo_evidence_is_admissible(room):
    posted = room.post(
        thread_id="t1", type="claim", body={"text": "c"},
        evidence=[dict(REPO_EVIDENCE, id="e1")],
        claim=supported(evidence_basis=["e1"]),
    )
    assert posted["status"] == "created"


def test_cross_message_agent_output_only_basis_is_rejected(room):
    """Two agents citing each other must never reach `supported`."""
    opinion = room.post(
        thread_id="t1", type="observation", body={"text": "I think so too"},
        evidence=[{"kind": "agent_output", "note": "model reasoning"}],
    )
    with pytest.raises(ClaimStateError, match="agent output alone is never support"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            claim=supported(evidence_basis=[opinion["message_id"]]),
        )


def test_cross_message_with_no_evidence_is_rejected(room):
    bare = room.post(thread_id="t1", type="observation", body={"text": "just an assertion"})
    with pytest.raises(ClaimStateError, match="no admissible evidence"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            claim=supported(evidence_basis=[bare["message_id"]]),
        )


def test_valid_cross_message_repo_evidence_supports_a_claim(room):
    grounded = room.post(
        thread_id="t1", type="evidence", body={"text": "the closure admits only active dependents"},
        evidence=[REPO_EVIDENCE],
    )
    posted = room.post(
        thread_id="t1", type="claim", body={"text": "c"},
        claim=supported(evidence_basis=[grounded["message_id"]]),
    )
    assert posted["status"] == "created"


@pytest.mark.parametrize("commit", ["40ffdf46", "main", "HEAD", "40ffdf4617283f4accb3493a8a710c5025c5d3b"])
def test_abbreviated_or_symbolic_commits_are_refused(room, commit):
    """An abbreviation is not an immutable identity."""
    with pytest.raises(SchemaError, match="full Git object ID"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "repo", "commit": commit, "path": "x.py"}])


def test_sha256_repo_object_ids_are_accepted(room):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "repo", "commit": "a" * 64, "path": "x.py"}])


# -- 5. provenance is not forgeable ----------------------------------------

@pytest.mark.parametrize("impostor", ["human", "openai-research", "supervisor"])
def test_a_room_cannot_post_as_another_participant(room, impostor):
    with pytest.raises(ForbiddenOperation, match="not forgeable"):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  sender={"agent": impostor})


def test_sender_agent_is_always_the_room_participant(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert room.get("t1", posted["message_id"])["sender"]["agent"] == "claude-code"


def test_model_and_operator_metadata_remain_configurable(room):
    posted = room.post(
        thread_id="t1", type="observation", body={"text": "x"},
        sender={"model": "claude-sonnet-5", "operator": "pr0"},
    )
    sender = room.get("t1", posted["message_id"])["sender"]
    assert sender == {"agent": "claude-code", "model": "claude-sonnet-5", "operator": "pr0"}


def test_declaring_your_own_identity_is_allowed(room):
    room.post(thread_id="t1", type="observation", body={"text": "x"},
              sender={"agent": "claude-code", "model": "claude-sonnet-5"})


# -- 6. parent and thread integrity ----------------------------------------

def test_orphan_parent_is_rejected(room):
    with pytest.raises(UnresolvedReference, match="does not resolve"):
        room.post(thread_id="t1", type="answer", body={"text": "x"}, parent_id=uuid7())


def test_cross_thread_parent_is_rejected(room):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    with pytest.raises(SchemaError, match="may not cross threads"):
        room.post(thread_id="t2", type="answer", body={"text": "!"},
                  parent_id=root["message_id"])


def test_reply_rejects_a_conflicting_thread_override(room):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    with pytest.raises(AgentRoomError, match="belongs to thread"):
        room.reply(root["message_id"], thread_id="t2", type="answer", body={"text": "!"})


def test_reply_to_unknown_parent_is_rejected(room):
    with pytest.raises(UnresolvedReference):
        room.reply(uuid7(), type="answer", body={"text": "!"})


def test_retraction_must_reference_what_it_retracts(room):
    with pytest.raises(SchemaError, match="must reference"):
        room.post(thread_id="t1", type="retraction", body={"text": "withdrawn"})


def test_challenge_must_reference_what_it_contests(room):
    with pytest.raises(SchemaError, match="must reference"):
        room.post(thread_id="t1", type="challenge", body={"text": "disputed"})


def test_valid_retraction_and_challenge_are_accepted(room):
    root = room.post(thread_id="t1", type="claim", body={"text": "c"},
                     claim={"status": "proposed"})
    room.reply(root["message_id"], type="challenge", body={"text": "disputed"})
    room.reply(root["message_id"], type="retraction", body={"text": "withdrawn"})
    assert len(room.thread("t1")) == 3


# -- 7. decision_request implies human approval -----------------------------

def test_decision_request_requires_human_approval_flag(room):
    with pytest.raises(SchemaError, match="human_approval_required=true"):
        room.post(thread_id="t1", type="decision_request", body={"text": "decide"})


def test_decision_request_with_the_flag_is_accepted(room):
    posted = room.post(thread_id="t1", type="decision_request", body={"text": "decide"},
                       human_approval_required=True)
    assert posted["status"] == "created"


# -- 8. acknowledge cannot manufacture state --------------------------------

def test_acknowledging_an_unknown_message_is_rejected(room):
    with pytest.raises(UnresolvedReference, match="unknown message"):
        room.acknowledge(uuid7())


def test_acknowledging_a_message_addressed_elsewhere_is_rejected(store, tmp_path):
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "c", "claude-code"))
    posted = claude.post(thread_id="t1", type="question", body={"text": "?"},
                         recipient={"agent": "openai-research"})

    bystander = AgentRoom(store, "other", ParticipantCursor(tmp_path / "o", "other"))
    with pytest.raises(AgentRoomError, match="not addressed"):
        bystander.acknowledge(posted["message_id"])
    assert not bystander.is_acknowledged(posted["message_id"])


def test_addressee_and_broadcast_acknowledgement_still_work(store, tmp_path):
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "c", "claude-code"))
    openai = AgentRoom(store, "openai-research", ParticipantCursor(tmp_path / "o", "openai-research"))

    directed = claude.post(thread_id="t1", type="question", body={"text": "?"},
                           recipient={"agent": "openai-research"})
    broadcast = claude.post(thread_id="t1", type="observation", body={"text": "all"})

    openai.acknowledge(directed["message_id"])
    openai.acknowledge(broadcast["message_id"])
    assert openai.inbox() == []
