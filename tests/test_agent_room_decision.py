"""Mechanical human authority and the release gate (Issue #5 §1, §7, §10).

Two questions are under test. Can any AI surface author an approval? And does
an approval release exactly the action it was given for, and nothing else —
not a changed action, not a changed snapshot, not a moved conversation.

Both are answered by construction rather than by inspection of intent: the
authority-bearing write path is simply not reachable from an agent, and the
gate re-derives every binding from durable state before it releases anything.
"""

import inspect
import json
import pathlib

import pytest

from agent_room import canonical
from agent_room.claude_participant import ClaudeParticipant
from agent_room.codex_participant import CodexParticipant
from agent_room.cursor import ParticipantCursor
from agent_room.decision import (
    HUMAN_PARTICIPANT,
    DecisionError,
    GateBlocked,
    HumanDecisionAuthority,
    assert_releasable,
    binding_digest,
    evaluate_gate,
    pending_requests,
)
from agent_room.errors import ForbiddenOperation, SchemaError
from agent_room.ids import uuid7
from agent_room.room import AgentRoom
from agent_room.supervisor import SupervisorBoundary
from agent_room.tool_profiles import KNOWN_PROFILES, QUALIFIED_PROFILES
from tests.conftest_agent_room import (
    CONTEXT_SHA,
    SNAPSHOT_SHA,
    bound_action,
    post_decision_request,
)

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "agent_room"


def stub(payload):
    def invoke(prompt):
        return payload if isinstance(payload, str) else json.dumps(payload)
    return invoke


# ===== 1. no AI surface can author a decision ==============================

def test_the_room_refuses_to_post_an_approval(room):
    for mtype in ("approval", "rejection"):
        with pytest.raises(ForbiddenOperation):
            room.post(thread_id="t1", type=mtype, body={"text": "I approve"})


def test_the_store_append_path_refuses_an_approval(store, room):
    """`append` is exported, so it must refuse too — not only `post`."""
    request = post_decision_request(room)
    recorded = HumanDecisionAuthority(store).record(
        request["message_id"], "approve")
    stored = store.read("t1", recorded["message_id"])
    replay = {k: v for k, v in stored.items() if k != canonical.DIGEST_FIELD}
    replay["message_id"] = uuid7()
    with pytest.raises(ForbiddenOperation, match="cannot author"):
        store.append(canonical.seal(replay))


def test_no_agent_room_may_wear_the_human_identity(store, tmp_path):
    with pytest.raises(ForbiddenOperation, match="reserved"):
        AgentRoom(store, HUMAN_PARTICIPANT,
                  ParticipantCursor(tmp_path / "h", HUMAN_PARTICIPANT))


@pytest.mark.parametrize("adapter_class,participant", [
    (ClaudeParticipant, "claude-code"),
    (CodexParticipant, "codex"),
])
def test_a_coding_participant_cannot_return_an_approval(
        store, tmp_path, adapter_class, participant):
    room = AgentRoom(store, participant,
                     ParticipantCursor(tmp_path / participant, participant))
    adapter = adapter_class(room, stub({"type": "approval",
                                        "body": {"text": "approved"}}))
    with pytest.raises(Exception) as caught:
        adapter.parse_response(json.dumps(
            {"type": "approval", "body": {"text": "approved"}}))
    assert "approval" in str(caught.value)


def test_the_supervisor_boundary_cannot_import_an_approval(store, tmp_path):
    room = AgentRoom(store, "claude-code",
                     ParticipantCursor(tmp_path / "c", "claude-code"))
    target = room.post(thread_id="t1", type="question", body={"text": "?"},
                       recipient={"agent": "openai-research"})
    supervisor_room = AgentRoom(
        store, "openai-research",
        ParticipantCursor(tmp_path / "o", "openai-research"))
    boundary = SupervisorBoundary(supervisor_room)
    packet = boundary.export(target["message_id"])
    document = {
        "packet_schema_version": packet["packet_schema_version"],
        "target_message_id": packet["target_message_id"],
        "context_sha256": packet["context_sha256"],
        "response": {"type": "approval", "body": {"text": "approved"}},
    }
    with pytest.raises(Exception) as caught:
        boundary.import_response(json.dumps(document))
    assert "approval" in str(caught.value)
    assert [m["type"] for m in room.thread("t1")] == ["question"]


def test_no_participant_or_orchestrator_module_reaches_the_authority_surface():
    """Capability separation, checked in the source rather than asserted.

    If any of these modules could call the authority surface, "an agent cannot
    approve" would rest on nobody having written the call yet.
    """
    forbidden = ("HumanDecisionAuthority", "append_decision")
    for name in ("participant.py", "claude_participant.py",
                 "codex_participant.py", "supervisor.py", "orchestrator.py",
                 "room.py"):
        source = (PACKAGE / name).read_text(encoding="utf-8")
        for symbol in forbidden:
            assert symbol not in source, (
                f"{name} references {symbol}; the human decision surface must "
                "be unreachable from participant and orchestrator code"
            )


def test_the_cli_shows_what_would_be_decided_without_deciding(store, room, capsys):
    """`--show` must stand alone: read first, decide second."""
    from agent_room.cli import main

    request = post_decision_request(room)
    code = main(["--repo", str(store.workdir), "--participant", "human",
                 "human-decide", "--request-id", request["message_id"], "--show"])
    assert code == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["action_id"] == "activate-agent-room-transport"
    assert shown["binding"]["snapshot_sha256"] == SNAPSHOT_SHA
    assert evaluate_gate(store, request["message_id"])["decisions"] == []


def test_the_cli_needs_a_verdict_before_it_will_record_anything(store, room, capsys):
    from agent_room.cli import main

    request = post_decision_request(room)
    code = main(["--repo", str(store.workdir), "--participant", "human",
                 "human-decide", "--request-id", request["message_id"],
                 "--confirm-human"])
    assert code == 2
    assert "--decision approve|reject" in capsys.readouterr().err


def test_the_cli_never_records_a_decision_without_explicit_human_confirmation(
        store, room, capsys):
    from agent_room.cli import main

    request = post_decision_request(room)
    code = main(["--repo", str(store.workdir), "--participant", "human",
                 "human-decide", "--request-id", request["message_id"],
                 "--decision", "approve"])
    assert code == 2
    assert "--confirm-human" in capsys.readouterr().err
    assert evaluate_gate(store, request["message_id"])["decisions"] == []


# ===== 2. the record binds request + snapshot + context ====================

def test_a_decision_binds_everything_it_decided(store, room):
    request = post_decision_request(room)
    stored_request = store.resolve_message(request["message_id"])
    recorded = HumanDecisionAuthority(store).record(
        request["message_id"], "approve", decision_id="hd-1")

    decision = store.read("t1", recorded["message_id"])["decision"]
    assert decision["request_message_id"] == request["message_id"]
    assert decision["request_envelope_sha256"] == \
        stored_request[canonical.DIGEST_FIELD]
    assert decision["binding"]["snapshot_sha256"] == SNAPSHOT_SHA
    assert decision["binding"]["supervisor_context_sha256"] == CONTEXT_SHA
    assert decision["action_id"] == "activate-agent-room-transport"
    assert decision["decision_binding_sha256"] == binding_digest(decision)


def test_the_binding_digest_ignores_who_typed_it_and_when(store, room):
    """Same decision about the same thing hashes the same."""
    request = post_decision_request(room)
    base = HumanDecisionAuthority(store).record(
        request["message_id"], "approve", decision_id="hd-a",
        timestamp="2026-09-23T10:00:00Z")
    first = store.read("t1", base["message_id"])["decision"]
    second = dict(first, decision_id="hd-b", decided_at="2026-09-23T23:59:59Z")
    assert binding_digest(second) == binding_digest(first)


def test_the_authority_surface_refuses_a_mistaken_expectation(store, room):
    request = post_decision_request(room)
    with pytest.raises(DecisionError, match="you named snapshot_sha256"):
        HumanDecisionAuthority(store).record(
            request["message_id"], "approve",
            expect_snapshot_sha256="f" * 64)
    assert evaluate_gate(store, request["message_id"])["decisions"] == []


def test_the_authority_surface_derives_bindings_from_the_stored_request(
        store, room):
    """A caller cannot smuggle a different snapshot into the record."""
    signature = inspect.signature(HumanDecisionAuthority.record)
    supplied = set(signature.parameters) - {"self", "request_message_id",
                                            "verdict"}
    assert supplied == {
        "decision_id", "note", "expect_snapshot_sha256",
        "expect_supervisor_context_sha256", "expect_action_id", "timestamp",
    }, "record() must take no binding value it would trust over the request"


def test_an_unbound_decision_request_can_never_release_anything(store, room):
    plain = room.post(thread_id="t1", type="decision_request",
                      body={"text": "what do you think?"},
                      human_approval_required=True)
    report = evaluate_gate(store, plain["message_id"])
    assert report["state"] == "blocked_unbound"
    assert not report["releasable"]
    with pytest.raises(DecisionError, match="no bound action"):
        HumanDecisionAuthority(store).describe(plain["message_id"])


# ===== 4/5. no approval, and rejection, both block =========================

def test_with_no_decision_the_action_is_blocked(store, room):
    request = post_decision_request(room)
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256=SNAPSHOT_SHA,
                           supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "blocked_no_decision"
    assert not report["releasable"]
    assert any("no timeout" in reason for reason in report["reasons"])


def test_a_rejection_blocks(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "reject",
                                         decision_id="hd-no")
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256=SNAPSHOT_SHA,
                           supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "blocked_rejected"
    assert not report["releasable"]


def test_a_rejection_after_an_approval_blocks_again(store, room):
    """The human's latest word is the one that counts."""
    request = post_decision_request(room)
    authority = HumanDecisionAuthority(store)
    authority.record(request["message_id"], "approve", decision_id="hd-yes")
    assert evaluate_gate(store, request["message_id"],
                         snapshot_sha256=SNAPSHOT_SHA,
                         supervisor_context_sha256=CONTEXT_SHA)["releasable"]
    authority.record(request["message_id"], "reject", decision_id="hd-no")
    assert evaluate_gate(store, request["message_id"],
                         snapshot_sha256=SNAPSHOT_SHA,
                         supervisor_context_sha256=CONTEXT_SHA
                         )["state"] == "blocked_rejected"


# ===== 3/6. exact approval releases exactly the bound action ===============

def test_an_exact_approval_releases_the_bound_action(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    report = assert_releasable(
        store, request["message_id"],
        snapshot_sha256=SNAPSHOT_SHA, supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "released"
    assert report["action_id"] == "activate-agent-room-transport"


def test_a_moved_snapshot_makes_the_approval_stale(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256="9" * 64,
                           supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "blocked_stale"
    assert any("snapshot_sha256 has moved" in r for r in report["reasons"])


def test_a_moved_supervisor_context_makes_the_approval_stale(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256=SNAPSHOT_SHA,
                           supervisor_context_sha256="9" * 64)
    assert report["state"] == "blocked_stale"
    assert any("supervisor_context_sha256 has moved" in r
               for r in report["reasons"])


def test_an_approval_of_one_action_does_not_release_another(store, room):
    """The whole point: approval is per-action, not a mood."""
    merge = post_decision_request(room, action_id="merge-infrastructure",
                                  scope="merge PR #8 into main")
    activate = post_decision_request(room, action_id="activate-transport",
                                     scope="create the live branch")
    HumanDecisionAuthority(store).record(merge["message_id"], "approve")

    assert evaluate_gate(store, merge["message_id"],
                         snapshot_sha256=SNAPSHOT_SHA,
                         supervisor_context_sha256=CONTEXT_SHA)["releasable"]
    other = evaluate_gate(store, activate["message_id"],
                          snapshot_sha256=SNAPSHOT_SHA,
                          supervisor_context_sha256=CONTEXT_SHA)
    assert other["state"] == "blocked_no_decision"
    assert not other["releasable"]


def test_a_decision_record_edited_after_the_fact_does_not_release(store, room):
    """The store would catch the tamper; the gate must not release even so."""
    request = post_decision_request(room)
    recorded = HumanDecisionAuthority(store).record(
        request["message_id"], "approve")
    stored = store.read("t1", recorded["message_id"])
    forged = dict(stored["decision"])
    forged["binding"] = dict(forged["binding"], snapshot_sha256="e" * 64)

    class Tampered:
        """A store whose decision content disagrees with its digest."""

        def __init__(self, real):
            self.real = real

        def resolve_message(self, mid):
            return self.real.resolve_message(mid)

        def thread_messages(self, thread_id):
            out = []
            for message in self.real.thread_messages(thread_id):
                if message["message_id"] == stored["message_id"]:
                    message = dict(message, decision=forged)
                out.append(message)
            return out

    report = evaluate_gate(Tampered(store), request["message_id"],
                           snapshot_sha256=SNAPSHOT_SHA,
                           supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "blocked_stale"
    assert any("binding digest does not match" in r for r in report["reasons"])


def test_a_decision_from_a_non_human_identity_carries_no_authority(store, room):
    """Reached only by bypassing the surface; it must still not release."""
    request = post_decision_request(room)
    recorded = HumanDecisionAuthority(store).record(
        request["message_id"], "approve")
    stored = store.read("t1", recorded["message_id"])
    impostor = dict(stored, sender={"agent": "claude-code"})

    class Impostor:
        def __init__(self, real):
            self.real = real

        def resolve_message(self, mid):
            return self.real.resolve_message(mid)

        def thread_messages(self, thread_id):
            return [
                impostor if m["message_id"] == stored["message_id"] else m
                for m in self.real.thread_messages(thread_id)
            ]

    report = evaluate_gate(Impostor(store), request["message_id"])
    assert not report["releasable"]
    assert any("not the reserved human identity" in r for r in report["reasons"])


# ===== 3b. an unmeasured gate never releases ===============================

def test_an_approval_does_not_release_when_nothing_was_measured(store, room):
    """The gate must fail closed, not warn and release anyway.

    An approval says "this state, as I reviewed it, may go ahead". A gate that
    has not looked at current state has established nothing about whether that
    state still exists, so it cannot say the action is releasable - however
    internally consistent the stored record is.
    """
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")

    report = evaluate_gate(store, request["message_id"])
    assert report["state"] == "blocked_unmeasured"
    assert report["releasable"] is False
    assert report["unmeasured"] == ["snapshot_sha256",
                                    "supervisor_context_sha256"]
    assert all("cannot establish that the approved state still exists" in r
               for r in report["reasons"])


@pytest.mark.parametrize("measured,missing", [
    ("snapshot_sha256", "supervisor_context_sha256"),
    ("supervisor_context_sha256", "snapshot_sha256"),
])
def test_measuring_only_one_of_the_two_still_blocks(store, room, measured,
                                                    missing):
    """Half a measurement is not half a release; it is no release."""
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")

    observations = {"snapshot_sha256": SNAPSHOT_SHA,
                    "supervisor_context_sha256": CONTEXT_SHA}
    report = evaluate_gate(
        store, request["message_id"],
        **{measured: observations[measured], missing: None})
    assert report["state"] == "blocked_unmeasured"
    assert report["releasable"] is False
    assert report["unmeasured"] == [missing]


def test_only_both_exact_measurements_release(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256=SNAPSHOT_SHA,
                           supervisor_context_sha256=CONTEXT_SHA)
    assert report["state"] == "released"
    assert report["releasable"] is True
    assert report["unmeasured"] == []


def test_a_measured_mismatch_is_reported_ahead_of_a_missing_measurement(
        store, room):
    """We looked and it had moved - that is more actionable than "we did not look"."""
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    report = evaluate_gate(store, request["message_id"],
                           snapshot_sha256="9" * 64,
                           supervisor_context_sha256=None)
    assert report["state"] == "blocked_stale"
    assert report["unmeasured"] == ["supervisor_context_sha256"]
    assert any("snapshot_sha256 has moved" in r for r in report["reasons"])
    assert any("was not measured" in r for r in report["reasons"])


def test_assert_releasable_requires_both_measurements(store, room):
    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")

    for observations in (
        {},
        {"snapshot_sha256": SNAPSHOT_SHA},
        {"supervisor_context_sha256": CONTEXT_SHA},
    ):
        with pytest.raises(GateBlocked) as caught:
            assert_releasable(store, request["message_id"], **observations)
        assert caught.value.report["state"] == "blocked_unmeasured"

    assert assert_releasable(
        store, request["message_id"],
        snapshot_sha256=SNAPSHOT_SHA,
        supervisor_context_sha256=CONTEXT_SHA)["releasable"]


def test_assert_releasable_rejects_a_misspelled_observation(store, room):
    """Named parameters, so a typo cannot quietly become "unmeasured"."""
    request = post_decision_request(room)
    with pytest.raises(TypeError):
        assert_releasable(store, request["message_id"], snapshot_sha="x" * 64)


def test_the_cli_gate_status_without_both_measurements_blocks(store, room,
                                                              capsys):
    from agent_room.cli import main

    request = post_decision_request(room)
    HumanDecisionAuthority(store).record(request["message_id"], "approve")
    main(["--repo", str(store.workdir), "--participant", "coordinator",
          "gate-status", "--request-id", request["message_id"]])
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "blocked_unmeasured"
    assert report["releasable"] is False


def test_gate_blocked_carries_the_full_report(store, room):
    request = post_decision_request(room)
    with pytest.raises(GateBlocked) as caught:
        assert_releasable(store, request["message_id"])
    assert caught.value.report["state"] == "blocked_no_decision"


def test_pending_requests_lists_only_undecided_bound_requests(store, room):
    decided = post_decision_request(room, action_id="already-decided")
    waiting = post_decision_request(room, action_id="still-waiting")
    room.post(thread_id="t1", type="decision_request",
              body={"text": "unbound"}, human_approval_required=True)
    HumanDecisionAuthority(store).record(decided["message_id"], "approve")

    pending = pending_requests(store, "t1")
    assert [p["action_id"] for p in pending] == ["still-waiting"]
    assert pending[0]["request_message_id"] == waiting["message_id"]


# ===== 14. Serena and Graphify stay closed =================================

def test_no_tool_profile_beyond_none_is_qualified():
    assert QUALIFIED_PROFILES == ("none",)
    assert set(KNOWN_PROFILES) >= {"serena", "graphify", "serena+graphify"}


@pytest.mark.parametrize("profile", ["serena", "graphify", "serena+graphify"])
def test_named_tool_profiles_still_fail_closed(profile):
    from agent_room.tool_profiles import ToolProfileUnavailable, resolve

    with pytest.raises(ToolProfileUnavailable, match="not yet qualified"):
        resolve(profile)
