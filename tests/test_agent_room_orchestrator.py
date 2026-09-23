"""Bounded coordination (Issue #5 §3, §4, §10).

The coordinator is deliberately dull: it counts rounds from the durable thread,
refuses to start one more past the ceiling, refuses a final inspection by a
provider that authored the work, and treats an empty inbox as idle. Everything
it reports is a pure function of the room, which is what makes a restarted
process land on exactly the same state.
"""

import json
import subprocess
import sys
import textwrap

import pytest

from agent_room import AgentRoom, ParticipantCursor
from agent_room.decision import HumanDecisionAuthority
from agent_room.orchestrator import (
    CLAUDE,
    CODEX,
    Assignment,
    BoundExhausted,
    Coordinator,
    IndependenceViolation,
    RoundBounds,
)
from agent_room.participant import NoWorkAvailable
from agent_room.supervisor import PARTICIPANT as SUPERVISOR
from tests.conftest_agent_room import post_decision_request

REPO = "pr0dus/cek"
FULL_SHA = "ee9d560d6254beb32ae4c4bbb97e68ee90c2f514"


@pytest.fixture
def coordinator(store, tmp_path):
    return Coordinator(
        store,
        Assignment(thread_id="q1", builder=CLAUDE, inspector=CODEX),
        state_root=tmp_path / "state",
    )


def room_for(store, tmp_path, participant):
    return AgentRoom(store, participant,
                     ParticipantCursor(tmp_path / participant, participant))


def post(store, tmp_path, participant, mtype, *, parent=None, **kwargs):
    room = room_for(store, tmp_path, participant)
    if parent is not None:
        return room.reply(parent, type=mtype,
                          body={"text": f"{participant} {mtype}"}, **kwargs)
    return room.post(thread_id="q1", type=mtype,
                     body={"text": f"{participant} {mtype}"}, **kwargs)


# ===== 9. round ceilings stop cleanly ======================================

def test_rounds_are_counted_from_the_durable_thread(store, tmp_path, coordinator):
    task = post(store, tmp_path, SUPERVISOR, "question")
    claim = post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    post(store, tmp_path, CODEX, "challenge", parent=claim["message_id"])
    post(store, tmp_path, SUPERVISOR, "challenge", parent=claim["message_id"])

    assert coordinator.rounds() == {
        "implementation_attempts": 1,
        "inspection_rounds": 1,
        "supervisor_corrections": 1,
    }
    assert coordinator.remaining()["implementation_attempts"] == 1


def test_the_implementation_ceiling_stops_the_work_item(store, tmp_path,
                                                        coordinator):
    task = post(store, tmp_path, SUPERVISOR, "question")
    for _ in range(2):
        post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])

    with pytest.raises(BoundExhausted) as caught:
        coordinator.assert_within_bounds("implementation_attempts")
    assert caught.value.kind == "implementation_attempts"
    assert caught.value.state["rounds"]["implementation_attempts"] == 2
    assert "implementation_attempts" in caught.value.state["exhausted"]


def test_exhaustion_reports_unresolved_findings_rather_than_converging(
        store, tmp_path, coordinator):
    """A stopped work item must still show what was left open."""
    task = post(store, tmp_path, SUPERVISOR, "question")
    claim = post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    post(store, tmp_path, CODEX, "challenge", parent=claim["message_id"])
    post(store, tmp_path, CODEX, "challenge", parent=claim["message_id"])

    with pytest.raises(BoundExhausted) as caught:
        coordinator.assert_within_bounds("inspection_rounds")
    state = caught.value.state
    assert state["rounds"]["inspection_rounds"] == 2
    assert state["message_count"] == 4
    assert state["participants"] == sorted({SUPERVISOR, CLAUDE, CODEX})


@pytest.mark.parametrize("kind", ["implementation_attempts", "inspection_rounds",
                                  "supervisor_corrections"])
def test_every_ceiling_is_enforced(store, tmp_path, kind):
    bounds = RoundBounds(**{kind: 0})
    coordinator = Coordinator(
        store, Assignment(thread_id="q1", builder=CLAUDE, inspector=CODEX),
        state_root=tmp_path / "state", bounds=bounds)
    post(store, tmp_path, SUPERVISOR, "question")
    with pytest.raises(BoundExhausted):
        coordinator.assert_within_bounds(kind)


def test_a_turn_is_refused_before_the_model_is_invoked(store, tmp_path):
    """The ceiling must bite before tokens are spent, not after."""
    coordinator = Coordinator(
        store, Assignment(thread_id="q1", builder=CLAUDE, inspector=CODEX),
        state_root=tmp_path / "state",
        bounds=RoundBounds(implementation_attempts=0))
    post(store, tmp_path, SUPERVISOR, "question")

    class Exploding:
        participant = CLAUDE

        def run_turn(self, message_id=None):
            raise AssertionError("the adapter must never be reached")

    with pytest.raises(BoundExhausted):
        coordinator.run_turn(Exploding(), kind="implementation_attempts")


def test_no_unbounded_loop_exists_in_the_coordinator():
    """Structural: there is no scheduler, retry loop or recursion here."""
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "agent_room" / "orchestrator.py").read_text(encoding="utf-8")
    assert "while " not in source
    assert "time.sleep" not in source


def test_an_inspector_querying_the_task_does_not_spend_the_budget(
        store, tmp_path, coordinator):
    """Inspection rounds inspect the work, not the assignment.

    Observed in the live Issue #5 run: the provider assigned to inspect
    challenged the *task* before any implementation existed. Charging that
    against the inspection ceiling would have exhausted it before there was
    anything to inspect.
    """
    task = post(store, tmp_path, SUPERVISOR, "question")
    post(store, tmp_path, CODEX, "challenge", parent=task["message_id"])
    assert coordinator.rounds()["inspection_rounds"] == 0

    claim = post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    post(store, tmp_path, CODEX, "challenge", parent=claim["message_id"])
    assert coordinator.rounds()["inspection_rounds"] == 1


# ===== 10. builder is never the final inspector ============================

def test_an_assignment_cannot_name_one_provider_twice():
    with pytest.raises(IndependenceViolation, match="cannot independently"):
        Assignment(thread_id="q1", builder=CLAUDE, inspector=CLAUDE)


def test_only_the_two_coding_providers_may_build_or_inspect():
    with pytest.raises(IndependenceViolation, match="must be one of"):
        Assignment(thread_id="q1", builder=SUPERVISOR, inspector=CODEX)


def test_authorship_is_derived_from_who_actually_implemented(store, tmp_path,
                                                             coordinator):
    task = post(store, tmp_path, SUPERVISOR, "question")
    post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    assert coordinator.authorship() == [CLAUDE]
    coordinator.assert_independent_inspector(CODEX)


def test_mixed_authorship_disqualifies_the_other_provider_too(store, tmp_path,
                                                              coordinator):
    """If both coding providers edited, neither review is independent."""
    task = post(store, tmp_path, SUPERVISOR, "question")
    post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    post(store, tmp_path, CODEX, "evidence", parent=task["message_id"])

    assert coordinator.authorship() == sorted([CLAUDE, CODEX])
    with pytest.raises(IndependenceViolation, match="still self-review"):
        coordinator.assert_independent_inspector(CODEX)


def test_a_builder_may_not_be_its_own_final_inspector(store, tmp_path,
                                                      coordinator):
    task = post(store, tmp_path, SUPERVISOR, "question")
    post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"])
    with pytest.raises(IndependenceViolation):
        coordinator.assert_independent_inspector(CLAUDE)


# ===== 13. no work is idle, not a failure ==================================

def test_an_empty_inbox_is_reported_as_idle(store, tmp_path, coordinator):
    class Quiet:
        participant = CLAUDE

        def run_turn(self, message_id=None):
            raise NoWorkAvailable("no unread messages addressed to claude-code")

    result = coordinator.run_turn(Quiet())
    assert result["status"] == "idle"
    assert result["participant"] == CLAUDE


def test_idle_does_not_consume_a_round(store, tmp_path, coordinator):
    class Quiet:
        participant = CLAUDE

        def run_turn(self, message_id=None):
            raise NoWorkAvailable("nothing to do")

    before = coordinator.rounds()
    coordinator.run_turn(Quiet(), kind="implementation_attempts")
    assert coordinator.rounds() == before


def test_a_real_failure_is_still_a_failure(store, tmp_path, coordinator):
    class Broken:
        participant = CLAUDE

        def run_turn(self, message_id=None):
            raise RuntimeError("client exploded")

    with pytest.raises(RuntimeError, match="client exploded"):
        coordinator.run_turn(Broken())


# ===== 12. a restart reconstructs the qualification state ==================

def build_thread(store, tmp_path):
    task = post(store, tmp_path, SUPERVISOR, "question")
    claim = post(store, tmp_path, CLAUDE, "claim", parent=task["message_id"],
                 evidence=[{"kind": "run", "commit": FULL_SHA,
                            "run_id": "proof-abc"}])
    post(store, tmp_path, CODEX, "challenge", parent=claim["message_id"])
    request = post_decision_request(
        room_for(store, tmp_path, SUPERVISOR), thread_id="q1")
    return task, claim, request


def test_state_is_a_pure_function_of_the_room(store, tmp_path, coordinator):
    build_thread(store, tmp_path)
    first = coordinator.reconstruct()
    second = Coordinator(
        store, Assignment(thread_id="q1", builder=CLAUDE, inspector=CODEX),
        state_root=tmp_path / "elsewhere",
    ).reconstruct()
    assert first == second


def test_reconstruction_reports_rounds_proofs_and_pending_decisions(
        store, tmp_path, coordinator):
    _task, _claim, request = build_thread(store, tmp_path)
    state = coordinator.reconstruct()

    assert state["rounds"] == {"implementation_attempts": 1,
                               "inspection_rounds": 1,
                               "supervisor_corrections": 0}
    assert state["authorship"] == [CLAUDE]
    assert state["proof_run_ids"] == ["proof-abc"]
    assert state["pending_decisions"] == [{
        "request_message_id": request["message_id"],
        "action_id": "activate-agent-room-transport",
        "state": "blocked_no_decision",
        "releasable": False,
    }]
    assert state["recorded_decisions"] == []


def test_a_recorded_decision_shows_up_in_reconstructed_state(
        store, tmp_path, coordinator):
    _task, _claim, request = build_thread(store, tmp_path)
    HumanDecisionAuthority(store).record(request["message_id"], "approve",
                                         decision_id="hd-live")
    state = coordinator.reconstruct()
    assert state["recorded_decisions"] == [{
        "request_message_id": request["message_id"],
        "decision": "approve",
        "decision_id": "hd-live",
    }]
    assert state["pending_decisions"] == []


def test_a_fresh_process_reconstructs_the_identical_state(store, tmp_path):
    """No in-memory continuity: a separate interpreter must agree exactly."""
    coordinator = Coordinator(
        store, Assignment(thread_id="q1", builder=CLAUDE, inspector=CODEX),
        state_root=tmp_path / "state")
    build_thread(store, tmp_path)
    expected = coordinator.reconstruct()

    script = textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {str(tmp_path.parents[0] / 'x')!r})
        from agent_room import GitMessageStore
        from agent_room.orchestrator import Assignment, Coordinator
        store = GitMessageStore({str(store.workdir)!r}, branch="agent-room")
        state = Coordinator(
            store,
            Assignment(thread_id="q1", builder="claude-code", inspector="codex"),
            state_root={str(tmp_path / "restarted")!r},
        ).reconstruct()
        print(json.dumps(state, sort_keys=True))
    """)
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True,
        timeout=120, cwd=root,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == expected
