"""Traces are the raw material for Phase 0, so losslessness is the property
that matters: whatever the environment emitted must survive a round trip
byte-for-byte in value, with nothing derived and nothing dropped.
"""

import json

from newi_arc import run_episode
from newi_arc.agents import RandomCore
from newi_arc.contract import Action, Observation
from newi_arc.mock_env import MockEnv
from newi_arc.trace import TraceRecorder, read_trace


def _obs(frame, state="NOT_FINISHED", levels=0):
    return Observation(
        game_id="g",
        frame=frame,
        state=state,
        levels_completed=levels,
        win_levels=2,
        available_actions=(1, 6),
    )


def test_frame_survives_round_trip_unchanged(tmp_path):
    frame = [[[0, 1, 2], [3, 4, 5]]]
    path = tmp_path / "t.jsonl"
    with TraceRecorder(path, game_id="g", core="c", seed=7) as rec:
        rec.record(_obs(frame), Action("ACTION6", x=3, y=4), _obs(frame, levels=1))

    header, transitions = read_trace(path)
    assert header["game_id"] == "g"
    assert header["seed"] == 7
    assert len(transitions) == 1
    assert transitions[0]["before"]["frame"] == frame
    assert transitions[0]["after"]["levels_completed"] == 1


def test_action_coordinates_recorded(tmp_path):
    path = tmp_path / "t.jsonl"
    with TraceRecorder(path, game_id="g", core="c", seed=0) as rec:
        rec.record(_obs([[[0]]]), Action("ACTION6", x=11, y=22), _obs([[[1]]]))
        rec.record(_obs([[[1]]]), Action("ACTION1"), _obs([[[1]]]))

    _, transitions = read_trace(path)
    assert transitions[0]["action"] == {"name": "ACTION6", "x": 11, "y": 22}
    assert transitions[1]["action"] == {"name": "ACTION1"}


def test_records_carry_no_derived_structure(tmp_path):
    """Guards the no-interpretation rule: only raw fields may be written."""
    path = tmp_path / "t.jsonl"
    with TraceRecorder(path, game_id="g", core="c", seed=0) as rec:
        rec.record(_obs([[[0, 1]]]), Action("ACTION1"), _obs([[[1, 1]]]))

    _, transitions = read_trace(path)
    allowed = {
        "frame",
        "state",
        "levels_completed",
        "win_levels",
        "available_actions",
    }
    assert set(transitions[0]["before"]) == allowed
    assert set(transitions[0]["after"]) == allowed


def test_partial_trace_is_readable(tmp_path):
    """An interrupted run keeps whatever it captured."""
    path = tmp_path / "t.jsonl"
    rec = TraceRecorder(path, game_id="g", core="c", seed=0)
    rec.record(_obs([[[0]]]), Action("ACTION1"), _obs([[[1]]]))
    # deliberately not closed — no footer written

    header, transitions = read_trace(path)
    assert header["record"] == "header"
    assert len(transitions) == 1


def test_episode_records_every_transition(tmp_path):
    path = tmp_path / "ep.jsonl"
    recorder = TraceRecorder(path, game_id="mock", core="random", seed=3)
    result = run_episode(
        RandomCore(seed=3), MockEnv(seed=3), max_actions=25, recorder=recorder
    )

    _, transitions = read_trace(path)
    assert len(transitions) == result.total_actions


def test_footer_written_on_close(tmp_path):
    path = tmp_path / "t.jsonl"
    with TraceRecorder(path, game_id="g", core="c", seed=0) as rec:
        rec.record(_obs([[[0]]]), Action("ACTION1"), _obs([[[0]]]))

    footers = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if json.loads(line).get("record") == "footer"
    ]
    assert len(footers) == 1
    assert footers[0]["steps"] == 1
