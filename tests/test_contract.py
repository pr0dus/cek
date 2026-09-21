"""Guards the contract against engine drift.

Every grounding assumption downstream rests on these facts. If the engine
changes them, this fails loudly rather than letting a stale assumption
propagate into results.

Skipped when arcengine is absent, so the harness stays testable without it.
"""

import pytest

from newi_arc.contract import COMPLEX_ACTIONS, GRID_MAX, SIMPLE_ACTIONS

arcengine = pytest.importorskip("arcengine")


def test_game_states_match_engine():
    assert {s.value for s in arcengine.GameState} == {
        "NOT_PLAYED",
        "NOT_FINISHED",
        "WIN",
        "GAME_OVER",
    }


def test_action_split_matches_engine():
    simple = {a.name for a in arcengine.GameAction if a.is_simple()}
    complex_ = {a.name for a in arcengine.GameAction if a.is_complex()}
    assert simple == set(SIMPLE_ACTIONS) | {"RESET"}
    assert complex_ == set(COMPLEX_ACTIONS)


def test_complex_action_coordinate_bounds():
    field = arcengine.ComplexAction.model_fields["x"]
    bounds = {m.__class__.__name__: getattr(m, "ge", getattr(m, "le", None))
              for m in field.metadata}
    assert 0 in bounds.values()
    assert GRID_MAX - 1 in bounds.values()


def test_frame_is_a_stack_of_integer_grids():
    assert arcengine.FrameData.model_fields["frame"].annotation == list[list[list[int]]]


def test_expected_frame_fields_present():
    expected = {
        "game_id",
        "frame",
        "state",
        "levels_completed",
        "win_levels",
        "available_actions",
    }
    assert expected <= set(arcengine.FrameData.model_fields)
