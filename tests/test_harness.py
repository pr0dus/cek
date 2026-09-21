import pytest

from newi_arc import Action, run_episode
from newi_arc.agents import RandomCore
from newi_arc.contract import GRID_MAX, Observation
from newi_arc.metrics import ActionCounter, EpisodeResult, LevelRecord
from newi_arc.mock_env import MockEnv


def test_complex_action_requires_coordinates():
    with pytest.raises(ValueError):
        Action("ACTION6")


def test_simple_action_rejects_coordinates():
    with pytest.raises(ValueError):
        Action("ACTION1", x=1, y=1)


def test_coordinates_bounded_by_grid():
    Action("ACTION6", x=GRID_MAX - 1, y=0)
    with pytest.raises(ValueError):
        Action("ACTION6", x=GRID_MAX, y=0)


def test_random_core_completes_episode_within_budget():
    result = run_episode(RandomCore(seed=1), MockEnv(seed=1), max_actions=50)
    assert result.total_actions <= 50
    assert result.core.startswith("random")


def test_counter_closes_levels_on_progress():
    counter = ActionCounter()
    for _ in range(4):
        counter.record()
    counter.observe_progress(1)
    for _ in range(2):
        counter.record()
    counter.finish()

    assert counter.levels[0] == LevelRecord(0, 4, True)
    assert counter.levels[1] == LevelRecord(1, 2, False)


def test_rhae_returns_none_without_baseline():
    result = EpisodeResult(
        core="x", game_id="g", levels=[LevelRecord(0, 10, True)]
    )
    assert result.rhae({}) is None


def test_rhae_is_squared_efficiency_ratio():
    result = EpisodeResult(
        core="x", game_id="g", levels=[LevelRecord(0, 100, True)]
    )
    assert result.rhae({0: 10}) == pytest.approx(0.01)


def test_incomplete_levels_excluded_from_rhae():
    result = EpisodeResult(
        core="x", game_id="g", levels=[LevelRecord(0, 100, False)]
    )
    assert result.rhae({0: 10}) is None


def test_observation_exposes_top_grid_layer():
    obs = Observation(
        game_id="g",
        frame=[[[1, 2]], [[3, 4]]],
        state="NOT_FINISHED",
        levels_completed=0,
        win_levels=1,
        available_actions=(1,),
    )
    assert obs.depth == 2
    assert obs.grid == [[3, 4]]
