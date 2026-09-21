"""Episode loop.

Same loop for every core, so numbers are comparable. The action budget is the
only thing standing between an unbounded search and an infinite run, and it is
recorded in the result because a score is meaningless without it.
"""

from typing import Protocol

from .contract import Action, Observation, RESET
from .core import Core
from .metrics import ActionCounter, EpisodeResult


class Environment(Protocol):
    def observe(self) -> Observation: ...
    def step(self, action: Action) -> Observation: ...


def run_episode(
    core: Core,
    env: Environment,
    max_actions: int = 200,
) -> EpisodeResult:
    core.reset()
    counter = ActionCounter()
    history: list[Observation] = []
    obs = env.observe()

    while counter.total < max_actions:
        if obs.state == "WIN":
            break

        action = RESET if obs.needs_reset else core.act(obs, history)

        history.append(obs)
        obs = env.step(action)
        counter.record(was_reset=action.name == "RESET")
        counter.observe_progress(obs.levels_completed)

    counter.finish()
    return EpisodeResult(
        core=core.name,
        game_id=obs.game_id,
        levels=counter.levels,
        total_actions=counter.total,
        final_state=obs.state,
        resets=counter.resets,
    )
