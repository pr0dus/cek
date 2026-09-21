"""Episode loop.

Same loop for every core, so numbers are comparable. The action budget is the
only thing standing between an unbounded search and an infinite run, and it is
recorded in the result because a score is meaningless without it.
"""

from typing import Protocol, TYPE_CHECKING

from .contract import Action, Observation, RESET
from .core import Core
from .metrics import ActionCounter, EpisodeResult

if TYPE_CHECKING:
    from .trace import TraceRecorder


class Environment(Protocol):
    def observe(self) -> Observation: ...
    def step(self, action: Action) -> Observation: ...


def run_episode(
    core: Core,
    env: Environment,
    max_actions: int = 200,
    recorder: "TraceRecorder | None" = None,
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
        previous = obs
        obs = env.step(action)
        if recorder is not None:
            recorder.record(previous, action, obs)
        counter.record(was_reset=action.name == "RESET")
        counter.observe_progress(obs.levels_completed)

    counter.finish()
    if recorder is not None:
        recorder.close(final_state=obs.state, total_actions=counter.total)
    return EpisodeResult(
        core=core.name,
        game_id=obs.game_id,
        levels=counter.levels,
        total_actions=counter.total,
        final_state=obs.state,
        resets=counter.resets,
    )
