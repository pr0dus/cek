"""Random baseline.

Every later result is stated relative to this. A core that does not beat
random on action efficiency has not demonstrated anything, whatever else it
does internally.
"""

import random

from ..contract import Action, Observation
from ..contract import COMPLEX_ACTIONS, GRID_MAX, SIMPLE_ACTIONS


class RandomCore:
    def __init__(self, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._seed = seed

    @property
    def name(self) -> str:
        return f"random(seed={self._seed})"

    def reset(self) -> None:
        pass

    def act(self, observation: Observation, history: list[Observation]) -> Action:
        name = self._rng.choice(SIMPLE_ACTIONS + COMPLEX_ACTIONS)
        if name in COMPLEX_ACTIONS:
            return Action(
                name,
                x=self._rng.randrange(GRID_MAX),
                y=self._rng.randrange(GRID_MAX),
            )
        return Action(name)
