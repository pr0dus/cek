"""A mock environment implementing the verified contract.

Exists so the harness, metrics and cores are testable with no API key and no
environment files. It is NOT a model of any real game and must never be used
to claim a result — its mechanics are trivial and known to the test author,
which is exactly the self-designed-domain trap the real benchmark avoids.
"""

import random

from .contract import Action, Observation

_SIZE = 8


class MockEnv:
    """Toy environment: ACTION6 on the one 'hot' cell advances a level.

    Deliberately learnable so exploration logic can be exercised, deliberately
    useless as evidence.
    """

    def __init__(self, seed: int = 0, levels: int = 3, size: int = _SIZE) -> None:
        self._rng = random.Random(seed)
        self._size = size
        self._win_levels = levels
        self._levels_completed = 0
        self._state = "NOT_PLAYED"
        self._target = self._new_target()

    def _new_target(self) -> tuple[int, int]:
        return (self._rng.randrange(self._size), self._rng.randrange(self._size))

    def _grid(self) -> list[list[int]]:
        grid = [[0] * self._size for _ in range(self._size)]
        tx, ty = self._target
        grid[ty][tx] = 1 + self._levels_completed
        return grid

    def observe(self) -> Observation:
        return Observation(
            game_id="mock",
            frame=[self._grid()],
            state=self._state,
            levels_completed=self._levels_completed,
            win_levels=self._win_levels,
            available_actions=(0, 1, 2, 3, 4, 5, 6, 7),
        )

    def step(self, action: Action) -> Observation:
        if action.name == "RESET":
            self._levels_completed = 0
            self._target = self._new_target()
            self._state = "NOT_FINISHED"
        elif self._state == "NOT_FINISHED":
            if action.is_complex and (action.x, action.y) == self._target:
                self._levels_completed += 1
                if self._levels_completed >= self._win_levels:
                    self._state = "WIN"
                else:
                    self._target = self._new_target()
        return self.observe()
