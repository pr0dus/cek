"""Adapter from the real ARC-AGI-3 engine to our Environment protocol.

Imports of `arc_agi` are deferred so the rest of the harness stays usable —
and testable — on machines without the engine or network access.
"""

import os
from typing import Any

from .contract import Action, Observation


class ArcEnv:
    """Wraps an `arc_agi` EnvironmentWrapper behind observe()/step()."""

    def __init__(
        self,
        game_id: str,
        api_key: str | None = None,
        seed: int = 0,
        mode: str = "normal",
        environments_dir: str = "environment_files",
    ) -> None:
        from arc_agi import Arcade, OperationMode

        self._arcade = Arcade(
            arc_api_key=api_key or os.getenv("ARC_API_KEY", ""),
            operation_mode=OperationMode(mode),
            environments_dir=environments_dir,
        )
        env = self._arcade.make(game_id, seed=seed)
        if env is None:
            available = [e.game_id for e in self._arcade.get_environments()]
            raise RuntimeError(
                f"could not open game {game_id!r}; available: {available or '(none)'}"
            )
        self._env = env
        self._last = self._to_observation(self._env.reset())

    @staticmethod
    def _to_observation(resp: Any) -> Observation:
        if resp is None:
            raise RuntimeError("environment returned no frame")
        return Observation.from_frame_data(resp)

    @staticmethod
    def list_games(
        api_key: str | None = None,
        mode: str = "normal",
        environments_dir: str = "environment_files",
    ) -> list[str]:
        from arc_agi import Arcade, OperationMode

        arcade = Arcade(
            arc_api_key=api_key or os.getenv("ARC_API_KEY", ""),
            operation_mode=OperationMode(mode),
            environments_dir=environments_dir,
        )
        return [e.game_id for e in arcade.get_environments()]

    def observe(self) -> Observation:
        return self._last

    def step(self, action: Action) -> Observation:
        from arcengine import GameAction

        game_action = GameAction.from_name(action.name)
        data = {"x": action.x, "y": action.y} if action.is_complex else None
        self._last = self._to_observation(self._env.step(game_action, data))
        return self._last
