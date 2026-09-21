"""Action accounting.

ARC-AGI-3 scores by Relative Human Action Efficiency: per-level actions
against a human baseline, power-law weighted. A human solving a level in 10
actions against an agent's 100 gives (10/100)^2 = 1% credit.

Actions per level is therefore the measurement that matters, not just whether
a level was reached. Brute force that eventually wins still scores near zero.
"""

from dataclasses import dataclass, field


@dataclass
class LevelRecord:
    level: int
    actions: int
    completed: bool


@dataclass
class EpisodeResult:
    core: str
    game_id: str
    levels: list[LevelRecord] = field(default_factory=list)
    total_actions: int = 0
    final_state: str = ""
    resets: int = 0

    @property
    def levels_completed(self) -> int:
        return sum(1 for r in self.levels if r.completed)

    @property
    def actions_per_completed_level(self) -> float | None:
        done = [r for r in self.levels if r.completed]
        if not done:
            return None
        return sum(r.actions for r in done) / len(done)

    def rhae(self, human_actions: dict[int, int]) -> float | None:
        """RHAE against a per-level human baseline.

        Returns None when no completed level has a baseline, since averaging
        over an empty set would report 0.0 and read as a real score.
        """
        scores = []
        for record in self.levels:
            if not record.completed or record.actions <= 0:
                continue
            baseline = human_actions.get(record.level)
            if baseline is None:
                continue
            scores.append((baseline / record.actions) ** 2)
        if not scores:
            return None
        return sum(scores) / len(scores)


class ActionCounter:
    """Tracks actions per level, closing a level when the env reports progress."""

    def __init__(self) -> None:
        self.levels: list[LevelRecord] = []
        self._current_level = 0
        self._actions_this_level = 0
        self.total = 0
        self.resets = 0

    def record(self, was_reset: bool = False) -> None:
        self.total += 1
        self._actions_this_level += 1
        if was_reset:
            self.resets += 1

    def observe_progress(self, levels_completed: int) -> None:
        """Close the current level when the environment's counter advances."""
        while levels_completed > self._current_level:
            self.levels.append(
                LevelRecord(self._current_level, self._actions_this_level, True)
            )
            self._current_level += 1
            self._actions_this_level = 0

    def finish(self, abandoned: bool = True) -> None:
        """Record the in-progress level as incomplete, if any actions went into it."""
        if abandoned and self._actions_this_level > 0:
            self.levels.append(
                LevelRecord(self._current_level, self._actions_this_level, False)
            )
            self._actions_this_level = 0
