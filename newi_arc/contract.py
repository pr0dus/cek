"""The ARC-AGI-3 observation and action contract.

Verified against arcengine 0.9.3 by introspection, not from documentation.
Re-run `tests/test_contract.py` after any engine upgrade: if these facts
change, every downstream assumption about grounding changes with them.
"""

from dataclasses import dataclass

GRID_MAX = 64
"""Complex actions address a 64x64 coordinate space (x, y in [0, 63])."""

SIMPLE_ACTIONS = ("ACTION1", "ACTION2", "ACTION3", "ACTION4", "ACTION5", "ACTION7")
COMPLEX_ACTIONS = ("ACTION6",)
"""Only ACTION6 carries coordinates. The rest are bare."""

TERMINAL_STATES = ("WIN", "GAME_OVER")
RESETTABLE_STATES = ("NOT_PLAYED", "GAME_OVER")


@dataclass(frozen=True)
class Observation:
    """One environment frame, decoupled from the engine's own types.

    An agent core sees only this. Nothing here names a game, a mechanic, or a
    goal — if a core needs more than this to act, it is being told the answer.
    """

    game_id: str
    frame: list[list[list[int]]]
    state: str
    levels_completed: int
    win_levels: int
    available_actions: tuple[int, ...]

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def needs_reset(self) -> bool:
        return self.state in RESETTABLE_STATES

    @property
    def grid(self) -> list[list[int]]:
        """The topmost grid layer.

        `frame` is a stack; most games appear to use a single layer, but the
        contract permits more, so callers that care must handle depth > 1.
        """
        return self.frame[-1] if self.frame else []

    @property
    def depth(self) -> int:
        return len(self.frame)

    @classmethod
    def from_frame_data(cls, fd: object) -> "Observation":
        # `frame` is absent from the declared FrameDataRaw model but present at
        # runtime, and its layers arrive as numpy arrays rather than lists.
        raw = getattr(fd, "frame", None) or []
        frame = [
            layer.tolist() if hasattr(layer, "tolist") else layer for layer in raw
        ]
        state = getattr(fd, "state")
        return cls(
            game_id=getattr(fd, "game_id", ""),
            frame=frame,
            state=getattr(state, "value", str(state)),
            levels_completed=getattr(fd, "levels_completed", 0),
            win_levels=getattr(fd, "win_levels", 0),
            available_actions=tuple(getattr(fd, "available_actions", ()) or ()),
        )


@dataclass(frozen=True)
class Action:
    """An action request. `x`/`y` are set only for complex actions."""

    name: str
    x: int | None = None
    y: int | None = None

    def __post_init__(self) -> None:
        if self.name in COMPLEX_ACTIONS:
            if self.x is None or self.y is None:
                raise ValueError(f"{self.name} requires x and y")
            if not (0 <= self.x < GRID_MAX and 0 <= self.y < GRID_MAX):
                raise ValueError(f"coordinates out of range: {self.x},{self.y}")
        elif self.x is not None or self.y is not None:
            raise ValueError(f"{self.name} does not take coordinates")

    @property
    def is_complex(self) -> bool:
        return self.name in COMPLEX_ACTIONS


RESET = Action("RESET")
