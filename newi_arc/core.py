"""The interface any reasoning core must satisfy.

This is the whole contract between the harness and whatever is thinking.
CEK, a fresh architecture, or a random baseline all implement this and are
measured on identical instrumentation.

Deliberately narrow: a core receives observations and returns actions. It is
given no game identity, no mechanic description, and no goal. Anything a core
needs beyond `Observation` is something we would be telling it.
"""

from typing import Protocol, runtime_checkable

from .contract import Action, Observation


@runtime_checkable
class Core(Protocol):
    """A reasoning core."""

    @property
    def name(self) -> str:
        """Identifier used in results. Include config that affects behaviour."""
        ...

    def reset(self) -> None:
        """Called before each episode. Discard per-episode state here.

        Knowledge intended to carry across episodes must survive this call —
        that carry-over is what Phase 4 measures.
        """
        ...

    def act(self, observation: Observation, history: list[Observation]) -> Action:
        """Choose the next action.

        `history` is every observation this episode, oldest first, excluding
        `observation`.
        """
        ...
