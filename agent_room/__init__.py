"""Agent Room — durable, auditable message store for AI-to-AI research exchange.

Implements Issue #2 against the design qualified at commit cb13177.

The store preserves research state; it does not decide what is true. Nothing
here executes anything, grants authority, or connects to NEWI cognition.
"""

from .errors import (
    AgentRoomError,
    ClaimStateError,
    ConflictError,
    ForbiddenOperation,
    IntegrityError,
    PushRaceError,
    SchemaError,
)
from .room import AgentRoom
from .gitstore import GitMessageStore
from .cursor import ParticipantCursor

__all__ = [
    "AgentRoom",
    "GitMessageStore",
    "ParticipantCursor",
    "AgentRoomError",
    "SchemaError",
    "IntegrityError",
    "ConflictError",
    "ClaimStateError",
    "ForbiddenOperation",
    "PushRaceError",
]
