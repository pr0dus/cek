"""Agent Room — durable, auditable message store for AI-to-AI research exchange.

Implements Issue #2 against the design qualified at commit cb13177.

The store preserves research state; it does not decide what is true. Nothing
here executes anything, grants authority, or connects to NEWI cognition.
"""

from .errors import (
    AgentRoomError,
    AppendOnlyViolation,
    ClaimStateError,
    ConflictError,
    DeliveryError,
    DirtyCheckoutError,
    ForbiddenOperation,
    GitTimeout,
    HistoryUnavailable,
    IntegrityError,
    LockTimeout,
    PushAmbiguous,
    PushRaceError,
    SchemaError,
    UnresolvedReference,
    WrongBranchError,
)
from .claude_participant import (
    ClaudeAdapterError,
    ClaudeInvoker,
    ClaudeParticipant,
    MalformedResponse,
    NoWorkAvailable,
    TurnLockTimeout,
)
from .room import AgentRoom
from .gitstore import GitMessageStore
from .cursor import ParticipantCursor

__all__ = [
    "AgentRoom",
    "ClaudeParticipant",
    "ClaudeInvoker",
    "ClaudeAdapterError",
    "MalformedResponse",
    "NoWorkAvailable",
    "TurnLockTimeout",
    "GitMessageStore",
    "ParticipantCursor",
    "AgentRoomError",
    "AppendOnlyViolation",
    "SchemaError",
    "IntegrityError",
    "ConflictError",
    "ClaimStateError",
    "DeliveryError",
    "DirtyCheckoutError",
    "ForbiddenOperation",
    "GitTimeout",
    "HistoryUnavailable",
    "LockTimeout",
    "PushAmbiguous",
    "PushRaceError",
    "UnresolvedReference",
    "WrongBranchError",
]
