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
from .codex_participant import CodexInvoker, CodexParticipant
from .decision import (
    GATE_STATES,
    REQUIRED_OBSERVATIONS,
    DecisionError,
    GateBlocked,
    HumanDecisionAuthority,
    assert_releasable,
    binding_digest,
    evaluate_gate,
    pending_requests,
)
from .orchestrator import (
    Assignment,
    BoundExhausted,
    Coordinator,
    IndependenceViolation,
    RoundBounds,
)
from .namespace import NamespaceViolation
from .limits import LimitExceeded
from .process import BoundedResult, ProcessError, isolated_env, run_bounded, sanitised_env
from .proof import (
    ProofArtifactConflict,
    ProofError,
    proof_evidence,
    run_isolated_proof,
    run_proof,
    verify_artifact,
    verify_proof,
)
from .release import ReleaseBlocked, ReleaseError, authorise, reconcile, reserve
from .snapshot import SnapshotError, snapshot_manifest, verify_manifest
from .participant import ParticipantAdapter, ParticipantAdapterError
from .supervisor import (
    MalformedSupervisorResponse,
    StaleSupervisorContext,
    SupervisorBoundary,
    SupervisorError,
)
from .tool_profiles import (
    KNOWN_PROFILES,
    QUALIFIED_PROFILES,
    ToolProfile,
    ToolProfileError,
    ToolProfileUnavailable,
    UnknownToolProfile,
)
from .room import AgentRoom
from .gitstore import GitMessageStore
from .cursor import ParticipantCursor

__all__ = [
    "AgentRoom",
    "ClaudeParticipant",
    "CodexParticipant",
    "CodexInvoker",
    "ParticipantAdapter",
    "ParticipantAdapterError",
    "HumanDecisionAuthority",
    "DecisionError",
    "GateBlocked",
    "GATE_STATES",
    "REQUIRED_OBSERVATIONS",
    "evaluate_gate",
    "assert_releasable",
    "binding_digest",
    "pending_requests",
    "Coordinator",
    "Assignment",
    "RoundBounds",
    "BoundExhausted",
    "IndependenceViolation",
    "snapshot_manifest",
    "verify_manifest",
    "SnapshotError",
    "run_proof",
    "run_isolated_proof",
    "verify_artifact",
    "ProofArtifactConflict",
    "NamespaceViolation",
    "LimitExceeded",
    "ProcessError",
    "BoundedResult",
    "run_bounded",
    "sanitised_env",
    "isolated_env",
    "authorise",
    "reserve",
    "reconcile",
    "ReleaseError",
    "ReleaseBlocked",
    "verify_proof",
    "proof_evidence",
    "ProofError",
    "SupervisorBoundary",
    "SupervisorError",
    "StaleSupervisorContext",
    "MalformedSupervisorResponse",
    "ToolProfile",
    "ToolProfileError",
    "ToolProfileUnavailable",
    "UnknownToolProfile",
    "KNOWN_PROFILES",
    "QUALIFIED_PROFILES",
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
