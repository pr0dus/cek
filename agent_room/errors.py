"""Failure modes, each distinct because the caller must react differently.

Malformed input, tampered history, and a genuine identity collision are not
the same event. Collapsing them into one exception would let a silent
overwrite look like a validation slip.
"""


class AgentRoomError(Exception):
    """Base for every Agent Room failure."""


class SchemaError(AgentRoomError):
    """Envelope does not satisfy the Issue #1 contract."""


class ClaimStateError(SchemaError):
    """Claim epistemic state violates PROCESS.md's ledger rules."""


class IntegrityError(AgentRoomError):
    """Stored envelope does not match its recorded digest.

    Raised on read. Means the artifact was altered after commit, which the
    append-only model forbids.
    """


class ConflictError(AgentRoomError):
    """Same message_id, different content.

    Never resolved by overwriting: the prior content is authoritative and the
    write is refused.
    """


class ForbiddenOperation(AgentRoomError):
    """Operation not available to an agent participant.

    Issues #2-#4 withhold `approval`/`rejection` from agent-facing APIs;
    mechanical human authority arrives in Issue #5.
    """


class PushRaceError(AgentRoomError):
    """Bounded fetch/rebase-or-retry exhausted against a moving branch ref."""


class AppendOnlyViolation(AgentRoomError):
    """A committed message path was later modified, deleted or renamed.

    Reads fail closed on this rather than returning the rewritten content or
    silently omitting the deleted message. A resealed rewrite is exactly the
    attack the digest alone cannot catch: the digest will be valid, so only
    history can show the message is not what was originally committed.
    """


class WrongBranchError(AgentRoomError):
    """The checkout is not the dedicated room branch.

    Refused before any write, so a mis-pointed store cannot commit room
    traffic onto main or repurpose an unrelated developer checkout.
    """


class UnresolvedReference(SchemaError):
    """A parent_id or evidence_basis entry does not resolve in the store."""


class DirtyCheckoutError(AgentRoomError):
    """The dedicated room checkout has uncommitted or staged changes.

    Refused before an append, because `git commit` would otherwise sweep those
    changes into the message commit - including a staged rewrite of an already
    committed message, which would then be pushed as legitimate history.
    """


class DeliveryError(AgentRoomError):
    """The message committed locally but could not be delivered to the remote.

    Carries the identity of what was already written so a caller can retry
    delivery instead of reposting under a fresh UUID — which would duplicate
    the logical message in permanent history.
    """

    def __init__(self, message, *, message_id, commit, path, cause=None):
        super().__init__(message)
        self.locally_committed = True
        self.pushed = False
        self.message_id = message_id
        self.commit = commit
        self.path = path
        self.cause = cause

    def as_result(self) -> dict:
        """The same facts in the shape `append()` returns on success."""
        return {
            "status": "created",
            "locally_committed": True,
            "pushed": False,
            "message_id": self.message_id,
            "commit": self.commit,
            "path": self.path,
            "error": str(self.cause or self),
        }


class LockTimeout(AgentRoomError):
    """Another process holds the single-writer lock for this checkout.

    Bounded by construction: the wait has a deadline and then fails, so a
    stuck holder can never hang a caller indefinitely.
    """
