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

    def __init__(self, message, *, message_id, commit, path, cause=None,
                 commit_known=True, pushed=False, recovery_error=None,
                 locally_committed=True, locally_committed_known=True,
                 pushed_known=True, status="created"):
        super().__init__(message)
        #: True / False / None. None means reconciliation could not settle it;
        #: a caller must not repost while persistence is unknown.
        self.locally_committed = locally_committed
        self.locally_committed_known = locally_committed_known
        #: True / False / None. None means the remote may have accepted the
        #: ref but the acknowledgement was lost.
        self.pushed = pushed
        self.pushed_known = pushed_known
        self.message_id = message_id
        #: The surviving add commit, or None when it could not be proven.
        #: Never a known-stale pre-rebase SHA presented as current.
        self.commit = commit
        self.commit_known = commit_known
        self.path = path
        self.cause = cause
        self.recovery_error = recovery_error
        #: "created" | "not_created" | "unknown" - agrees with the local state.
        self.status = status

    def as_result(self) -> dict:
        """The same facts in the shape `append()` returns on success."""
        result = {
            "status": self.status,
            "locally_committed": self.locally_committed,
            "locally_committed_known": self.locally_committed_known,
            "pushed": self.pushed,
            "pushed_known": self.pushed_known,
            "message_id": self.message_id,
            "commit": self.commit,
            "commit_known": self.commit_known,
            "path": self.path,
            "error": str(self.cause or self),
        }
        if self.recovery_error:
            result["recovery_error"] = str(self.recovery_error)
        return result


class HistoryUnavailable(AgentRoomError):
    """Required Git history could not be read, or is known to be incomplete.

    Distinct from "the room is empty". A shallow clone or a failed history
    query cannot prove append-only semantics, so it must fail closed rather
    than present itself as a room with zero messages.
    """


class InvalidBranchName(AgentRoomError):
    """The configured branch is not a literal Git branch name.

    Prefixing `refs/heads/` does not neutralise revision syntax: Git still
    resolves `refs/heads/room~1`, so a caller could point verification at an
    earlier, cleaner history than the branch actually holds.
    """


class CursorStateError(AgentRoomError):
    """The participant-local cursor file is malformed.

    Cursor state is local and rebuildable, so recovery is simply to delete the
    file — every message reverts to unread and nothing durable is lost. It is
    reported rather than silently discarded so that corruption is noticed.
    """


class GitTimeout(AgentRoomError):
    """A Git subprocess exceeded its timeout.

    Kept inside the Agent Room error contract so a caller — and the CLI —
    never sees a bare `subprocess.TimeoutExpired` leak out of the library.
    """

    def __init__(self, message, *, command=None, timeout=None):
        super().__init__(message)
        self.command = command
        self.timeout = timeout


class PushAmbiguous(AgentRoomError):
    """The push produced no usable result, so delivery is unknown.

    Distinct from a rejection: the remote may already hold the ref. The safe
    recovery is to retry `push()` for the same committed message — never to
    repost it under a new id.
    """

    def __init__(self, message, *, pushed=None, pushed_known=False,
                 cause=None, recovery_error=None):
        super().__init__(message)
        self.pushed = pushed
        self.pushed_known = pushed_known
        self.cause = cause
        self.recovery_error = recovery_error


class LockTimeout(AgentRoomError):
    """Another process holds the single-writer lock for this checkout.

    Bounded by construction: the wait has a deadline and then fails, so a
    stuck holder can never hang a caller indefinitely.
    """
