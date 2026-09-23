"""High-level Agent Room API.

Ties the append-only store to participant-local cursor state and enforces the
rules an agent must not be able to talk its way around: no `approval` or
`rejection`, no epistemic promotion by assertion, no rewriting history.

Nothing here executes anything. Posting a message is the whole capability.
"""

import datetime as dt
from typing import Any, Iterable

from . import canonical
from .cursor import ParticipantCursor
from .errors import (
    AgentRoomError,
    ForbiddenOperation,
    SchemaError,
    UnresolvedReference,
)
from .gitstore import GitMessageStore
from .ids import uuid7
from .schema import SCHEMA_VERSION, validate_envelope


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AgentRoom:
    """Library surface for one participant."""

    def __init__(
        self,
        store: GitMessageStore,
        participant: str,
        cursor: ParticipantCursor | None = None,
    ) -> None:
        self.store = store
        self.participant = participant
        self.cursor = cursor

    # -- write -------------------------------------------------------------
    def build_envelope(
        self,
        *,
        thread_id: str,
        type: str,
        body: dict,
        recipient: dict | None = None,
        project: dict | None = None,
        parent_id: str | None = None,
        evidence: list | None = None,
        claim: dict | None = None,
        status: str = "open",
        reply_requested: bool = False,
        human_approval_required: bool = False,
        sender: dict | None = None,
        message_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict:
        # Defaults apply to "not provided" only. `x or default` would erase
        # malformed input - `recipient=[]` would silently become a broadcast,
        # and `message_id=""` would be replaced by a fresh UUID instead of
        # being rejected. Anything explicitly passed is preserved so schema
        # validation can refuse it.
        if sender is None:
            sender_meta: Any = {}
        elif isinstance(sender, dict):
            sender_meta = dict(sender)
        else:
            # NB: `type` is a parameter of this method, so the builtin is
            # shadowed here - use __class__ rather than type().
            raise SchemaError(
                f"sender must be an object, got "
                f"{sender.__class__.__name__} {sender!r}"
            )
        claimed = sender_meta.pop("agent", None)
        if claimed is not None and claimed != self.participant:
            raise ForbiddenOperation(
                f"this room posts as {self.participant!r} and cannot post as "
                f"{claimed!r}; participant identity is not forgeable"
            )
        sender_meta["agent"] = self.participant

        envelope: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "message_id": uuid7() if message_id is None else message_id,
            "timestamp": _now_iso() if timestamp is None else timestamp,
            "sender": sender_meta,
            "recipient": {"broadcast": True} if recipient is None else recipient,
            "project": {} if project is None else project,
            "thread_id": thread_id,
            "type": type,
            "body": body,
            "evidence": [] if evidence is None else evidence,
            "status": status,
            # Deliberately NOT bool(...): coercing here would silently accept
            # "false", 0, [] and friends. Preserve what the caller passed and
            # let schema validation reject the wrong type.
            "reply_requested": reply_requested,
            "human_approval_required": human_approval_required,
        }
        if parent_id is not None:
            envelope["parent_id"] = parent_id
        if claim is not None:
            envelope["claim"] = claim
        return envelope

    def post(self, **kwargs) -> dict:
        """Validate, seal and append one message. Agent-facing.

        References are resolved against the store, so a parent or evidence
        basis that does not exist fails closed rather than being written as a
        dangling edge.
        """
        envelope = self.build_envelope(**kwargs)
        # The store is its own authority for references; nothing the caller
        # supplies can assert that a parent or evidence message exists.
        validate_envelope(envelope, agent_facing=True, resolver=self.store)
        return self.store.append(canonical.seal(envelope))

    def reply(self, parent_id: str, **kwargs) -> dict:
        """Post a message linked to `parent_id`, inheriting its thread.

        A reply belongs to its parent's thread. An explicit `thread_id` that
        disagrees is a caller error, not something to silently honour - it
        would create a cross-thread parent edge and make thread
        reconstruction incoherent.
        """
        parent = self.find(parent_id)
        if parent is None:
            raise UnresolvedReference(f"cannot reply: unknown parent {parent_id}")
        supplied = kwargs.get("thread_id")
        if supplied is not None and supplied != parent["thread_id"]:
            raise AgentRoomError(
                f"cannot reply into thread {supplied!r}: parent {parent_id} "
                f"belongs to thread {parent['thread_id']!r}"
            )
        kwargs["thread_id"] = parent["thread_id"]
        return self.post(parent_id=parent_id, **kwargs)

    # -- read --------------------------------------------------------------
    def get(self, thread_id: str, message_id: str) -> dict:
        return self.store.read(thread_id, message_id)

    def find(self, message_id: str) -> dict | None:
        return self.store.resolve_message(message_id)

    def thread(self, thread_id: str) -> list[dict]:
        """Complete thread in deterministic commit-add order."""
        return self.store.thread_messages(thread_id)

    def thread_tree(self, thread_id: str) -> list[dict]:
        """The thread as parent->children adjacency, preserving order."""
        messages = self.thread(thread_id)
        children: dict[str | None, list[str]] = {}
        for env in messages:
            children.setdefault(env.get("parent_id"), []).append(env["message_id"])
        return [
            {
                "message_id": env["message_id"],
                "parent_id": env.get("parent_id"),
                "type": env["type"],
                "children": children.get(env["message_id"], []),
            }
            for env in messages
        ]

    def all_messages(self) -> list[dict]:
        return list(self.store.iter_messages())

    # -- queries -----------------------------------------------------------
    def by_participant(self, agent: str, *, role: str = "any") -> list[dict]:
        out = []
        for env in self.store.iter_messages():
            sender = env["sender"].get("agent")
            recipient = (env.get("recipient") or {}).get("agent")
            if role in ("any", "sender") and sender == agent:
                out.append(env)
            elif role in ("any", "recipient") and recipient == agent:
                out.append(env)
        return out

    def by_project(self, repo: str) -> list[dict]:
        return [
            env for env in self.store.iter_messages()
            if (env.get("project") or {}).get("repo") == repo
        ]

    def by_thread(self, thread_id: str) -> list[dict]:
        return self.thread(thread_id)

    # -- inbox / acknowledgement ------------------------------------------
    def _require_cursor(self) -> ParticipantCursor:
        if self.cursor is None:
            raise AgentRoomError("no participant cursor configured")
        return self.cursor

    def inbox(self, *, unread_only: bool = True) -> list[dict]:
        cursor = self._require_cursor()
        messages = list(self.store.iter_messages())
        if unread_only:
            return cursor.unread(messages)
        return [
            env for env in messages
            if env["sender"].get("agent") != self.participant
            and ((env.get("recipient") or {}).get("broadcast")
                 or (env.get("recipient") or {}).get("agent") == self.participant)
        ]

    def is_visible(self, envelope: dict) -> bool:
        """Whether this participant is an addressee of `envelope`."""
        recipient = envelope.get("recipient") or {}
        return bool(
            recipient.get("broadcast")
            or recipient.get("agent") == self.participant
            or envelope["sender"].get("agent") == self.participant
        )

    def acknowledge(self, message_id: str) -> dict:
        """Record that this participant has seen a message.

        Acknowledgement is not agreement, and it never touches the artifact.
        It also may not manufacture state: the message must exist, and a
        directed message must actually be addressed to this participant,
        otherwise the cursor would accumulate assertions about messages the
        participant never received.
        """
        cursor = self._require_cursor()
        envelope = self.store.resolve_message(message_id)
        if envelope is None:
            raise UnresolvedReference(
                f"cannot acknowledge unknown message {message_id!r}"
            )
        if not self.is_visible(envelope):
            raise AgentRoomError(
                f"message {message_id!r} is not addressed to {self.participant!r}"
            )
        cursor.acknowledge(message_id, at=_now_iso())
        return {"acknowledged": message_id, "participant": self.participant}

    def is_acknowledged(self, message_id: str) -> bool:
        return self._require_cursor().is_acknowledged(message_id)
