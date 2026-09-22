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
from .errors import AgentRoomError
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
        envelope: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "message_id": message_id or uuid7(),
            "timestamp": timestamp or _now_iso(),
            "sender": sender or {"agent": self.participant},
            "recipient": recipient or {"broadcast": True},
            "project": project or {},
            "thread_id": thread_id,
            "type": type,
            "body": body,
            "evidence": evidence or [],
            "status": status,
            "reply_requested": bool(reply_requested),
            "human_approval_required": bool(human_approval_required),
        }
        if parent_id is not None:
            envelope["parent_id"] = parent_id
        if claim is not None:
            envelope["claim"] = claim
        return envelope

    def post(self, **kwargs) -> dict:
        """Validate, seal and append one message. Agent-facing."""
        envelope = self.build_envelope(**kwargs)
        validate_envelope(envelope, agent_facing=True)
        return self.store.append(canonical.seal(envelope))

    def reply(self, parent_id: str, **kwargs) -> dict:
        """Post a message linked to `parent_id`, inheriting its thread."""
        if "thread_id" not in kwargs:
            parent = self.find(parent_id)
            if parent is None:
                raise AgentRoomError(f"cannot reply: unknown parent {parent_id}")
            kwargs["thread_id"] = parent["thread_id"]
        return self.post(parent_id=parent_id, **kwargs)

    # -- read --------------------------------------------------------------
    def get(self, thread_id: str, message_id: str) -> dict:
        return self.store.read(thread_id, message_id)

    def find(self, message_id: str) -> dict | None:
        for env in self.store.iter_messages():
            if env["message_id"] == message_id:
                return env
        return None

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

    def acknowledge(self, message_id: str) -> dict:
        """Record that this participant has seen a message.

        Acknowledgement is not agreement, and it never touches the artifact.
        """
        cursor = self._require_cursor()
        cursor.acknowledge(message_id, at=_now_iso())
        return {"acknowledged": message_id, "participant": self.participant}

    def is_acknowledged(self, message_id: str) -> bool:
        return self._require_cursor().is_acknowledged(message_id)
