"""The participant turn protocol, shared by every AI participant.

One finite turn: take a single unread message addressed to this participant,
recover its thread from durable state, ask the model once, validate the reply,
post it, and only then acknowledge. Nothing loops and nothing runs in the
background.

The safety properties live here rather than in each adapter, so a new
participant inherits them instead of re-deriving them:

*Single-flight.* The whole critical section runs under a participant-scoped
advisory lock, because reconciling alone cannot stop two processes that both
check before either appends.

*Idempotence.* A response already durable for a target is discovered before any
model work, so a lost acknowledgement never buys a second answer.

*The model is a collaborator, not an authority.* The reply is read as
structured data only. Free-form text is never executed and never treated as an
approval signal, and `approval`/`rejection` are refused here as well as at the
store.

Adapters supply only what is genuinely client-specific: the participant name,
an audit marker, a role sentence, and how to invoke their client.
"""

import fcntl
import json
import os
import time
from contextlib import contextmanager
from typing import Callable

from . import canonical
from .errors import (
    AgentRoomError,
    DeliveryError,
    ForbiddenOperation,
    SchemaError,
)
from .schema import AGENT_FORBIDDEN_TYPES, MESSAGE_TYPES

#: Types an agent participant may author (design §6; enforced again by the store).
AGENT_MESSAGE_TYPES = tuple(sorted(MESSAGE_TYPES - AGENT_FORBIDDEN_TYPES))

#: How long a second turn waits for the first to finish. Must comfortably
#: exceed a model invocation, or a legitimately queued turn fails instead of
#: waiting and then reconciling. Bounded, never infinite.
DEFAULT_TURN_LOCK_TIMEOUT_SECONDS = 960.0
TURN_LOCK_POLL_SECONDS = 0.05

#: Handed to the client for structured output, and re-validated on the way
#: back: a schema the model satisfied is not the same as a message the room
#: will accept.
RESPONSE_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["type", "body"],
    "properties": {
        "type": {"type": "string", "enum": list(AGENT_MESSAGE_TYPES)},
        "body": {
            "type": "object",
            "additionalProperties": False,
            "required": ["text"],
            "properties": {
                "format": {"type": "string"},
                "text": {"type": "string"},
            },
        },
        "evidence": {"type": "array", "items": {"type": "object"}},
        "claim": {"type": "object"},
        "reply_requested": {"type": "boolean"},
        "human_approval_required": {"type": "boolean"},
    },
}


class ParticipantAdapterError(AgentRoomError):
    """The participant turn could not be completed."""


class MalformedResponse(ParticipantAdapterError):
    """The model's reply was not a usable Agent Room message.

    Raised before anything is posted or acknowledged, so a malformed turn
    leaves the room exactly as it was.
    """


class NoWorkAvailable(ParticipantAdapterError):
    """No unread message is addressed to this participant."""


class TurnLockTimeout(ParticipantAdapterError):
    """Another turn for this participant is already in flight.

    Bounded by construction: the wait has a deadline and then fails cleanly,
    so a stuck or very slow turn can never hang a caller indefinitely.
    """


def parse_json(text, label: str):
    try:
        return canonical.strict_loads(text)
    except SchemaError as exc:
        raise MalformedResponse(f"{label} is not usable JSON: {exc}") from exc


def render_message(message: dict) -> str:
    lines = [
        f"- id: {message['message_id']}",
        f"  from: {message['sender'].get('agent')}",
        f"  type: {message['type']}",
        f"  timestamp: {message['timestamp']}",
    ]
    if message.get("parent_id"):
        lines.append(f"  in_reply_to: {message['parent_id']}")
    claim = message.get("claim")
    if claim:
        lines.append(f"  claim_status: {claim.get('status')}")
        if claim.get("scope"):
            lines.append(f"  claim_scope: {claim['scope']}")
    for ref in message.get("evidence") or []:
        lines.append(f"  evidence: {json.dumps(ref, sort_keys=True)}")
    if message.get("human_approval_required"):
        lines.append("  human_approval_required: true")
    text = (message.get("body") or {}).get("text", "")
    lines.append("  body: |")
    lines.extend(f"    {line}" for line in str(text).splitlines() or [""])
    return "\n".join(lines)


class ParticipantAdapter:
    """One bounded turn for one participant against a durable room."""

    #: Overridden per adapter.
    PARTICIPANT = "participant"
    MARKER = "agent-room-adapter"
    ROLE = "a research collaborator, not an authority"
    #: Back-compatible alias for `invoked_model` in this adapter's results.
    LEGACY_INVOKED_KEY: str | None = None

    def __init__(
        self,
        room,
        invoker: Callable[[str], str] | None = None,
        *,
        participant: str | None = None,
        turn_timeout: float = DEFAULT_TURN_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        expected = participant or self.PARTICIPANT
        if room.participant != expected:
            raise ParticipantAdapterError(
                f"room posts as {room.participant!r}, not {expected!r}"
            )
        self.room = room
        self.participant = expected
        self.invoke = invoker if invoker is not None else self.default_invoker()
        self.turn_timeout = float(turn_timeout)
        if self.turn_timeout < 0:
            raise ParticipantAdapterError("turn_timeout must be >= 0")

    def default_invoker(self):
        raise NotImplementedError

    # -- single-flight -----------------------------------------------------
    def turn_lock_path(self):
        """Shared, deterministic location: the repository's common Git dir.

        Common dir rather than the worktree dir, so linked worktrees of one
        room cannot each run a turn simultaneously. Scoped per participant, so
        two different participants never block each other.
        """
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in self.participant)
        return self.room.store._git_common_dir() / f"agent-room-turn-{safe}.lock"

    @contextmanager
    def turn_lock(self):
        """Exclusive lock over one participant's whole turn.

        Deliberately a different file from the store's writer lock: the append
        inside this critical section takes that one, and reusing the same lock
        would deadlock. `flock` is released by the kernel if the process dies,
        so a crashed turn cannot wedge the participant.
        """
        path = self.turn_lock_path()
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise ParticipantAdapterError(
                f"cannot open turn lock {path}: {exc}") from exc
        deadline = time.monotonic() + self.turn_timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TurnLockTimeout(
                            f"another {self.participant} turn is in flight for "
                            f"{self.room.store.workdir} (waited "
                            f"{self.turn_timeout}s); try again later"
                        )
                    time.sleep(TURN_LOCK_POLL_SECONDS)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    # -- selection ---------------------------------------------------------
    def select_message(self, message_id: str | None = None) -> dict:
        """Exactly one incoming message: the named one, or the oldest unread."""
        if message_id is not None:
            message = self.room.find(message_id)
            if message is None:
                raise NoWorkAvailable(f"no such message: {message_id}")
            if not self.room.is_visible(message):
                raise NoWorkAvailable(
                    f"message {message_id} is not addressed to {self.participant}"
                )
            return message
        unread = self.room.inbox(unread_only=True)
        if not unread:
            raise NoWorkAvailable(
                f"no unread messages addressed to {self.participant}"
            )
        return unread[0]

    def find_existing_response(self, target: dict) -> dict | None:
        """A reply to `target` this participant has already made durable.

        Matched on lineage and identity only - `parent_id` plus
        `sender.agent`. Deliberately not on body text or similarity: model
        output is not a stable key.
        """
        for message in self.room.thread(target["thread_id"]):
            if (message.get("parent_id") == target["message_id"]
                    and message["sender"].get("agent") == self.participant):
                return message
        return None

    def _acknowledge(self, message_id: str) -> tuple:
        try:
            self.room.acknowledge(message_id)
            return True, None
        except AgentRoomError as exc:
            return False, str(exc)

    # -- prompt ------------------------------------------------------------
    def build_prompt(self, thread: list, target: dict) -> str:
        rendered = "\n".join(render_message(m) for m in thread)
        return f"""You are the participant `{self.participant}` in an Agent Room \
research thread. You are {self.ROLE}.

Thread `{target['thread_id']}`, oldest first:

{rendered}

Respond to message `{target['message_id']}`.

Rules:
- Reply with a single JSON object matching the provided schema. No prose outside it.
- `type` must be one of: {", ".join(AGENT_MESSAGE_TYPES)}.
- You may NOT author `approval` or `rejection`; human authority is not yours to assert.
- Agreement from another participant is never validation. Do not mark a claim
  `supported` because someone agreed.
- A claim may honestly remain `proposed` or `challenged` when evidence is incomplete.
- For `supported` you must supply a non-empty `scope`, a non-empty
  `revision_condition`, and an `evidence_basis` that resolves. Evidence of kind
  `agent_output` is never admissible support.
- Evidence locators must be exactly one of these shapes, or omit `evidence`:
  - {{"kind": "repo", "repo": "<owner/name>", "commit": "<full 40- or 64-hex id>",
     "path": "<repo-relative path>", "lines": [start, end]}}   (lines optional)
  - {{"kind": "run", "commit": "<full id>", "run_id": "<id>"}} or the same with
    a repo-relative "path"
  - {{"kind": "external", "url": "https://..."}}
  All four of kind/repo/commit/path are REQUIRED for `repo` evidence, and the
  commit must be a full object id - an abbreviation is rejected. If you do not
  have a full commit id, omit `evidence` entirely rather than inventing one.
- A tool's output is not evidence merely because a tool produced it; claims
  still need repository, test or artifact evidence.
- If the work needs a human decision, use `decision_request` with
  `human_approval_required` true.
- A `challenge` or `retraction` must reply to the message it contests or withdraws.
"""

    # -- validation --------------------------------------------------------
    def normalise_payload(self, payload: dict) -> dict:
        """Client-specific shaping before the shared rules apply.

        A hook, not a licence: it may only adjust how a client expresses
        "absent". It never relaxes what the room will accept.
        """
        return payload

    def parse_response(self, raw: str) -> dict:
        """Structured fields only. Nothing here is executed or obeyed."""
        payload = parse_json(raw, f"{self.participant} response")
        if not isinstance(payload, dict):
            raise MalformedResponse(
                f"response must be a JSON object, got {type(payload).__name__}"
            )
        payload = self.normalise_payload(payload)

        unknown = set(payload) - set(RESPONSE_SCHEMA["properties"])
        if unknown:
            raise MalformedResponse(f"response has unknown fields: {sorted(unknown)}")

        mtype = payload.get("type")
        if mtype in AGENT_FORBIDDEN_TYPES:
            raise MalformedResponse(
                f"{self.participant} may not author {mtype!r}; human authority "
                "arrives in Issue #5"
            )
        if mtype not in AGENT_MESSAGE_TYPES:
            raise MalformedResponse(f"unsupported response type {mtype!r}")

        body = payload.get("body")
        if not isinstance(body, dict):
            raise MalformedResponse(
                f"response body must be an object, got {type(body).__name__}"
            )
        unknown_body = set(body) - set(RESPONSE_SCHEMA["properties"]["body"]["properties"])
        if unknown_body:
            raise MalformedResponse(
                f"response body has unknown fields: {sorted(unknown_body)}"
            )
        if not isinstance(body.get("text"), str) or not body["text"].strip():
            raise MalformedResponse("response needs a non-empty body.text")
        if "format" in body and not isinstance(body["format"], str):
            raise MalformedResponse("body.format must be a string")

        for field in ("reply_requested", "human_approval_required"):
            if field in payload and not isinstance(payload[field], bool):
                raise MalformedResponse(f"{field} must be a boolean")
        if "evidence" in payload and not isinstance(payload["evidence"], list):
            raise MalformedResponse("evidence must be a list")
        if "claim" in payload and not isinstance(payload["claim"], dict):
            raise MalformedResponse("claim must be an object")
        return payload

    # -- the turn ----------------------------------------------------------
    def run_turn(self, message_id: str | None = None, *, dry_run: bool = False) -> dict:
        """Select, read, ask, validate, post, acknowledge. Then stop.

        The whole sequence runs under the participant turn lock, so a second
        process cannot pass the reconciliation check while this one is still
        deciding what to say.
        """
        with self.turn_lock():
            return self._run_turn_locked(message_id, dry_run=dry_run)

    def _run_turn_locked(self, message_id: str | None = None, *,
                         dry_run: bool = False) -> dict:
        target = self.select_message(message_id)

        # Reconcile before doing any model work. If a response to this target
        # is already durable, the only thing that can legitimately be missing
        # is the acknowledgement.
        existing = self.find_existing_response(target)
        if existing is not None and not dry_run:
            acknowledged, ack_error = self._acknowledge(target["message_id"])
            return {
                "status": "already_responded",
                "participant": self.participant,
                "target_message_id": target["message_id"],
                "thread_id": target["thread_id"],
                "response_message_id": existing["message_id"],
                "response_type": existing["type"],
                "response_via": (existing["sender"] or {}).get("via"),
                "invoked_model": False,
                **({self.LEGACY_INVOKED_KEY: False} if self.LEGACY_INVOKED_KEY else {}),
                "acknowledged": acknowledged,
                **({"acknowledge_error": ack_error} if ack_error else {}),
            }

        thread = self.room.thread(target["thread_id"])
        prompt = self.build_prompt(thread, target)

        if dry_run:
            return {
                "status": "dry_run",
                "participant": self.participant,
                "target_message_id": target["message_id"],
                "thread_id": target["thread_id"],
                "thread_length": len(thread),
                "prompt_characters": len(prompt),
                "existing_response_message_id":
                    existing["message_id"] if existing else None,
            }

        raw = self.invoke(prompt)
        response = self.parse_response(raw)   # raises before any mutation

        delivery_error = None
        try:
            posted = self.room.reply(
                target["message_id"],
                type=response["type"],
                body=response["body"],
                evidence=response.get("evidence"),
                claim=response.get("claim"),
                reply_requested=response.get("reply_requested", False),
                human_approval_required=response.get("human_approval_required", False),
                recipient={"agent": target["sender"].get("agent")}
                if target["sender"].get("agent") else None,
                sender={"via": self.MARKER},
            )
        except (SchemaError, ForbiddenOperation) as exc:
            # A reply the room refuses is malformed output too. Surfacing it as
            # the same controlled failure keeps one story for the caller, and
            # nothing has been written or acknowledged at this point.
            raise MalformedResponse(
                f"{self.participant}'s reply was rejected by the room: {exc}"
            ) from exc
        except DeliveryError as exc:
            if exc.locally_committed is not True:
                # Persistence is unproven. Do not acknowledge and do not claim
                # a response exists; a later turn reconciles against history.
                raise
            posted = {"message_id": exc.message_id, "commit": exc.commit,
                      "path": exc.path}
            delivery_error = exc

        # Durable first, acknowledged second. If the acknowledgement fails the
        # response still stands, and the next turn reconciles rather than
        # asking the model again.
        acknowledged, ack_error = self._acknowledge(target["message_id"])

        result = {
            "status": "responded",
            "participant": self.participant,
            "target_message_id": target["message_id"],
            "thread_id": target["thread_id"],
            "response_message_id": posted["message_id"],
            "response_type": response["type"],
            "commit": posted.get("commit"),
            "invoked_model": True,
            **({self.LEGACY_INVOKED_KEY: True} if self.LEGACY_INVOKED_KEY else {}),
            "acknowledged": acknowledged,
        }
        if ack_error:
            result["acknowledge_error"] = ack_error
        if delivery_error is not None:
            result["delivered"] = False
            result["delivery_error"] = str(delivery_error)
        return result
