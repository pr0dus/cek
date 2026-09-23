"""Claude Code as an Agent Room participant.

One finite turn: take a single unread message addressed to `claude-code`,
recover its thread from durable state, ask Claude once, validate the reply,
post it, and only then acknowledge the incoming message. Nothing runs in the
background and nothing loops.

Two boundaries matter more than the plumbing:

*Claude is a collaborator, not an authority.* The reply is read only as
structured data. Free-form model text is never executed and never treated as
an approval signal, and `approval`/`rejection` are refused here as well as at
the store — Issue #5 owns human authority.

*Acknowledgement follows durability.* The incoming message is acknowledged
only once the response is durably recorded. Any other outcome leaves an
honest retryable state rather than a message marked read with no answer.
"""

import json
import shutil
import subprocess
from typing import Any, Callable

from . import canonical
from .errors import AgentRoomError, ForbiddenOperation, SchemaError
from .schema import AGENT_FORBIDDEN_TYPES, MESSAGE_TYPES

#: Types an agent participant may author (design §6; enforced again by the store).
AGENT_MESSAGE_TYPES = tuple(sorted(MESSAGE_TYPES - AGENT_FORBIDDEN_TYPES))

DEFAULT_CLAUDE_BIN = "claude"
DEFAULT_TIMEOUT_SECONDS = 900

#: Passed to `claude --json-schema`, so the client validates the shape before
#: we ever see it. We validate again: a schema the model satisfies is not the
#: same as a message the room will accept.
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


class ClaudeAdapterError(AgentRoomError):
    """The Claude turn could not be completed."""


class MalformedResponse(ClaudeAdapterError):
    """Claude's reply was not a usable Agent Room message.

    Raised before anything is posted or acknowledged, so a malformed turn
    leaves the room exactly as it was.
    """


class NoWorkAvailable(ClaudeAdapterError):
    """No unread message is addressed to this participant."""


class ClaudeInvoker:
    """Runs one non-interactive Claude Code turn.

    Injectable: the tests substitute a stub so the suite never spends tokens,
    needs a login, or depends on model behaviour.

    Defaults are deliberately narrow — `--restricted` drops the code-running
    tools and WebFetch and confines file tools to the working directory,
    `--strict-mcp-config` drops MCP servers, and the prompt goes over stdin so
    a large thread cannot overflow the argument list. The installed client's
    own permission system is reused, never widened.
    """

    def __init__(
        self,
        executable: str = DEFAULT_CLAUDE_BIN,
        *,
        cwd: str | None = None,
        model: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        restricted: bool = True,
        extra_args: tuple = (),
    ) -> None:
        self.executable = executable
        self.cwd = cwd
        self.model = model
        self.timeout = timeout
        self.restricted = restricted
        self.extra_args = tuple(extra_args)

    def command(self) -> list:
        resolved = shutil.which(self.executable) or self.executable
        args = [
            resolved, "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(RESPONSE_SCHEMA),
            "--strict-mcp-config",
        ]
        if self.restricted:
            args.append("--restricted")
        if self.model:
            args += ["--model", self.model]
        return args + list(self.extra_args)

    def __call__(self, prompt: str) -> str:
        command = self.command()
        try:
            proc = subprocess.run(
                command, input=prompt, cwd=self.cwd,
                capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ClaudeAdapterError(
                f"claude did not return within {self.timeout}s"
            ) from exc
        except (OSError, ValueError) as exc:
            raise ClaudeAdapterError(
                f"could not run {self.executable}: {type(exc).__name__}: {exc}"
            ) from exc
        if proc.returncode != 0:
            raise ClaudeAdapterError(
                f"claude exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )

        envelope = _parse_json(proc.stdout, "claude --output-format json output")
        if not isinstance(envelope, dict):
            raise MalformedResponse("claude output was not a JSON object")
        if envelope.get("is_error"):
            raise ClaudeAdapterError(
                f"claude reported an error: {str(envelope.get('result'))[:500]}"
            )
        result = envelope.get("result")
        if not isinstance(result, str):
            raise MalformedResponse(
                f"claude result must be text, got {type(result).__name__}"
            )
        return result


def _parse_json(text: str, label: str):
    try:
        return canonical.strict_loads(text)
    except SchemaError as exc:
        raise MalformedResponse(f"{label} is not usable JSON: {exc}") from exc


def _render_message(message: dict) -> str:
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


class ClaudeParticipant:
    """One bounded Claude turn against a durable room."""

    def __init__(
        self,
        room,
        invoker: Callable[[str], str] | None = None,
        *,
        participant: str = "claude-code",
    ) -> None:
        if room.participant != participant:
            raise ClaudeAdapterError(
                f"room posts as {room.participant!r}, not {participant!r}"
            )
        self.room = room
        self.participant = participant
        self.invoke = invoker if invoker is not None else ClaudeInvoker()

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

    # -- prompt ------------------------------------------------------------
    def build_prompt(self, thread: list, target: dict) -> str:
        rendered = "\n".join(_render_message(m) for m in thread)
        return f"""You are the participant `{self.participant}` in an Agent Room \
research thread. You are a research collaborator, not an authority.

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
- If the work needs a human decision, use `decision_request` with
  `human_approval_required` true.
- A `challenge` or `retraction` must reply to the message it contests or withdraws.
"""

    # -- validation --------------------------------------------------------
    def parse_response(self, raw: str) -> dict:
        """Structured fields only. Nothing here is executed or obeyed."""
        payload = _parse_json(raw, "claude response")
        if not isinstance(payload, dict):
            raise MalformedResponse(
                f"claude response must be a JSON object, got {type(payload).__name__}"
            )

        unknown = set(payload) - set(RESPONSE_SCHEMA["properties"])
        if unknown:
            raise MalformedResponse(f"claude response has unknown fields: {sorted(unknown)}")

        mtype = payload.get("type")
        if mtype in AGENT_FORBIDDEN_TYPES:
            raise MalformedResponse(
                f"claude may not author {mtype!r}; human authority arrives in Issue #5"
            )
        if mtype not in AGENT_MESSAGE_TYPES:
            raise MalformedResponse(f"unsupported response type {mtype!r}")

        body = payload.get("body")
        if not isinstance(body, dict):
            raise MalformedResponse(
                f"claude response body must be an object, got {type(body).__name__}"
            )
        # Our own check must match the schema we advertise, or the client and
        # the adapter disagree about what "valid" means.
        unknown_body = set(body) - set(RESPONSE_SCHEMA["properties"]["body"]["properties"])
        if unknown_body:
            raise MalformedResponse(
                f"claude response body has unknown fields: {sorted(unknown_body)}"
            )
        if not isinstance(body.get("text"), str) or not body["text"].strip():
            raise MalformedResponse("claude response needs a non-empty body.text")
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
        """Select, read, ask, validate, post, acknowledge. Then stop."""
        target = self.select_message(message_id)
        thread = self.room.thread(target["thread_id"])
        prompt = self.build_prompt(thread, target)

        if dry_run:
            return {
                "status": "dry_run",
                "target_message_id": target["message_id"],
                "thread_id": target["thread_id"],
                "thread_length": len(thread),
                "prompt_characters": len(prompt),
            }

        raw = self.invoke(prompt)
        response = self.parse_response(raw)   # raises before any mutation

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
            )
        except (SchemaError, ForbiddenOperation) as exc:
            # A reply the room refuses is malformed output too. Surfacing it as
            # the same controlled failure keeps one story for the caller, and
            # nothing has been written or acknowledged at this point.
            raise MalformedResponse(
                f"claude's reply was rejected by the room: {exc}"
            ) from exc

        # Durable first, acknowledged second. If the acknowledgement fails the
        # response still stands and the turn is safely repeatable against the
        # same target; the reverse order could lose a request entirely.
        acknowledged = False
        ack_error = None
        try:
            self.room.acknowledge(target["message_id"])
            acknowledged = True
        except AgentRoomError as exc:
            ack_error = str(exc)

        return {
            "status": "responded",
            "target_message_id": target["message_id"],
            "thread_id": target["thread_id"],
            "response_message_id": posted["message_id"],
            "response_type": response["type"],
            "commit": posted.get("commit"),
            "acknowledged": acknowledged,
            **({"acknowledge_error": ack_error} if ack_error else {}),
        }
