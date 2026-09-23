"""Codex as an Agent Room participant.

The turn protocol — single-flight lock, reconciliation, three-valued
persistence, authority boundary — lives in `participant.py` and is shared with
Claude. Only the invocation boundary is Codex-specific, and it is genuinely
different: Codex takes its prompt on stdin, its output schema as a *file*, and
writes its final message to a *file* rather than to stdout.

Codex is an engineering participant: it may implement, inspect, test,
challenge, propose or hand off. It is not an authority, and the role is
assigned per thread — nothing here encodes a permanent hierarchy between
participants.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import tool_profiles
from .limits import MAX_MODEL_OUTPUT_BYTES, assert_within
from .process import ProcessError, run_bounded, sanitised_env
from .participant import (
    AGENT_MESSAGE_TYPES,
    DEFAULT_TURN_LOCK_TIMEOUT_SECONDS,
    RESPONSE_SCHEMA,
    MalformedResponse,
    NoWorkAvailable,
    ParticipantAdapter,
    ParticipantAdapterError,
    TurnLockTimeout,
)

#: Kept as the adapter's own error name; the shared base class raises it.
CodexAdapterError = ParticipantAdapterError

DEFAULT_CODEX_BIN = "codex"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_SANDBOX = "read-only"

#: The only sandbox policies a participant turn may use. `danger-full-access`
#: is deliberately absent: an Agent Room turn never needs it, and offering it
#: at the library boundary would make the safety claim depend on the CLI
#: parser rather than on the API.
ALLOWED_SANDBOXES = ("read-only", "workspace-write")

#: Audit marker in `sender.via`, distinguishing an automatic turn from a reply
#: a human drove by hand. Not a security control - provenance rests on
#: `sender.agent`, which the store fixes to the room's participant.
ADAPTER_MARKER = "agent-room-codex-adapter"

def _strict_schema() -> dict:
    """`RESPONSE_SCHEMA` in the form OpenAI structured output demands.

    Discovered by running the real client, not from documentation: strict mode
    rejects a schema whose `required` omits any property of an
    `additionalProperties: false` object -

        Invalid schema ... 'required' is required to be supplied and to be an
        array including every key in properties. Missing 'format'.

    So every property is listed as required and optionality is expressed as a
    nullable type instead. The nulls that come back are stripped in
    `normalise_payload`, leaving exactly the shape the shared validator and the
    store already enforce. Claude's `--json-schema` accepts the lenient form;
    this is the same contract spelled differently, not a weaker one.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["type", "body", "evidence", "claim",
                     "reply_requested", "human_approval_required"],
        "properties": {
            "type": {"type": "string", "enum": list(AGENT_MESSAGE_TYPES)},
            "body": {
                "type": "object", "additionalProperties": False,
                "required": ["text", "format"],
                "properties": {
                    "text": {"type": "string"},
                    "format": {"type": ["string", "null"]},
                },
            },
            "evidence": {
                "type": ["array", "null"],
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["kind", "repo", "commit", "path",
                                 "lines", "run_id", "url", "id"],
                    "properties": {
                        "kind": {"type": "string",
                                 "enum": ["repo", "run", "external", "agent_output"]},
                        "repo": {"type": ["string", "null"]},
                        "commit": {"type": ["string", "null"]},
                        "path": {"type": ["string", "null"]},
                        "lines": {"type": ["array", "null"],
                                  "items": {"type": "integer"}},
                        "run_id": {"type": ["string", "null"]},
                        "url": {"type": ["string", "null"]},
                        "id": {"type": ["string", "null"]},
                    },
                },
            },
            "claim": {
                "type": ["object", "null"], "additionalProperties": False,
                "required": ["status", "scope", "revision_condition",
                             "evidence_basis"],
                "properties": {
                    "status": {"type": "string",
                               "enum": ["proposed", "challenged",
                                        "supported", "retracted"]},
                    "scope": {"type": ["string", "null"]},
                    "revision_condition": {"type": ["string", "null"]},
                    "evidence_basis": {"type": ["array", "null"],
                                       "items": {"type": "string"}},
                },
            },
            "reply_requested": {"type": ["boolean", "null"]},
            "human_approval_required": {"type": ["boolean", "null"]},
        },
    }


STRICT_RESPONSE_SCHEMA = _strict_schema()

__all__ = [
    "STRICT_RESPONSE_SCHEMA",
    "ADAPTER_MARKER", "AGENT_MESSAGE_TYPES", "RESPONSE_SCHEMA",
    "DEFAULT_CODEX_BIN", "DEFAULT_SANDBOX", "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TURN_LOCK_TIMEOUT_SECONDS",
    "CodexAdapterError", "CodexInvoker", "CodexParticipant",
    "MalformedResponse", "NoWorkAvailable", "TurnLockTimeout",
]


class CodexInvoker:
    """Runs one non-interactive Codex turn.

    Injectable: the tests substitute a stub, so the suite never spends tokens,
    needs a login, or depends on model behaviour.

    The boundary is deliberately narrow and uses only what the installed
    client actually supports:

    - `codex exec -` reads the prompt from **stdin**, so a long thread cannot
      overflow the argument list;
    - `--sandbox read-only` is the default: connectivity must not need write
      access, and widening it is an explicit caller decision, never implicit;
    - `--ephemeral` keeps no session files on disk;
    - `--ignore-user-config` skips `$CODEX_HOME/config.toml`, so **user and
      global MCP servers are not silently enabled**. Authentication still
      resolves from `CODEX_HOME`, so the existing login is reused without any
      credential being read, copied or created here;
    - `--output-schema` (a file) and `--output-last-message` (a file) give the
      structured reply without parsing conversational stdout.

    Capability arrives only as a **named** `tool_profile` whose arguments are
    constructed in `tool_profiles` - never as a caller-supplied argument
    vector, which would be arbitrary flag injection rather than an allowlist.
    `--ignore-user-config` and the output channel are fixed, and the sandbox
    is checked against `ALLOWED_SANDBOXES`, so no construction path can widen
    them. A tool's output is not evidence merely because a tool produced it.
    """

    def __init__(
        self,
        executable: str = DEFAULT_CODEX_BIN,
        *,
        cwd: str | None = None,
        model: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        sandbox: str = DEFAULT_SANDBOX,
        tool_profile=tool_profiles.NONE,
    ) -> None:
        if sandbox not in ALLOWED_SANDBOXES:
            raise CodexAdapterError(
                f"sandbox {sandbox!r} is not permitted for a participant turn; "
                f"allowed: {list(ALLOWED_SANDBOXES)}"
            )
        self.executable = executable
        self.cwd = cwd
        self.model = model
        self.timeout = timeout
        self.sandbox = sandbox
        #: Resolved at construction, so an unknown or unqualified profile can
        #: never reach a command line.
        self.tool_profile = tool_profiles.resolve(tool_profile)

    def command(self, schema_path: str, output_path: str) -> list:
        resolved = shutil.which(self.executable) or self.executable
        args = [
            resolved, "exec", "-",
            "--sandbox", self.sandbox,
            "--skip-git-repo-check",
            "--ephemeral",
            "--output-schema", schema_path,
            "--output-last-message", output_path,
            "--ignore-user-config",
        ]
        if self.model:
            args += ["--model", self.model]
        if self.cwd:
            args += ["-C", self.cwd]
        return args + list(self.tool_profile.codex_arguments())

    def __call__(self, prompt: str) -> str:
        workdir = Path(tempfile.mkdtemp(prefix="agent-room-codex-"))
        schema_path = workdir / "schema.json"
        output_path = workdir / "last-message.txt"
        schema_path.write_text(json.dumps(STRICT_RESPONSE_SCHEMA), encoding="utf-8")
        command = self.command(str(schema_path), str(output_path))
        try:
            try:
                result = run_bounded(
                    command, input=prompt.encode("utf-8"), cwd=self.cwd,
                    timeout=self.timeout, env=sanitised_env(),
                    max_output_bytes=MAX_MODEL_OUTPUT_BYTES,
                )
            except ProcessError as exc:
                raise CodexAdapterError(
                    f"could not run {self.executable}: {exc}"
                ) from exc
            if result.timed_out:
                # The whole process group is already torn down by the time we
                # get here: a model turn that spawns helpers must not leave
                # them running after the turn is abandoned.
                raise CodexAdapterError(
                    f"codex did not return within {self.timeout}s; its process "
                    f"group was {result.teardown}"
                )
            if result.output_limited:
                raise CodexAdapterError(
                    f"codex produced more than {MAX_MODEL_OUTPUT_BYTES} bytes "
                    f"on {', '.join(result.limited_streams)}; its process "
                    f"group was {result.teardown}. The turn is refused, not "
                    "retried with a looser bound."
                )
            stderr = result.stderr.decode("utf-8", "replace")
            if result.returncode != 0:
                raise CodexAdapterError(
                    f"codex exited {result.returncode}: {stderr.strip()[:500]}"
                )
            # The structured result arrives as a file, so the streaming cap
            # above never saw it. Check its size before reading: a read is
            # where an unbounded file becomes unbounded memory.
            try:
                written = output_path.stat().st_size
            except OSError as exc:
                raise MalformedResponse(
                    f"codex wrote no final message: {exc}"
                ) from exc
            assert_within(written, MAX_MODEL_OUTPUT_BYTES,
                          "codex final message")
            try:
                raw = output_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise MalformedResponse(
                    f"codex wrote no final message: {exc}"
                ) from exc
            if not raw.strip():
                raise MalformedResponse("codex wrote an empty final message")
            return raw
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class CodexParticipant(ParticipantAdapter):
    """One bounded Codex turn against a durable room."""

    PARTICIPANT = "codex"
    MARKER = ADAPTER_MARKER
    ROLE = (
        "an engineering participant - you may implement, inspect, test, "
        "challenge, propose or hand off work as the thread requires. You are "
        "not research authority, and no other participant is either"
    )

    def default_invoker(self):
        return CodexInvoker()

    @staticmethod
    def _drop_nulls(value):
        if isinstance(value, dict):
            return {k: CodexParticipant._drop_nulls(v)
                    for k, v in value.items() if v is not None}
        if isinstance(value, list):
            return [CodexParticipant._drop_nulls(v) for v in value]
        return value

    def normalise_payload(self, payload: dict) -> dict:
        """Strict mode returns `null` for every absent optional field.

        Stripping them yields exactly the shape the shared validator and the
        store expect, so nothing downstream has to know which client produced
        the reply.
        """
        return self._drop_nulls(payload)
