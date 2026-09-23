"""Claude Code as an Agent Room participant.

The turn protocol - single-flight lock, reconciliation, three-valued
persistence, authority boundary - lives in `participant.py` and is shared with
every other participant. Only the invocation boundary is Claude-specific.
"""

import json
import shutil
import subprocess

from . import tool_profiles
from .participant import (
    AGENT_MESSAGE_TYPES,
    DEFAULT_TURN_LOCK_TIMEOUT_SECONDS,
    RESPONSE_SCHEMA,
    MalformedResponse,
    NoWorkAvailable,
    ParticipantAdapter,
    ParticipantAdapterError,
    TurnLockTimeout,
    parse_json,
)

#: Kept as the adapter's own error name; the shared base class raises it.
ClaudeAdapterError = ParticipantAdapterError

DEFAULT_CLAUDE_BIN = "claude"
DEFAULT_TIMEOUT_SECONDS = 900

#: Stamped into `sender.via` on every reply this adapter posts, so an
#: automatic turn can be told from a reply a human drove by hand. An audit
#: marker, not a security control - `sender.agent` is what provenance rests on.
ADAPTER_MARKER = "agent-room-claude-adapter"

__all__ = [
    "ADAPTER_MARKER", "AGENT_MESSAGE_TYPES", "RESPONSE_SCHEMA",
    "DEFAULT_CLAUDE_BIN", "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TURN_LOCK_TIMEOUT_SECONDS",
    "ClaudeAdapterError", "ClaudeInvoker", "ClaudeParticipant",
    "MalformedResponse", "NoWorkAvailable", "TurnLockTimeout",
]


class ClaudeInvoker:
    """Runs one non-interactive Claude Code turn.

    Injectable: the tests substitute a stub so the suite never spends tokens,
    needs a login, or depends on model behaviour.

    The boundary is fixed, not configurable. `--restricted` drops the
    code-running tools and WebFetch and confines file tools to the working
    directory, `--strict-mcp-config` drops MCP servers, and the prompt goes
    over stdin so a large thread cannot overflow the argument list. There is
    deliberately **no** way to disable either and **no** arbitrary argument
    passthrough: the installed client's permission system is reused, never
    widened. Extra capability arrives only as a named, allowlisted
    `tool_profile` whose arguments are constructed in `tool_profiles`.
    """

    def __init__(
        self,
        executable: str = DEFAULT_CLAUDE_BIN,
        *,
        cwd: str | None = None,
        model: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        tool_profile=tool_profiles.NONE,
    ) -> None:
        self.executable = executable
        self.cwd = cwd
        self.model = model
        self.timeout = timeout
        #: Resolved at construction, so an unknown or unqualified profile can
        #: never reach a command line.
        self.tool_profile = tool_profiles.resolve(tool_profile)

    def command(self) -> list:
        resolved = shutil.which(self.executable) or self.executable
        args = [
            resolved, "-p",
            "--output-format", "json",
            "--json-schema", json.dumps(RESPONSE_SCHEMA),
            "--strict-mcp-config",
            "--restricted",
        ]
        if self.model:
            args += ["--model", self.model]
        return args + list(self.tool_profile.claude_arguments())

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

        envelope = parse_json(proc.stdout, "claude --output-format json output")
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


class ClaudeParticipant(ParticipantAdapter):
    """One bounded Claude turn against a durable room."""

    PARTICIPANT = "claude-code"
    MARKER = ADAPTER_MARKER
    ROLE = "a research collaborator, not an authority"
    LEGACY_INVOKED_KEY = "invoked_claude"

    def default_invoker(self):
        return ClaudeInvoker()
