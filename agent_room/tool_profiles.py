"""Named, allowlisted tool profiles for participant invocations.

A participant adapter must not offer a generic way to widen what the model can
do. Appending a caller-supplied argument vector to a client command is not an
allowlist — it is arbitrary flag injection, and it can override the very
defaults the adapter exists to guarantee.

So capability is named, never spelled. A caller asks for `"none"` or
`"serena"`; the arguments, if any, are constructed **here** from that name. No
raw argument vector crosses the API.

Today only `none` is qualified. The others are declared so the seam has a
shape, and resolving one fails cleanly rather than guessing launch flags for
tooling that has not been independently inspected — a guess is exactly the
kind of invented precision this project keeps refusing elsewhere.
"""

from dataclasses import dataclass

from .errors import AgentRoomError

NONE = "none"
SERENA = "serena"
GRAPHIFY = "graphify"
SERENA_GRAPHIFY = "serena+graphify"

#: Every name the API recognises.
KNOWN_PROFILES = (NONE, SERENA, GRAPHIFY, SERENA_GRAPHIFY)

#: Names actually qualified for use. Extending this is a deliberate act that
#: must follow a tooling qualification, not a convenience edit.
QUALIFIED_PROFILES = (NONE,)

#: A profile may add tooling. It may never touch the guarantees the adapter
#: makes: sandbox/restriction, approval or permission mode, user-config and
#: rules isolation, authentication, the output schema and result channel, the
#: model, or the project path. Any profile emitting one of these is a bug, and
#: is refused rather than trusted.
FORBIDDEN_ARGUMENT_TOKENS = (
    "--sandbox", "danger-full-access", "--dangerously-bypass-approvals-and-sandbox",
    "--approve-for-me", "--permission-mode", "--restricted", "--no-restricted",
    "--ignore-user-config", "--ignore-rules", "--ignore-config",
    "--output-schema", "--output-last-message", "--json-schema",
    "--output-format", "--strict-mcp-config", "--settings",
    "--allowedTools", "--allowed-tools", "--disallowedTools", "--disallowed-tools",
    "--model", "--worktree", "--add-dir", "--cd", "--tools", "--plugin-dir",
    "--agents", "--system-prompt", "--append-system-prompt",
)


class ToolProfileError(AgentRoomError):
    """The requested tool profile is not usable."""


class UnknownToolProfile(ToolProfileError):
    """No such profile name."""


class ToolProfileUnavailable(ToolProfileError):
    """A recognised profile that has not been qualified yet."""


def _assert_safe(arguments, profile_name: str, client: str) -> tuple:
    """Refuse any profile argument that would touch a guaranteed setting.

    Defensive: today every qualified profile returns nothing, so this cannot
    fire. It exists so that a future profile cannot quietly reintroduce the
    hole this module was written to close.
    """
    for argument in arguments:
        if not isinstance(argument, str):
            raise ToolProfileError(
                f"{client} profile {profile_name!r} produced a non-string "
                f"argument: {argument!r}"
            )
        for token in FORBIDDEN_ARGUMENT_TOKENS:
            if argument == token or argument.startswith(f"{token}="):
                raise ToolProfileError(
                    f"{client} profile {profile_name!r} tried to set {token!r}; "
                    "a tool profile may not alter sandbox, permissions, config "
                    "isolation, authentication, output channel or project path"
                )
    return tuple(arguments)


@dataclass(frozen=True)
class ToolProfile:
    """A resolved, qualified capability profile."""

    name: str

    @property
    def enables_serena(self) -> bool:
        return self.name in (SERENA, SERENA_GRAPHIFY)

    @property
    def enables_graphify(self) -> bool:
        return self.name in (GRAPHIFY, SERENA_GRAPHIFY)

    def claude_arguments(self) -> tuple:
        return _assert_safe(self._arguments(), self.name, "claude")

    def codex_arguments(self) -> tuple:
        return _assert_safe(self._arguments(), self.name, "codex")

    def _arguments(self) -> tuple:
        # `none` is the only qualified profile, and it adds nothing. When
        # Serena or Graphify are qualified, their arguments are built here
        # from this name - never accepted from a caller.
        return ()


def resolve(profile) -> ToolProfile:
    """Turn a profile name into a qualified profile, or fail cleanly."""
    if isinstance(profile, ToolProfile):
        name = profile.name
    elif profile is None:
        name = NONE
    elif isinstance(profile, str):
        name = profile.strip().lower()
    else:
        raise UnknownToolProfile(
            f"tool profile must be a name, got {type(profile).__name__} {profile!r}"
        )

    if name not in KNOWN_PROFILES:
        raise UnknownToolProfile(
            f"unknown tool profile {name!r}; known profiles: {list(KNOWN_PROFILES)}"
        )
    if name not in QUALIFIED_PROFILES:
        raise ToolProfileUnavailable(
            f"tool profile {name!r} is recognised but not yet qualified; "
            f"available now: {list(QUALIFIED_PROFILES)}. Qualify the tooling "
            "before enabling it rather than guessing its launch arguments."
        )
    return ToolProfile(name)
