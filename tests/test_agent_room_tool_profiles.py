"""The participant capability boundary.

A participant adapter must not offer a generic way to widen what the model can
do. These tests hold that line at the **library** boundary, not merely at one
CLI parser: the invokers are exported public surfaces and the adapters call
them directly.
"""

import inspect
import json

import pytest

from agent_room import tool_profiles
from agent_room.claude_participant import ClaudeInvoker
from agent_room.codex_participant import ALLOWED_SANDBOXES, CodexAdapterError, CodexInvoker
from agent_room.tool_profiles import (
    KNOWN_PROFILES,
    QUALIFIED_PROFILES,
    ToolProfile,
    ToolProfileError,
    ToolProfileUnavailable,
    UnknownToolProfile,
    resolve,
)


# ===== no arbitrary argument injection ====================================

def test_codex_invoker_has_no_raw_argument_passthrough():
    params = inspect.signature(CodexInvoker.__init__).parameters
    assert "extra_args" not in params
    assert params["tool_profile"].default == tool_profiles.NONE


def test_claude_invoker_has_no_raw_argument_passthrough():
    params = inspect.signature(ClaudeInvoker.__init__).parameters
    assert "extra_args" not in params
    assert "restricted" not in params, "no public escape from --restricted"
    assert params["tool_profile"].default == tool_profiles.NONE


@pytest.mark.parametrize("injected", [
    ("-c", "mcp_servers.evil.command=sh"),
    ["--dangerously-bypass-approvals-and-sandbox"],
    ("--sandbox", "danger-full-access"),
    ("--ignore-rules",),
    "--permission-mode bypassPermissions",
    {"tool": "serena"},
    7,
])
def test_arbitrary_values_cannot_be_passed_as_a_tool_profile(injected):
    with pytest.raises(UnknownToolProfile):
        CodexInvoker(tool_profile=injected)
    with pytest.raises(UnknownToolProfile):
        ClaudeInvoker(tool_profile=injected)


# ===== bypass-style options cannot enter through construction =============

@pytest.mark.parametrize("sandbox", [
    "danger-full-access", "DANGER-FULL-ACCESS", "", "anything", None, 7,
])
def test_codex_refuses_an_unsafe_sandbox_at_construction(sandbox):
    with pytest.raises(CodexAdapterError, match="not permitted"):
        CodexInvoker(sandbox=sandbox)


def test_allowed_sandboxes_exclude_full_access():
    assert "danger-full-access" not in ALLOWED_SANDBOXES
    assert ALLOWED_SANDBOXES == ("read-only", "workspace-write")


def test_codex_command_never_contains_bypass_flags():
    for sandbox in ALLOWED_SANDBOXES:
        command = " ".join(CodexInvoker(sandbox=sandbox).command("/s", "/o"))
        assert "danger-full-access" not in command
        assert "--dangerously-bypass-approvals-and-sandbox" not in command
        assert "--approve-for-me" not in command
        assert "--ignore-rules" not in command


def test_claude_command_is_always_restricted_and_strict():
    command = ClaudeInvoker().command()
    assert "--restricted" in command
    assert "--strict-mcp-config" in command
    assert "--permission-mode" not in command
    assert "bypassPermissions" not in " ".join(command)
    assert "--allowedTools" not in command and "--disallowedTools" not in command


def test_codex_config_isolation_is_not_optional():
    params = inspect.signature(CodexInvoker.__init__).parameters
    assert "ignore_user_config" not in params
    assert "--ignore-user-config" in CodexInvoker().command("/s", "/o")


# ===== default profile enables nothing ====================================

def test_default_profile_is_none_and_adds_no_arguments():
    assert resolve(None).name == tool_profiles.NONE
    assert resolve(tool_profiles.NONE).codex_arguments() == ()
    assert resolve(tool_profiles.NONE).claude_arguments() == ()


def test_default_commands_enable_no_tooling_and_no_mcp():
    codex = " ".join(CodexInvoker(cwd="/tmp").command("/s", "/o"))
    claude = " ".join(ClaudeInvoker(cwd="/tmp").command())
    for command in (codex, claude):
        assert "serena" not in command.lower()
        assert "graphify" not in command.lower()
    assert "mcp_servers" not in codex
    assert "--ignore-user-config" in codex, "user/global MCP not loaded"
    assert "--strict-mcp-config" in claude, "MCP servers not loaded"


def test_none_profile_reports_no_tooling():
    profile = resolve("none")
    assert profile.enables_serena is False
    assert profile.enables_graphify is False


# ===== unqualified and unknown names fail controlled ======================

@pytest.mark.parametrize("name", ["serena", "graphify", "serena+graphify"])
def test_recognised_but_unqualified_profiles_are_refused(name):
    """Declared so the seam has a shape; not usable until qualified."""
    assert name in KNOWN_PROFILES and name not in QUALIFIED_PROFILES
    with pytest.raises(ToolProfileUnavailable, match="not yet qualified"):
        resolve(name)
    with pytest.raises(ToolProfileUnavailable):
        CodexInvoker(tool_profile=name)
    with pytest.raises(ToolProfileUnavailable):
        ClaudeInvoker(tool_profile=name)


@pytest.mark.parametrize("name", ["nonsense", "SERENA-ish", "", "  ", "none "])
def test_unknown_profile_names_fail_controlled(name):
    if name.strip().lower() in KNOWN_PROFILES:
        assert resolve(name).name in KNOWN_PROFILES      # tolerant of whitespace/case
        return
    with pytest.raises(UnknownToolProfile):
        resolve(name)


def test_profile_errors_are_agent_room_errors():
    from agent_room.errors import AgentRoomError
    assert issubclass(ToolProfileError, AgentRoomError)
    assert issubclass(UnknownToolProfile, ToolProfileError)
    assert issubclass(ToolProfileUnavailable, ToolProfileError)


# ===== a future profile still cannot widen anything =======================

@pytest.mark.parametrize("forbidden", [
    ["--sandbox", "danger-full-access"],
    ["--dangerously-bypass-approvals-and-sandbox"],
    ["--permission-mode", "bypassPermissions"],
    ["--ignore-user-config"],
    ["--ignore-rules"],
    ["--output-schema", "/tmp/x"],
    ["--model", "something"],
    ["--cd", "/etc"],
    ["--settings", "/tmp/s.json"],
    ["--allowedTools", "Bash"],
])
def test_a_profile_emitting_a_guaranteed_setting_is_refused(monkeypatch, forbidden):
    """Defensive: a future profile cannot reintroduce the hole this closed."""
    monkeypatch.setattr(ToolProfile, "_arguments", lambda self: tuple(forbidden))
    profile = resolve("none")
    with pytest.raises(ToolProfileError, match="may not alter"):
        profile.codex_arguments()
    with pytest.raises(ToolProfileError, match="may not alter"):
        profile.claude_arguments()


def test_a_profile_emitting_non_strings_is_refused(monkeypatch):
    monkeypatch.setattr(ToolProfile, "_arguments", lambda self: (7,))
    with pytest.raises(ToolProfileError, match="non-string"):
        resolve("none").codex_arguments()


def test_a_benign_future_profile_argument_is_allowed(monkeypatch):
    """The guard blocks guaranteed settings, not tooling itself."""
    monkeypatch.setattr(ToolProfile, "_arguments",
                        lambda self: ("-c", "mcp_servers.serena.command=serena"))
    assert resolve("none").codex_arguments() == (
        "-c", "mcp_servers.serena.command=serena")


# ===== CLI surface ========================================================

def test_cli_rejects_an_unqualified_profile(store, tmp_path, capsys):
    from agent_room import AgentRoom, ParticipantCursor
    from agent_room.cli import main

    supervisor = AgentRoom(store, "supervisor",
                           ParticipantCursor(tmp_path / "sup", "supervisor"))
    supervisor.post(thread_id="t1", type="question", body={"text": "?"},
                    recipient={"agent": "codex"})

    code = main(["--repo", str(store.workdir), "--participant", "codex",
                 "--state-dir", str(tmp_path / "cx"), "codex-turn",
                 "--tool-profile", "serena", "--codex-bin", "/nonexistent"])
    err = capsys.readouterr().err
    assert code == 2
    assert "ToolProfileUnavailable" in err and "Traceback" not in err


def test_cli_rejects_an_unknown_profile(store, tmp_path, capsys):
    """A flag smuggled in as the profile VALUE still fails controlled."""
    from agent_room.cli import main

    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "--state-dir", str(tmp_path / "cl"), "claude-turn",
                 "--tool-profile=--sandbox=danger-full-access"])
    err = capsys.readouterr().err
    assert code == 2
    assert "UnknownToolProfile" in err and "Traceback" not in err


def test_cli_tool_profile_requires_a_value(store, tmp_path):
    """argparse refuses a bare flag before the library is even reached."""
    from agent_room.cli import main

    with pytest.raises(SystemExit):
        main(["--repo", str(store.workdir), "--participant", "claude-code",
              "--state-dir", str(tmp_path / "cl"), "claude-turn",
              "--tool-profile", "--sandbox=danger-full-access"])
