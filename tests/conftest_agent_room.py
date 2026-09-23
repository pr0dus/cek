"""Shared fixtures for the Agent Room tests.

Every fixture builds a throwaway Git repository under pytest's tmp_path. No
test touches the real `agent-room` transport branch, any real remote, or the
existing chatgpt-ubuntu-bridge.
"""

import subprocess

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor


def git(repo, *args):
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr}"
    return proc.stdout


def configure_identity(repo):
    git(repo, "config", "user.name", "test")
    git(repo, "config", "user.email", "test@localhost")


@pytest.fixture
def store(tmp_path):
    """A local-only append-only store. No remote, so nothing can be pushed."""
    s = GitMessageStore.initialise(tmp_path / "room", branch="agent-room")
    configure_identity(s.workdir)
    return s


@pytest.fixture
def room(store, tmp_path):
    cursor = ParticipantCursor(tmp_path / "state", "claude-code")
    return AgentRoom(store, "claude-code", cursor)


@pytest.fixture
def bare_remote(tmp_path):
    """A bare repo standing in for the GitHub remote."""
    path = tmp_path / "remote.git"
    path.mkdir()
    git(path, "init", "-q", "--bare")
    return path


# -- Issue #5 helpers -------------------------------------------------------

#: Stand-in digests. Real ones come from `snapshot.snapshot_manifest` and
#: `supervisor.context_digest`; these keep binding tests independent of a
#: checkout.
SNAPSHOT_SHA = "a" * 64
CONTEXT_SHA = "b" * 64


def bound_action(
    action_id: str = "activate-agent-room-transport",
    *,
    snapshot: str = SNAPSHOT_SHA,
    context: str = CONTEXT_SHA,
    scope: str = "create the production agent-room transport branch",
    consequential: bool = True,
    project: dict | None = None,
) -> dict:
    binding = {"snapshot_sha256": snapshot, "supervisor_context_sha256": context}
    if project is not None:
        binding["project"] = project
    return {
        "action_id": action_id,
        "scope": scope,
        "consequential": consequential,
        "binding": binding,
    }


def post_decision_request(room, thread_id: str = "t1", **kwargs) -> dict:
    """An agent asking a human to release a bound consequential action."""
    text = kwargs.pop("text", "This needs a human decision.")
    return room.post(
        thread_id=thread_id, type="decision_request", body={"text": text},
        human_approval_required=True, action=bound_action(**kwargs),
    )
