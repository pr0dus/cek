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
