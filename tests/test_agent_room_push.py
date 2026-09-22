"""Concurrent writers racing on the branch ref.

Participants never target the same message path — ids are UUIDv7s — so a race
appears only as a non-fast-forward on the branch ref (design §5). The store
must resolve that by fetch/rebase-and-retry, and must give up after a bounded
number of attempts rather than spinning.

All fixtures are local throwaway repositories. No real remote is contacted and
the live `agent-room` branch is never created.
"""

import subprocess

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor
from agent_room.errors import DeliveryError, PushRaceError
from tests.conftest_agent_room import configure_identity, git


def _clone_participant(bare_remote, path, name, tmp_path, retries=3):
    git(path.parent, "clone", "-q", str(bare_remote), str(path))
    configure_identity(path)
    git(path, "checkout", "-q", "agent-room")
    store = GitMessageStore(path, branch="agent-room", remote=str(bare_remote), push_retries=retries)
    return AgentRoom(store, name, ParticipantCursor(tmp_path / f"state-{name}", name))


def test_push_succeeds_when_the_remote_has_not_moved(tmp_path, bare_remote):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    result = room.post(thread_id="t1", type="observation", body={"text": "one"})
    assert result["push"] == {"pushed": True, "attempts": 1}


def test_non_fast_forward_race_is_resolved_by_rebase(tmp_path, bare_remote):
    """Two participants commit concurrently; both messages survive."""
    first = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(first.workdir)
    first.remote = str(bare_remote)
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "from claude"})

    second = _clone_participant(bare_remote, tmp_path / "b", "openai-research", tmp_path)

    # The remote advances after B cloned - B's next push is non-fast-forward.
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "claude again"})

    result = second.post(thread_id="t1", type="answer", body={"text": "from openai"})
    assert result["push"]["pushed"] is True
    assert result["push"]["attempts"] >= 2, "expected at least one rejected attempt"

    texts = {m["body"]["text"] for m in second.store.iter_messages()}
    assert texts == {"from claude", "claude again", "from openai"}


def test_retry_is_bounded_and_raises(tmp_path, bare_remote):
    """A permanently rejecting remote must fail, not loop forever."""
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'rejected by test hook' >&2\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 2
    room = AgentRoom(store, "claude-code", None)

    # push() itself reports the bounded exhaustion...
    with pytest.raises(PushRaceError, match="after 2 attempts"):
        store.push()

    # ...and post() surfaces it as a delivery failure, since by then the
    # message is already committed locally.
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "never lands"})
    assert isinstance(exc.value.cause, PushRaceError)
    assert "after 2 attempts" in str(exc.value.cause)


def test_push_retries_must_be_at_least_one(tmp_path):
    with pytest.raises(ValueError):
        GitMessageStore(tmp_path, push_retries=0)


def test_local_only_store_never_pushes(store, room):
    """Without a remote configured nothing leaves the machine."""
    result = room.post(thread_id="t1", type="observation", body={"text": "local"})
    assert "push" not in result
    assert store.push() == {"pushed": False, "reason": "no remote configured"}


def test_a_failed_push_does_not_lose_the_local_commit(tmp_path, bare_remote):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "held locally"})

    assert exc.value.locally_committed is True
    assert exc.value.pushed is False
    assert [m["body"]["text"] for m in store.iter_messages()] == ["held locally"]
    assert store.read("t1", exc.value.message_id)["body"]["text"] == "held locally"
