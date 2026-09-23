"""Issue #3 acceptance: disposable remotes and a controlled one-shot client."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor
from agent_room.claude_participant import ClaudeParticipant
from agent_room.errors import AgentRoomError, DeliveryError, ForbiddenOperation, SyncDivergedError
from tests.conftest_agent_room import git, configure_identity


@pytest.fixture
def setup(tmp_path, bare_remote):
    store = GitMessageStore.initialise(tmp_path / "supervisor")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    supervisor = AgentRoom(store, "supervisor")
    first = supervisor.post(thread_id="research", type="question", body={"text": "Inspect this"},
                            recipient={"agent": "claude-code"})
    clone = tmp_path / "claude-room"
    git(tmp_path, "clone", "-q", "--branch", "agent-room", str(bare_remote), str(clone))
    configure_identity(clone)
    participant = ClaudeParticipant(clone, state_dir=tmp_path / "state", push_retries=1)
    return supervisor, participant, first, bare_remote


@pytest.fixture
def client(tmp_path, monkeypatch):
    directory = tmp_path / "bin"
    directory.mkdir()
    output = tmp_path / "model.json"
    output.write_text(json.dumps({"type": "result", "subtype": "success", "is_error": False,
        "structured_output": {"type": "answer", "body": {"text": "bounded reply"},
                              "evidence": [], "human_approval_required": False,
                              "claim": {}}}))
    record = tmp_path / "invocations.jsonl"
    executable = directory / "claude"
    executable.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
with open(os.environ["TEST_CLAUDE_RECORD"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(), "prompt": sys.stdin.read()}) + "\\n")
print(pathlib.Path(os.environ["TEST_CLAUDE_OUTPUT"]).read_text())
''')
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(directory) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("TEST_CLAUDE_RECORD", str(record))
    monkeypatch.setenv("TEST_CLAUDE_OUTPUT", str(output))
    return output, record


def cli(participant, *args):
    return subprocess.run([sys.executable, "-m", "agent_room.claude_cli",
        "--repo", str(participant.store.workdir), "--state-dir", str(participant.cursor.state_dir),
        *args], text=True, capture_output=True, timeout=30)


def test_identity_and_authority(setup):
    _, p, _, _ = setup
    with pytest.raises(TypeError):
        ClaudeParticipant(p.store.workdir, state_dir=p.cursor.state_dir, participant="human")
    with pytest.raises(ForbiddenOperation):
        p.start_thread(thread_id="spoof", type="answer", body={"text": "no"}, sender={"agent": "human"})
    for kind in ("approval", "rejection"):
        with pytest.raises(ForbiddenOperation):
            p.start_thread(thread_id="spoof", type=kind, body={"text": "no"})
    result = cli(p, "send", "spoof", "--message", json.dumps({"sender": {"agent": "human"},
                                      "type": "answer", "body": {"text": "no"}}))
    assert result.returncode == 2 and "Traceback" not in result.stderr
    assert cli(p, "--participant", "human", "inbox").returncode == 2
    assert len(p.thread("research")) == 1


@pytest.mark.parametrize("operation", ["inbox", "get", "thread", "tree", "ack", "verify", "reply"])
def test_every_read_syncs_exact_ref(setup, operation):
    supervisor, p, _, remote = setup
    stale = git(p.store.workdir, "rev-parse", "HEAD").strip()
    new = supervisor.post(thread_id="research", type="question", body={"text": "fresh"},
                          recipient={"agent": "claude-code"})
    # A shadowing tag must not substitute for the branch; unrelated refs stay unfetched.
    git(supervisor.store.workdir, "tag", "agent-room", stale)
    git(supervisor.store.workdir, "push", str(remote), "refs/tags/agent-room")
    git(supervisor.store.workdir, "push", str(remote), "HEAD:refs/heads/unrelated")
    calls = []
    original = p.store._git
    def record(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)
    with patch.object(p.store, "_git", side_effect=record):
        if operation == "inbox":
            assert new["message_id"] in {m["message_id"] for m in p.inbox()}
        elif operation == "get":
            assert p.get("research", new["message_id"])["body"]["text"] == "fresh"
        elif operation == "thread":
            assert len(p.thread("research")) == 2
        elif operation == "tree":
            assert len(p.thread_tree("research")) == 2
        elif operation == "ack":
            p.acknowledge(new["message_id"])
        elif operation == "verify":
            assert p.verify() == 2
        else:
            assert p.reply(new["message_id"], type="answer", body={"text": "seen"})["pushed"]
    fetches = [args for args in calls if args[0] == "fetch"]
    assert fetches == [("fetch", "-q", "--no-tags", "--no-recurse-submodules", "origin", "refs/heads/agent-room")]
    assert "origin/unrelated" not in git(p.store.workdir, "branch", "-r")
    assert git(p.store.workdir, "tag").strip() == ""


def test_inbox_ack_thread_evidence_restart(setup):
    supervisor, p, first, _ = setup
    evidence = [{"kind": "external", "url": "https://github.com/pr0dus/cek/issues/3"}]
    reply = p.reply(first["message_id"], type="hypothesis", body={"text": "proposed"},
                    evidence=evidence, claim={"status": "proposed"})
    p.acknowledge(first["message_id"])
    fresh = ClaudeParticipant(p.store.workdir, state_dir=p.cursor.state_dir)
    assert fresh.inbox() == []
    messages = fresh.thread("research")
    assert len(messages) == 2
    assert messages[1]["sender"]["agent"] == "claude-code"
    assert messages[1]["parent_id"] == first["message_id"]
    assert messages[1]["evidence"] == evidence
    assert messages[1]["claim"]["status"] == "proposed"
    second = fresh.reply(reply["message_id"], type="question", body={"text": "continue"})
    assert fresh.thread_tree("research")[1]["children"] == [second["message_id"]]
    with pytest.raises(AgentRoomError):
        fresh.start_thread(thread_id="decision", type="decision_request", body={"text": "approve?"})
    decision = fresh.start_thread(thread_id="decision", type="decision_request", body={"text": "approve?"},
                                  human_approval_required=True)
    assert fresh.get("decision", decision["message_id"])["human_approval_required"] is True


def test_divergence_fails_without_reset(setup):
    supervisor, p, _, _ = setup
    local = AgentRoom(GitMessageStore(p.store.workdir), "claude-code")
    local.post(thread_id="local", type="answer", body={"text": "unpublished"})
    before = git(p.store.workdir, "rev-parse", "HEAD")
    supervisor.post(thread_id="remote", type="question", body={"text": "new"})
    with pytest.raises(SyncDivergedError):
        p.inbox()
    assert git(p.store.workdir, "rev-parse", "HEAD") == before
    assert len(local.thread("local")) == 1
    assert git(p.store.workdir, "status", "--porcelain") == ""


def test_missing_remote_fails_closed(setup):
    _, p, _, remote = setup
    git(remote, "update-ref", "-d", "refs/heads/agent-room")
    with pytest.raises(AgentRoomError):
        p.inbox()
    with pytest.raises(ValueError):
        ClaudeParticipant(p.store.workdir, state_dir=p.cursor.state_dir, remote=None)


def test_turn_process_restart_one_shot(setup, client, tmp_path):
    supervisor, p, first, _ = setup
    followup = supervisor.reply(first["message_id"], type="question", body={"text": "latest context"},
                                recipient={"agent": "claude-code"})
    outcome = cli(p, "turn", "--project-dir", str(tmp_path), "--message-id", first["message_id"])
    assert outcome.returncode == 0, outcome.stderr
    result = json.loads(outcome.stdout)
    assert result["acknowledged"] == first["message_id"]
    assert result["response"]["pushed"] is True
    record = [json.loads(line) for line in client[1].read_text().splitlines()]
    assert len(record) == 1
    assert record[0]["cwd"] == str(tmp_path)
    assert "latest context" in record[0]["prompt"]
    assert followup["message_id"] in record[0]["prompt"]
    argv = record[0]["argv"]
    assert "--print" in argv and "--safe-mode" in argv
    assert argv[argv.index("--tools") + 1] == ""
    assert "--dangerously-skip-permissions" not in argv and "--background" not in argv
    # Fresh OS process recovers the durable thread and cursor.
    recovered = cli(p, "thread", "research")
    messages = json.loads(recovered.stdout)
    assert messages[-1]["parent_id"] == first["message_id"]
    assert messages[-1]["sender"]["agent"] == "claude-code"
    unread = json.loads(cli(p, "inbox").stdout)
    assert [m["message_id"] for m in unread] == [followup["message_id"]]
    assert cli(p, "turn", "--project-dir", str(tmp_path)).returncode == 0
    assert json.loads(cli(p, "turn", "--project-dir", str(tmp_path)).stdout)["status"] == "idle"
    assert len(client[1].read_text().splitlines()) == 2


@pytest.mark.parametrize("bad", ["not JSON", "[]", '{"type":"result","type":"result"}',
    {"type": "approval", "body": {"text": "approved"}},
    {"type": "rejection", "body": {"text": "rejected"}},
    {"type": "decision_request", "body": {"text": "approval?"}},
    {"type": "answer", "body": {"text": "spoof"}, "sender": {"agent": "human"}},
    {"type": "answer", "body": []},
    {"type": "answer", "body": {"text": "cross-thread"}, "thread_id": "elsewhere"}])
def test_malformed_model_output_never_posts_or_acks(setup, client, tmp_path, bad):
    _, p, first, _ = setup
    if isinstance(bad, dict):
        bad = json.dumps({"type": "result", "subtype": "success", "is_error": False,
            "structured_output": {"evidence": [], "human_approval_required": False, **bad}})
    client[0].write_text(bad)
    before = git(p.store.workdir, "rev-parse", "HEAD")
    result = cli(p, "turn", "--project-dir", str(tmp_path))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert git(p.store.workdir, "rev-parse", "HEAD") == before
    assert not p.cursor.is_acknowledged(first["message_id"])


def test_failed_push_preserves_retryable_reply(setup, client, tmp_path):
    _, p, first, remote = setup
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(DeliveryError) as error:
        p.turn(project_dir=tmp_path)
    assert error.value.locally_committed
    assert not p.cursor.is_acknowledged(first["message_id"])
    assert len(p.thread("research")) == 2
    with pytest.raises(AgentRoomError, match="already exists"):
        p.turn(project_dir=tmp_path)
    assert len(client[1].read_text().splitlines()) == 1
    hook.unlink()
    assert p.push()["pushed"]
    p.acknowledge(first["message_id"])
    assert p.inbox() == []


def test_timeout_and_invalid_bounds(setup, tmp_path):
    _, p, first, _ = setup
    from agent_room.claude_participant import invoke_claude
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("claude", 1)):
        with pytest.raises(AgentRoomError, match="TimeoutExpired"):
            invoke_claude({}, [], project_dir=tmp_path, timeout=1)
    for value in (0, -1, float("nan"), float("inf"), 601):
        with pytest.raises(ValueError):
            p.turn(project_dir=tmp_path, timeout=value)
    assert not p.cursor.is_acknowledged(first["message_id"])


def test_sync_respects_writer_lock(setup):
    _, p, _, _ = setup
    from agent_room.errors import LockTimeout
    p.store.lock_timeout = 0
    with p.store.writer_lock():
        with pytest.raises(LockTimeout):
            p.inbox()
