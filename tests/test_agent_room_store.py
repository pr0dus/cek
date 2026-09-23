"""Append-only durability, identity conflicts, and deterministic threading.

The store's whole job is that research state survives and cannot be quietly
rewritten. Each test here corresponds to something that, if broken, would let
history change without anyone noticing.
"""

import json
import os
import subprocess
import sys
import time

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.errors import ConflictError
from agent_room.ids import uuid7


# -- Issue #2 test 1: survives process restart ------------------------------

def test_messages_survive_a_real_process_restart(tmp_path, store, room):
    """Written by this process, read back by a genuinely separate one."""
    posted = room.post(
        thread_id="t1", type="observation",
        body={"text": "survives"},
        project={"repo": "pr0dus/concept-evolution-kernel"},
    )

    script = (
        "import sys, json;"
        f"sys.path.insert(0, {str(os.getcwd())!r});"
        "from agent_room import GitMessageStore;"
        f"s = GitMessageStore({str(store.workdir)!r}, branch='agent-room');"
        f"print(json.dumps(s.read('t1', {posted['message_id']!r})))"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["body"]["text"] == "survives"


def test_a_fresh_store_object_sees_prior_history(tmp_path, store, room):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    reopened = GitMessageStore(store.workdir, branch="agent-room")
    assert len(list(reopened.iter_messages())) == 1


# -- Issue #2 test 8 + supervisor: identity conflicts ------------------------

def test_same_id_different_content_is_refused(store, room):
    """The prior content stays authoritative; the write is rejected."""
    mid = uuid7()
    room.post(thread_id="t1", type="observation", body={"text": "original"}, message_id=mid)

    second = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "impostor"}, message_id=mid,
    ))
    with pytest.raises(ConflictError):
        store.append(second)

    assert store.read("t1", mid)["body"]["text"] == "original"
    assert len(list(store.iter_messages())) == 1


def test_same_id_same_content_is_idempotent(store, room):
    """A retried submission must not duplicate or fail."""
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "once"},
        message_id=uuid7(), timestamp="2026-09-22T10:00:00Z",
    ))
    first = store.append(envelope)
    second = store.append(envelope)

    assert first["status"] == "created"
    assert second["status"] == "duplicate"
    assert len(list(store.iter_messages())) == 1


def test_history_is_not_rewritten_by_a_conflicting_write(store, room):
    mid = uuid7()
    room.post(thread_id="t1", type="observation", body={"text": "original"}, message_id=mid)
    commits_before = store._git("rev-list", "--count", "agent-room").stdout.strip()

    with pytest.raises(ConflictError):
        store.append(canonical.seal(room.build_envelope(
            thread_id="t1", type="observation", body={"text": "other"}, message_id=mid)))

    assert store._git("rev-list", "--count", "agent-room").stdout.strip() == commits_before


# -- Issue #2 test 4: retraction preserves the original ----------------------

def test_retraction_leaves_the_original_intact(room):
    """Corrections stay visible — PROCESS.md rule 2."""
    original = room.post(
        thread_id="t1", type="claim",
        body={"text": "closure admits inactive dependents"},
        claim={"status": "proposed"},
    )
    room.reply(
        original["message_id"], type="retraction",
        body={"text": "withdrawn: misread _active_dependency_closure"},
    )

    thread = room.thread("t1")
    assert len(thread) == 2
    kept = room.get("t1", original["message_id"])
    assert kept["body"]["text"] == "closure admits inactive dependents"
    assert kept["claim"]["status"] == "proposed"
    assert thread[1]["parent_id"] == original["message_id"]


def test_acknowledging_never_modifies_the_artifact(room, store):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    before = (store.workdir / posted["path"]).read_bytes()
    head_before = store._git("rev-parse", "agent-room").stdout.strip()

    room.acknowledge(posted["message_id"])

    assert (store.workdir / posted["path"]).read_bytes() == before
    assert store._git("rev-parse", "agent-room").stdout.strip() == head_before


# -- Issue #2 test 3: reply linkage -----------------------------------------

def test_replies_link_to_parents(room):
    root = room.post(thread_id="t1", type="claim", body={"text": "root"})
    a = room.reply(root["message_id"], type="challenge", body={"text": "contest"})
    b = room.reply(root["message_id"], type="answer", body={"text": "respond"})

    tree = {n["message_id"]: n for n in room.thread_tree("t1")}
    assert tree[root["message_id"]]["parent_id"] is None
    assert set(tree[root["message_id"]]["children"]) == {a["message_id"], b["message_id"]}
    assert tree[a["message_id"]]["parent_id"] == root["message_id"]


def test_reply_inherits_the_parent_thread(room):
    root = room.post(thread_id="research-1", type="question", body={"text": "?"})
    child = room.reply(root["message_id"], type="answer", body={"text": "!"})
    assert child["thread_id"] == "research-1"


# -- Issue #2 test 2 + supervisor: deterministic reconstruction --------------

def test_thread_reconstruction_is_deterministic(room):
    ids = [
        room.post(thread_id="t1", type="observation", body={"text": str(i)})["message_id"]
        for i in range(6)
    ]
    for _ in range(5):
        assert [m["message_id"] for m in room.thread("t1")] == ids


def test_ordering_is_commit_order_not_filename_sort(store, room):
    """A later-sorting id committed first must still come first.

    UUIDv7 usually sorts chronologically, so the two orders normally agree.
    Forcing them apart proves the store reads history, not names.
    """
    later_id = uuid7(when_ms=1_800_000_000_000)
    earlier_id = uuid7(when_ms=1_700_000_000_000)
    room.post(thread_id="t1", type="observation", body={"text": "first"}, message_id=later_id)
    room.post(thread_id="t1", type="observation", body={"text": "second"}, message_id=earlier_id)

    assert sorted([later_id, earlier_id]) == [earlier_id, later_id]
    assert [m["message_id"] for m in room.thread("t1")] == [later_id, earlier_id]


def test_ordering_ignores_filesystem_mtime(store, room):
    """Checkout order is an artifact; it must not decide history."""
    ids = [
        room.post(thread_id="t1", type="observation", body={"text": str(i)})["message_id"]
        for i in range(4)
    ]
    base = time.time()
    for offset, mid in enumerate(reversed(ids)):
        path = store.workdir / store.message_path("t1", mid)
        os.utime(path, (base + offset * 1000, base + offset * 1000))

    assert [m["message_id"] for m in room.thread("t1")] == ids


def test_threads_are_listed_in_commit_order(room):
    room.post(thread_id="zeta", type="observation", body={"text": "1"})
    room.post(thread_id="alpha", type="observation", body={"text": "2"})
    assert room.store.thread_ids() == ["zeta", "alpha"]


# -- Issue #2 test 6: filtering ---------------------------------------------

def test_filter_by_project_repo(room):
    room.post(thread_id="t1", type="observation", body={"text": "cek"},
              project={"repo": "pr0dus/cek"})
    room.post(thread_id="t2", type="observation", body={"text": "newi"},
              project={"repo": "pr0dus/concept-evolution-kernel"})

    hits = room.by_project("pr0dus/cek")
    assert [m["body"]["text"] for m in hits] == ["cek"]


def test_filter_by_thread(room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    room.post(thread_id="t2", type="observation", body={"text": "b"})
    assert [m["body"]["text"] for m in room.by_thread("t2")] == ["b"]


def test_filter_by_participant(store, tmp_path):
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "s1", "claude-code"))
    openai = AgentRoom(store, "openai-research", ParticipantCursor(tmp_path / "s2", "openai-research"))

    claude.post(thread_id="t1", type="observation", body={"text": "from claude"},
                recipient={"agent": "openai-research"})
    openai.post(thread_id="t1", type="answer", body={"text": "from openai"},
                recipient={"agent": "claude-code"})

    assert len(claude.by_participant("claude-code")) == 2   # sent one, received one
    assert len(claude.by_participant("claude-code", role="sender")) == 1
    assert claude.by_participant("claude-code", role="sender")[0]["body"]["text"] == "from claude"


# -- Issue #2 test 7: malformed input ---------------------------------------

def test_malformed_message_is_never_committed(store, room):
    from agent_room.errors import SchemaError

    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="not-a-real-type", body={"text": "x"})
    assert list(store.iter_messages()) == []


def test_unsealed_envelope_cannot_be_appended(store, room):
    from agent_room.errors import IntegrityError

    with pytest.raises(IntegrityError):
        store.append(room.build_envelope(thread_id="t1", type="observation", body={"text": "x"}))
