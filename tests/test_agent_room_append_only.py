"""Append-only enforcement, branch pinning, and the store trust boundary.

These cover the failure modes a digest alone cannot: an attacker who rewrites
a message can recompute its digest, and a deletion leaves nothing to verify.
Only the commit history shows that a message is not what was committed, so
history is the authority and any later mutation fails the read closed.
"""

import json

import pytest

from agent_room import GitMessageStore, canonical
from agent_room.errors import AppendOnlyViolation, SchemaError, WrongBranchError
from agent_room.ids import uuid7
from tests.conftest_agent_room import configure_identity, git


# -- 1. append-only is mechanical -------------------------------------------

def test_resealed_rewrite_is_detected(store, room):
    """The hard case: content changed *and* the digest recomputed to match."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    path = store.workdir / posted["path"]

    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["body"] = {"text": "rewritten and resealed"}
    del envelope["envelope_sha256"]
    rewritten = canonical.seal(envelope)
    canonical.verify(rewritten)          # the forgery is internally consistent
    path.write_text(canonical.canonical_text(rewritten), encoding="utf-8")
    store._git("add", posted["path"])
    store._commit("rewrite with a valid digest")

    with pytest.raises(AppendOnlyViolation, match="append-only"):
        store.read("t1", posted["message_id"])
    with pytest.raises(AppendOnlyViolation):
        list(store.iter_messages())


def test_deleted_message_fails_loudly_instead_of_disappearing(store, room):
    """A silent omission would let history be edited by removal."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "deleted later"})
    store._git("rm", "-q", posted["path"])
    store._commit("delete a committed message")

    with pytest.raises(AppendOnlyViolation, match="append-only"):
        list(store.iter_messages())
    with pytest.raises(AppendOnlyViolation):
        store.read("t1", posted["message_id"])
    with pytest.raises(AppendOnlyViolation):
        store.thread_messages("t1")


def test_renamed_message_is_detected(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "moved"})
    moved = f".agent-room/messages/t1/{uuid7()}.json"
    store._git("mv", posted["path"], moved)
    store._commit("rename a committed message")

    with pytest.raises(AppendOnlyViolation):
        list(store.iter_messages())


def test_reads_come_from_the_add_commit_not_the_tip(store, room):
    """Nothing later in history can change what a message says."""
    first = room.post(thread_id="t1", type="observation", body={"text": "first"})
    room.post(thread_id="t1", type="observation", body={"text": "second"})
    assert store.read("t1", first["message_id"])["body"]["text"] == "first"


def test_verify_append_only_reports_a_clean_history(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    room.post(thread_id="t2", type="observation", body={"text": "b"})
    assert store.verify_append_only() == 2


# -- 2. writes are pinned to the room branch --------------------------------

@pytest.fixture
def repo_on_main(tmp_path):
    """A developer checkout with `main` checked out — not a room repo."""
    path = tmp_path / "devrepo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    configure_identity(path)
    (path / "README.md").write_text("unrelated project\n", encoding="utf-8")
    git(path, "add", "README.md")
    git(path, "commit", "-q", "-m", "unrelated work")
    return path


def test_store_refuses_to_commit_onto_another_branch(repo_on_main, room):
    """The strongest safety boundary: room traffic never lands on main."""
    store = GitMessageStore(repo_on_main, branch="agent-room")
    head_before = git(repo_on_main, "rev-parse", "HEAD").strip()
    branch_before = git(repo_on_main, "rev-parse", "--abbrev-ref", "HEAD").strip()

    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "must not land"}))

    with pytest.raises(WrongBranchError):
        store.append(envelope)

    assert git(repo_on_main, "rev-parse", "HEAD").strip() == head_before
    assert git(repo_on_main, "rev-parse", "--abbrev-ref", "HEAD").strip() == branch_before
    assert git(repo_on_main, "status", "--porcelain").strip() == ""
    assert not (repo_on_main / ".agent-room").exists()


def test_initialise_refuses_to_repurpose_an_unrelated_repo(repo_on_main):
    head_before = git(repo_on_main, "rev-parse", "HEAD").strip()
    with pytest.raises(WrongBranchError, match="refusing to repurpose"):
        GitMessageStore.initialise(repo_on_main, branch="agent-room")
    assert git(repo_on_main, "rev-parse", "HEAD").strip() == head_before
    assert git(repo_on_main, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"


def test_initialise_refuses_when_room_branch_exists_but_is_not_checked_out(store):
    """Never switch someone's checkout for them; refuse instead."""
    git(store.workdir, "checkout", "-q", "-b", "side")
    with pytest.raises(WrongBranchError, match="refusing to repurpose"):
        GitMessageStore.initialise(store.workdir, branch="agent-room")
    assert git(store.workdir, "rev-parse", "--abbrev-ref", "HEAD").strip() == "side"


def test_push_refuses_from_the_wrong_branch(store, room, tmp_path):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    git(store.workdir, "checkout", "-q", "-b", "side")
    store.remote = str(tmp_path / "nowhere.git")
    with pytest.raises(WrongBranchError):
        store.push()


def test_detached_head_is_refused(store, room):
    sha = git(store.workdir, "rev-parse", "HEAD").strip()
    git(store.workdir, "checkout", "-q", "--detach", sha)
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "x"}))
    with pytest.raises(WrongBranchError, match="detached"):
        store.append(envelope)


# -- 3. validation at the store trust boundary ------------------------------

def test_append_rejects_a_correctly_resealed_malformed_envelope(store, room):
    """A valid digest is not a valid message."""
    envelope = room.build_envelope(thread_id="t1", type="observation", body={"text": "x"})
    envelope["type"] = "gossip"                 # not a real type
    sealed = canonical.seal(envelope)
    canonical.verify(sealed)                    # digest is correct

    with pytest.raises(SchemaError):
        store.append(sealed)
    assert store.verify_append_only() == 0


def test_append_rejects_a_missing_required_field(store, room):
    envelope = room.build_envelope(thread_id="t1", type="observation", body={"text": "x"})
    del envelope["reply_requested"]
    with pytest.raises(SchemaError):
        store.append(canonical.seal(envelope))


def test_read_rejects_a_malformed_artifact_committed_out_of_band(store, room):
    """Another writer's library cannot smuggle a bad envelope past reads."""
    mid = uuid7()
    envelope = room.build_envelope(thread_id="t1", type="observation",
                                   body={"text": "x"}, message_id=mid)
    envelope["status"] = "validated"            # not a lifecycle state
    sealed = canonical.seal(envelope)

    path = store.workdir / store.message_path("t1", mid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(sealed), encoding="utf-8")
    store._git("add", str(path.relative_to(store.workdir)))
    store._commit("smuggled malformed message")

    with pytest.raises(SchemaError):
        store.read("t1", mid)
    with pytest.raises(SchemaError):
        list(store.iter_messages())


def test_reserved_issue5_types_remain_readable_at_the_store_layer(store, room):
    """agent_facing=False on reads: approval must stay structurally readable."""
    mid = uuid7()
    envelope = room.build_envelope(thread_id="t1", type="observation",
                                   body={"text": "x"}, message_id=mid)
    envelope["type"] = "approval"
    sealed = canonical.seal(envelope)

    path = store.workdir / store.message_path("t1", mid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(sealed), encoding="utf-8")
    store._git("add", str(path.relative_to(store.workdir)))
    store._commit("human approval record")

    assert store.read("t1", mid)["type"] == "approval"
