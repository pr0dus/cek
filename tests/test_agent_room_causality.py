"""Identity binding, historical causality, delivery gating and partial failure.

The final round of store invariants. Each one protects a property that only
matters once real participants write to a shared branch: that a message means
what its path says, that it could only rely on what already existed, that a
writer never extends corrupt remote history, and that a failed delivery is
distinguishable from nothing having happened.
"""

import json

import pytest

from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.errors import (
    AppendOnlyViolation,
    DeliveryError,
    PushRaceError,
    SchemaError,
    UnresolvedReference,
)
from agent_room.ids import uuid7
from tests.conftest_agent_room import configure_identity, git

FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "repo": "pr0dus/concept-evolution-kernel",
                  "commit": FULL_SHA, "path": "newi_arc/metrics.py"}


def commit_at(store, rel, envelope, message="out-of-band artifact"):
    """Commit a sealed envelope at an arbitrary path, bypassing append()."""
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(envelope), encoding="utf-8")
    store._git("add", "--", rel)
    return store._commit(message, rel)


# -- 1. the committed path and the sealed envelope must agree ---------------

def test_filename_id_must_match_envelope_message_id(store, room):
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "x"}, message_id=uuid7()))
    other_id = uuid7()
    commit_at(store, f".agent-room/messages/t1/{other_id}.json", envelope)

    with pytest.raises(SchemaError, match="message id"):
        store.read("t1", other_id)
    with pytest.raises(SchemaError, match="message id"):
        list(store.iter_messages())


def test_path_thread_must_match_envelope_thread_id(store, room):
    mid = uuid7()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t2", type="observation", body={"text": "x"}, message_id=mid))
    commit_at(store, f".agent-room/messages/t1/{mid}.json", envelope)

    with pytest.raises(SchemaError, match="thread"):
        store.read("t1", mid)
    with pytest.raises(SchemaError, match="thread"):
        store.verify_store()


def test_mismatch_is_rejected_before_reference_resolution(store, room):
    """A misfiled artifact must not be usable as anyone's parent or evidence."""
    real = room.post(thread_id="t1", type="evidence", body={"text": "grounded"},
                     evidence=[REPO_EVIDENCE])
    impostor_id = uuid7()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="evidence", body={"text": "impostor"},
        message_id=uuid7(), evidence=[REPO_EVIDENCE]))
    commit_at(store, f".agent-room/messages/t1/{impostor_id}.json", envelope)

    # resolve_message must not hand back a body claiming another identity.
    with pytest.raises(SchemaError):
        store.resolve_message(impostor_id)
    assert real["message_id"] != impostor_id


# -- 2. references must have existed when the message was committed ---------

def test_child_committed_before_its_parent_is_rejected(store, room):
    """Out-of-band forward reference: parent added afterwards."""
    future_parent = uuid7()
    child = canonical.seal(room.build_envelope(
        thread_id="t1", type="answer", body={"text": "child first"},
        parent_id=future_parent))
    commit_at(store, store.message_path("t1", child["message_id"]), child)

    parent = canonical.seal(room.build_envelope(
        thread_id="t1", type="question", body={"text": "parent later"},
        message_id=future_parent))
    commit_at(store, store.message_path("t1", future_parent), parent)

    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.read("t1", child["message_id"])
    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.verify_store()


def test_supported_claim_committed_before_its_evidence_is_rejected(store, room):
    """A claim must not become retrospectively supported."""
    future_evidence = uuid7()
    claim = canonical.seal(room.build_envelope(
        thread_id="t1", type="claim", body={"text": "premature"},
        claim={"status": "supported", "scope": f"at commit {FULL_SHA}",
               "revision_condition": "a counterexample",
               "evidence_basis": [future_evidence]}))
    commit_at(store, store.message_path("t1", claim["message_id"]), claim)

    evidence = canonical.seal(room.build_envelope(
        thread_id="t1", type="evidence", body={"text": "arrives later"},
        message_id=future_evidence, evidence=[REPO_EVIDENCE]))
    commit_at(store, store.message_path("t1", future_evidence), evidence)

    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.read("t1", claim["message_id"])


def test_self_parent_is_rejected(store, room):
    mid = uuid7()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="answer", body={"text": "its own parent"},
        message_id=mid, parent_id=mid))
    commit_at(store, store.message_path("t1", mid), envelope)

    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.read("t1", mid)


def test_self_evidence_basis_is_rejected(store, room):
    mid = uuid7()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="claim", body={"text": "cites itself"},
        message_id=mid, evidence=[REPO_EVIDENCE],
        claim={"status": "supported", "scope": f"at commit {FULL_SHA}",
               "revision_condition": "a counterexample", "evidence_basis": [mid]}))
    commit_at(store, store.message_path("t1", mid), envelope)

    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.read("t1", mid)


def test_same_commit_reference_is_ambiguous_and_rejected(store, room):
    """Two messages added in one commit cannot order themselves."""
    parent_id, child_id = uuid7(), uuid7()
    parent = canonical.seal(room.build_envelope(
        thread_id="t1", type="question", body={"text": "p"}, message_id=parent_id))
    child = canonical.seal(room.build_envelope(
        thread_id="t1", type="answer", body={"text": "c"},
        message_id=child_id, parent_id=parent_id))

    for env, mid in ((parent, parent_id), (child, child_id)):
        rel = store.message_path("t1", mid)
        target = store.workdir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(canonical.canonical_text(env), encoding="utf-8")
        store._git("add", "--", rel)
    store._commit("both messages in one commit")

    with pytest.raises(UnresolvedReference, match="historically valid"):
        store.verify_store()


def test_normal_ordering_still_reads(room):
    """The ordinary case is unaffected: parent first, then child."""
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    room.reply(root["message_id"], type="answer", body={"text": "!"})
    assert len(room.thread("t1")) == 2


def test_in_message_evidence_ids_are_unaffected_by_causality(room):
    """An id inside the same envelope needs no earlier commit."""
    posted = room.post(
        thread_id="t1", type="claim", body={"text": "c"},
        evidence=[dict(REPO_EVIDENCE, id="e1")],
        claim={"status": "supported", "scope": f"at commit {FULL_SHA}",
               "revision_condition": "a counterexample", "evidence_basis": ["e1"]},
    )
    assert room.get("t1", posted["message_id"])["claim"]["status"] == "supported"


# -- 3. delivery is gated on full-store verification ------------------------

def test_verify_store_walks_every_message(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    room.post(thread_id="t2", type="observation", body={"text": "b"})
    assert store.verify_store() == 2


def test_verify_store_catches_what_append_only_alone_misses(store, room):
    """Append-only is clean; the artifact is still invalid."""
    mid = uuid7()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "x"}, message_id=mid))
    envelope = dict(envelope)
    del envelope["envelope_sha256"]
    envelope["status"] = "validated"                   # not a lifecycle state
    commit_at(store, store.message_path("t1", mid), canonical.seal(envelope))

    assert store.verify_append_only() == 1             # history itself is fine
    with pytest.raises(SchemaError):
        store.verify_store()


def test_writer_refuses_to_push_on_top_of_corrupt_remote_history(tmp_path, bare_remote):
    """A poisoned remote must not be extended, even though it is append-only."""
    # Participant A publishes a structurally invalid but append-only artifact.
    first = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(first.workdir)
    first.remote = str(bare_remote)
    room_a = AgentRoom(first, "claude-code", None)
    room_a.post(thread_id="t1", type="observation", body={"text": "legitimate"})

    mid = uuid7()
    bad = room_a.build_envelope(thread_id="t1", type="observation",
                                body={"text": "bad"}, message_id=mid)
    bad["status"] = "validated"
    commit_at(first, first.message_path("t1", mid), canonical.seal(bad))
    git(first.workdir, "push", str(bare_remote), "agent-room:agent-room")

    # Participant B cloned before that, writes its own message, and on push
    # must fetch/rebase - and then refuse.
    path_b = tmp_path / "b"
    git(tmp_path, "clone", "-q", str(bare_remote), str(path_b))
    configure_identity(path_b)
    git(path_b, "checkout", "-q", "agent-room")
    git(path_b, "reset", "-q", "--hard", "HEAD~1")     # before the bad commit
    second = GitMessageStore(path_b, branch="agent-room", remote=str(bare_remote))
    room_b = AgentRoom(second, "openai-research", None)

    with pytest.raises((SchemaError, DeliveryError)) as exc:
        room_b.post(thread_id="t1", type="observation", body={"text": "mine"})
    if isinstance(exc.value, DeliveryError):
        assert isinstance(exc.value.cause, SchemaError)
        # Delivery failed *after* a successful rebase, so the reported commit
        # must be the post-rebase SHA that actually holds the message.
        assert exc.value.commit == second.current_add_commit(exc.value.path)
        assert second._git("cat-file", "-e", exc.value.commit).returncode == 0


def test_cli_verify_uses_the_full_gate(store, room, capsys):
    from agent_room.cli import main

    room.post(thread_id="t1", type="observation", body={"text": "a"})
    code = main(["--repo", str(store.workdir), "--participant", "claude-code", "verify"])
    assert code == 0
    assert json.loads(capsys.readouterr().out) == {"verified": 1}


# -- 4. partial delivery failure is explicit --------------------------------

@pytest.fixture
def rejecting_remote(bare_remote):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    return bare_remote


def test_failed_delivery_reports_what_was_committed(tmp_path, rejecting_remote):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(rejecting_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "held"})

    err = exc.value
    assert err.locally_committed is True and err.pushed is False
    assert err.message_id and err.commit and err.path
    assert isinstance(err.cause, PushRaceError)
    assert err.as_result()["status"] == "created"

    # exactly one message, and it is the one the error names
    messages = list(store.iter_messages())
    assert len(messages) == 1
    assert messages[0]["message_id"] == err.message_id
    assert store.read("t1", err.message_id)["body"]["text"] == "held"


def test_retrying_delivery_does_not_create_a_second_message(tmp_path, rejecting_remote):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(rejecting_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "held"})
    first_id = exc.value.message_id

    # Retrying delivery - not reposting - is the correct recovery.
    with pytest.raises(PushRaceError):
        store.push()
    assert len(list(store.iter_messages())) == 1

    (rejecting_remote / "hooks" / "pre-receive").unlink()
    assert store.push()["pushed"] is True

    messages = list(store.iter_messages())
    assert len(messages) == 1 and messages[0]["message_id"] == first_id


def test_successful_post_reports_delivery_state(tmp_path, bare_remote):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    result = room.post(thread_id="t1", type="observation", body={"text": "ok"})
    assert result["locally_committed"] is True
    assert result["pushed"] is True


def test_local_only_post_reports_not_pushed(room):
    result = room.post(thread_id="t1", type="observation", body={"text": "local"})
    assert result["locally_committed"] is True
    assert result["pushed"] is False
    assert "push" not in result
