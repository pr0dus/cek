"""Store-level integrity: readable references, global ids, clean commits, locking.

These cover the second round of supervisor blockers. Each is a way the store
could accept or emit history that looks valid but is not: a claim that cannot
be read back, an id that resolves two ways, a staged rewrite riding along in
someone else's commit, or two processes trampling one index.
"""

import json
import os
import subprocess
import sys
import textwrap

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.errors import (
    ConflictError,
    DirtyCheckoutError,
    LockTimeout,
    SchemaError,
    UnresolvedReference,
    WrongBranchError,
)
from agent_room.ids import uuid7
from tests.conftest_agent_room import configure_identity, git

FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "commit": FULL_SHA, "path": "newi_arc/metrics.py"}


def _commit_out_of_band(store, envelope):
    """Commit a sealed artifact directly, bypassing append()'s validation."""
    rel = store.message_path(envelope["thread_id"], envelope["message_id"])
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(envelope), encoding="utf-8")
    store._git("add", "--", rel)
    store._commit("out-of-band artifact", rel)
    return rel


# -- 1. valid cross-message references must stay readable -------------------

@pytest.fixture
def supported_claim(room):
    """A `supported` claim whose evidence basis is another message."""
    grounded = room.post(
        thread_id="t1", type="evidence",
        body={"text": "closure admits only active dependents"},
        evidence=[REPO_EVIDENCE],
    )
    claim = room.post(
        thread_id="t1", type="claim", body={"text": "the invariant holds"},
        claim={
            "status": "supported",
            "scope": f"at commit {FULL_SHA}",
            "revision_condition": "a counterexample in the same scope",
            "evidence_basis": [grounded["message_id"]],
        },
    )
    return grounded, claim


def test_cross_message_supported_claim_is_readable_via_get(room, supported_claim):
    _, claim = supported_claim
    loaded = room.get("t1", claim["message_id"])
    assert loaded["claim"]["status"] == "supported"


def test_cross_message_supported_claim_is_readable_via_thread(room, supported_claim):
    assert len(room.thread("t1")) == 2


def test_cross_message_supported_claim_is_readable_via_iter(room, store, supported_claim):
    assert len(list(store.iter_messages())) == 2


def test_cross_message_supported_claim_survives_restart(store, supported_claim):
    """A fresh store object - and a fresh process - can still read it."""
    _, claim = supported_claim
    reopened = GitMessageStore(store.workdir, branch="agent-room")
    assert reopened.read("t1", claim["message_id"])["claim"]["status"] == "supported"

    script = textwrap.dedent(f"""
        import sys, json
        sys.path.insert(0, {os.getcwd()!r})
        from agent_room import GitMessageStore
        s = GitMessageStore({str(store.workdir)!r}, branch='agent-room')
        print(json.dumps([m['type'] for m in s.iter_messages()]))
    """)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == ["evidence", "claim"]


def test_reference_resolution_does_not_recurse_without_bound(room):
    """A chain of claims, each citing the last, must still read."""
    previous = room.post(thread_id="t1", type="evidence", body={"text": "base"},
                         evidence=[REPO_EVIDENCE])["message_id"]
    for i in range(6):
        previous = room.post(
            thread_id="t1", type="claim", body={"text": f"link {i}"},
            evidence=[REPO_EVIDENCE],
            claim={
                "status": "supported", "scope": f"at commit {FULL_SHA}",
                "revision_condition": "a counterexample",
                "evidence_basis": [previous],
            },
        )["message_id"]
    assert len(room.thread("t1")) == 7


def test_out_of_band_orphan_parent_fails_on_read(store, room):
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="answer", body={"text": "x"}, parent_id=uuid7()))
    _commit_out_of_band(store, envelope)

    with pytest.raises(UnresolvedReference):
        store.read("t1", envelope["message_id"])
    with pytest.raises(UnresolvedReference):
        list(store.iter_messages())


def test_out_of_band_cross_thread_parent_fails_on_read(store, room):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    envelope = canonical.seal(room.build_envelope(
        thread_id="t2", type="answer", body={"text": "!"}, parent_id=root["message_id"]))
    _commit_out_of_band(store, envelope)

    with pytest.raises(SchemaError, match="may not cross threads"):
        store.read("t2", envelope["message_id"])


def test_out_of_band_unresolvable_evidence_basis_fails_on_read(store, room):
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="claim", body={"text": "c"},
        claim={"status": "supported", "scope": "s",
               "revision_condition": "r", "evidence_basis": [uuid7()]}))
    _commit_out_of_band(store, envelope)

    with pytest.raises(UnresolvedReference):
        list(store.iter_messages())


# -- 2. message_id is globally unique ---------------------------------------

def test_same_id_under_a_different_thread_is_refused(store, room):
    mid = uuid7()
    room.post(thread_id="t1", type="observation", body={"text": "first"}, message_id=mid)

    second = canonical.seal(room.build_envelope(
        thread_id="t2", type="observation", body={"text": "second"}, message_id=mid))
    with pytest.raises(ConflictError, match="unique room-wide"):
        store.append(second)

    assert len(list(store.iter_messages())) == 1


def test_duplicate_id_committed_out_of_band_is_detected(store, room):
    mid = uuid7()
    room.post(thread_id="t1", type="observation", body={"text": "first"}, message_id=mid)
    envelope = canonical.seal(room.build_envelope(
        thread_id="t2", type="observation", body={"text": "second"}, message_id=mid))
    _commit_out_of_band(store, envelope)

    with pytest.raises(ConflictError, match="more than one path"):
        list(store.iter_messages())


def test_resolve_message_is_unambiguous(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert room.find(posted["message_id"])["thread_id"] == "t1"


# -- 3. a dirty checkout cannot smuggle changes into a message commit -------

def test_staged_rewrite_cannot_hitchhike_on_a_new_post(store, room):
    victim = room.post(thread_id="t1", type="observation", body={"text": "original"})

    # Stage a rewrite of the already-committed message, resealed so its digest
    # is internally valid.
    path = store.workdir / victim["path"]
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["body"] = {"text": "rewritten"}
    del envelope["envelope_sha256"]
    path.write_text(canonical.canonical_text(canonical.seal(envelope)), encoding="utf-8")
    store._git("add", "--", victim["path"])

    head_before = store._git("rev-parse", "HEAD").stdout.strip()
    with pytest.raises(DirtyCheckoutError):
        room.post(thread_id="t1", type="observation", body={"text": "innocent"})
    assert store._git("rev-parse", "HEAD").stdout.strip() == head_before
    assert store.read("t1", victim["message_id"])["body"]["text"] == "original"


def test_unrelated_staged_file_blocks_append(store, room):
    (store.workdir / "stray.txt").write_text("unrelated\n", encoding="utf-8")
    store._git("add", "--", "stray.txt")
    with pytest.raises(DirtyCheckoutError):
        room.post(thread_id="t1", type="observation", body={"text": "x"})


def test_untracked_file_blocks_append(store, room):
    (store.workdir / "stray.txt").write_text("unrelated\n", encoding="utf-8")
    with pytest.raises(DirtyCheckoutError):
        room.post(thread_id="t1", type="observation", body={"text": "x"})


def test_violated_history_is_never_pushed(tmp_path, bare_remote, room):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    local = AgentRoom(store, "claude-code", None)
    posted = local.post(thread_id="t1", type="observation", body={"text": "original"})

    # Rewrite it in a later commit, then try to push that history.
    path = store.workdir / posted["path"]
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["body"] = {"text": "rewritten"}
    del envelope["envelope_sha256"]
    path.write_text(canonical.canonical_text(canonical.seal(envelope)), encoding="utf-8")
    store._git("add", "--", posted["path"])
    store._commit("rewrite", posted["path"])

    store.remote = str(bare_remote)
    from agent_room.errors import AppendOnlyViolation
    with pytest.raises(AppendOnlyViolation):
        store.push()
    assert git(bare_remote, "branch", "--list").strip() == ""


# -- 4. single-writer lock --------------------------------------------------

def test_two_processes_cannot_mutate_one_checkout_concurrently(store, room, tmp_path):
    """The second process must fail fast, not corrupt the shared index."""
    holder = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {os.getcwd()!r})
        from agent_room import GitMessageStore
        s = GitMessageStore({str(store.workdir)!r}, branch='agent-room')
        with s.writer_lock():
            print('locked', flush=True)
            time.sleep(4)
    """)
    proc = subprocess.Popen([sys.executable, "-c", holder], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        store.lock_timeout = 0.5
        with pytest.raises(LockTimeout, match="writer lock"):
            room.post(thread_id="t1", type="observation", body={"text": "blocked"})
    finally:
        proc.kill()
        proc.wait(timeout=10)

    store.lock_timeout = 10.0
    assert room.post(thread_id="t1", type="observation", body={"text": "after"})["status"] == "created"


def test_writer_lock_is_released_after_use(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    room.post(thread_id="t1", type="observation", body={"text": "two"})
    assert len(room.thread("t1")) == 2


def test_lock_wait_is_bounded(store):
    with pytest.raises(ValueError):
        GitMessageStore(store.workdir, lock_timeout=-1)


def test_concurrent_acknowledgements_are_not_lost(store, tmp_path):
    """Two processes acking different messages must both survive."""
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "c", "claude-code"))
    first = claude.post(thread_id="t1", type="observation", body={"text": "one"})
    second = claude.post(thread_id="t1", type="observation", body={"text": "two"})

    state_dir = tmp_path / "shared"
    reader_a = AgentRoom(store, "openai-research", ParticipantCursor(state_dir, "openai-research"))
    reader_b = AgentRoom(store, "openai-research", ParticipantCursor(state_dir, "openai-research"))

    # Both loaded the same (empty) state before either wrote.
    reader_a.acknowledge(first["message_id"])
    reader_b.acknowledge(second["message_id"])

    fresh = ParticipantCursor(state_dir, "openai-research")
    assert fresh.acknowledged_ids() == {first["message_id"], second["message_id"]}


def test_cross_process_acknowledgements_are_not_lost(store, tmp_path):
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "c", "claude-code"))
    ids = [claude.post(thread_id="t1", type="observation", body={"text": str(i)})["message_id"]
           for i in range(4)]
    state_dir = tmp_path / "shared"

    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {os.getcwd()!r})
        from agent_room import ParticipantCursor
        c = ParticipantCursor({str(state_dir)!r}, 'openai-research')
        c.acknowledge(sys.argv[1], at='2026-09-22T10:00:00Z')
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script, mid]) for mid in ids]
    for p in procs:
        assert p.wait(timeout=60) == 0

    assert ParticipantCursor(state_dir, "openai-research").acknowledged_ids() == set(ids)


# -- 5. initialise never repurposes an existing repo ------------------------

def test_initialise_refuses_an_unborn_repo_with_untracked_files(tmp_path):
    """`.git` exists, HEAD has no commits, files are untracked — still refuse."""
    path = tmp_path / "unborn"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    (path / "notes.txt").write_text("someone's work\n", encoding="utf-8")
    before = (path / "notes.txt").read_bytes()
    branch_before = git(path, "symbolic-ref", "--short", "HEAD").strip()

    with pytest.raises(WrongBranchError, match="pre-existing git repository"):
        GitMessageStore.initialise(path, branch="agent-room")

    assert git(path, "symbolic-ref", "--short", "HEAD").strip() == branch_before
    assert (path / "notes.txt").read_bytes() == before
    assert git(path, "status", "--porcelain").strip() == "?? notes.txt"
    assert not (path / ".agent-room").exists()


def test_initialise_refuses_a_non_empty_directory(tmp_path):
    path = tmp_path / "occupied"
    path.mkdir()
    (path / "project.py").write_text("print('hi')\n", encoding="utf-8")
    with pytest.raises(WrongBranchError, match="not empty"):
        GitMessageStore.initialise(path, branch="agent-room")
    assert (path / "project.py").exists()
    assert not (path / ".git").exists()


def test_initialise_accepts_a_fresh_directory(tmp_path):
    store = GitMessageStore.initialise(tmp_path / "fresh", branch="agent-room")
    assert store.current_branch() == "agent-room"


def test_initialise_is_idempotent_on_its_own_repo(store):
    again = GitMessageStore.initialise(store.workdir, branch="agent-room")
    assert again.current_branch() == "agent-room"


# -- 6. safe identifiers ----------------------------------------------------

@pytest.mark.parametrize("thread_id", [
    pytest.param("with space", id="space"),
    pytest.param("with\ttab", id="tab"),
    pytest.param("with\nnewline", id="newline"),
    pytest.param("with\x00null", id="null"),
    pytest.param("a/b", id="separator"),
    pytest.param("..", id="parent-dir"),
    pytest.param(".hidden", id="leading-dot"),
    pytest.param("-leading-dash", id="leading-dash"),
    pytest.param("café", id="non-ascii"),
    pytest.param("x" * 65, id="too-long"),
    pytest.param("", id="empty"),
])
def test_unsafe_thread_ids_are_refused(room, thread_id):
    with pytest.raises(SchemaError, match="thread_id"):
        room.post(thread_id=thread_id, type="observation", body={"text": "x"})


@pytest.mark.parametrize("thread_id", ["t1", "th-2026-09-22", "a_b.c-1", "x" * 64, "A1"])
def test_safe_thread_ids_are_accepted(room, thread_id):
    assert room.post(thread_id=thread_id, type="observation", body={"text": "x"})["status"] == "created"


def test_duplicate_evidence_ids_are_refused(room):
    """Otherwise admissibility would depend on list order."""
    with pytest.raises(SchemaError, match="duplicated"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            evidence=[
                {"id": "e1", "kind": "agent_output", "note": "opinion"},
                dict(REPO_EVIDENCE, id="e1"),
            ],
            claim={"status": "supported", "scope": "s",
                   "revision_condition": "r", "evidence_basis": ["e1"]},
        )


def test_distinct_evidence_ids_are_fine(room):
    room.post(
        thread_id="t1", type="claim", body={"text": "c"},
        evidence=[
            {"id": "e1", "kind": "agent_output", "note": "opinion"},
            dict(REPO_EVIDENCE, id="e2"),
        ],
        claim={"status": "supported", "scope": "s",
               "revision_condition": "r", "evidence_basis": ["e2"]},
    )
