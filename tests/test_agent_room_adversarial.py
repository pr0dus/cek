"""Adversarial regressions derived from the independent Codex validation.

Every test here reproduces a way the store previously accepted, hid, or
mis-reported something. They are kept as the standing proof that those paths
stay closed — not as tests written around a fix.
"""

import json
import subprocess
import textwrap

import pytest

import agent_room
from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.cli import EXIT_PARTIAL_DELIVERY, main
from agent_room.errors import (
    AgentRoomError,
    PushAmbiguous,
    AppendOnlyViolation,
    ClaimStateError,
    DeliveryError,
    ForbiddenOperation,
    GitTimeout,
    SchemaError,
    UnresolvedReference,
)
from agent_room.ids import is_uuid7, uuid7
from tests.conftest_agent_room import configure_identity, git

REPO = "pr0dus/concept-evolution-kernel"
FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "repo": REPO, "commit": FULL_SHA, "path": "x.py"}


def write_raw(store, rel, text, message="out-of-band"):
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    store._git("add", "--", rel)
    return store._commit(message, rel)


def raw_commit(store, rel, text, message):
    """Commit a file with plain Git, bypassing the store's branch guards.

    Needed to build the adversarial shapes at all: the store legitimately
    refuses to write while another branch is checked out, which is exactly the
    protection under test elsewhere.
    """
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    git(store.workdir, "add", "--", rel)
    git(store.workdir, "commit", "-q", "-m", message, "--", rel)
    return git(store.workdir, "rev-parse", "HEAD").strip()


def raw_message(store, room, thread_id, text, message_id=None, **kw):
    """A valid sealed message written by plain Git onto the current branch."""
    envelope = canonical.seal(room.build_envelope(
        thread_id=thread_id, type="observation", body={"text": text},
        message_id=message_id or uuid7(), **kw))
    rel = store.message_path(thread_id, envelope["message_id"])
    raw_commit(store, rel, canonical.canonical_text(envelope), f"add {text}")
    return envelope


# ===== A. linear history and fail-closed path parsing ======================

def make_merge(store, side_work):
    """Fork a side branch, run `side_work`, and merge it back non-fast-forward."""
    base = git(store.workdir, "rev-parse", "HEAD").strip()
    git(store.workdir, "checkout", "-q", "-b", "side")
    side_work()
    git(store.workdir, "checkout", "-q", store.branch)
    git(store.workdir, "merge", "--no-ff", "-q", "-m", "merge side", "side")
    return base


def test_merge_only_rewrite_is_rejected(store, room):
    """A rewrite hidden inside a merge commit must not escape the scan."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    path = store.workdir / posted["path"]

    def rewrite():
        env = json.loads(path.read_text(encoding="utf-8"))
        env["body"] = {"text": "rewritten in a merge"}
        del env["envelope_sha256"]
        raw_commit(store, posted["path"],
                   canonical.canonical_text(canonical.seal(env)), "rewrite on side")

    make_merge(store, rewrite)
    with pytest.raises(AppendOnlyViolation, match="merge commits"):
        store.verify_store()


def test_merge_only_deletion_is_rejected(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "deleted"})

    def delete():
        git(store.workdir, "rm", "-q", posted["path"])
        git(store.workdir, "commit", "-q", "-m", "delete on side")

    make_merge(store, delete)
    with pytest.raises(AppendOnlyViolation, match="merge commits"):
        list(store.iter_messages())


def test_merge_only_addition_is_rejected(store, room):
    """A file introduced by the merge commit itself."""
    room.post(thread_id="t1", type="observation", body={"text": "base"})
    make_merge(store, lambda: raw_message(store, room, "t1", "added on side"))

    with pytest.raises(AppendOnlyViolation, match="merge commits"):
        store.verify_store()


def test_merge_history_cannot_be_pushed(tmp_path, bare_remote, store, room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    make_merge(store, lambda: raw_message(store, room, "t1", "b"))
    store.remote = str(bare_remote)

    with pytest.raises(AppendOnlyViolation):
        store.push()


@pytest.mark.parametrize("bad_name", [
    pytest.param("weird name.json", id="space-gets-git-quoted"),
    pytest.param("café.json", id="non-ascii-gets-git-quoted"),
    pytest.param("not-a-uuid.json", id="not-a-uuid"),
    pytest.param("notes.txt", id="wrong-extension"),
])
def test_malformed_message_paths_fail_closed(store, room, bad_name):
    """Git quotes such paths without -z; none may silently vanish."""
    room.post(thread_id="t1", type="observation", body={"text": "legit"})
    write_raw(store, f".agent-room/messages/t1/{bad_name}", "{}", "smuggled path")

    with pytest.raises(AppendOnlyViolation, match="canonical"):
        store.verify_store()


def test_nested_directory_under_messages_is_rejected(store, room):
    write_raw(store, ".agent-room/messages/t1/sub/dir/x.json", "{}", "nested")
    with pytest.raises(AppendOnlyViolation, match="canonical"):
        store.verify_store()


# ===== B. causality is ancestry ===========================================

def test_ancestry_predicate_rejects_siblings(store, room):
    """Unit-level: the invariant does not depend on the no-merge rule."""
    room.post(thread_id="t1", type="observation", body={"text": "base"})
    base = git(store.workdir, "rev-parse", "HEAD").strip()

    git(store.workdir, "checkout", "-q", "-b", "left")
    left = raw_commit(store, "left.txt", "l", "left branch")

    git(store.workdir, "checkout", "-q", base)
    git(store.workdir, "checkout", "-q", "-b", "right")
    right = raw_commit(store, "right.txt", "r", "right branch")

    assert store.is_strict_ancestor(base, left) is True
    assert store.is_strict_ancestor(base, right) is True
    assert store.is_strict_ancestor(left, right) is False, "siblings are not ordered"
    assert store.is_strict_ancestor(right, left) is False
    assert store.is_strict_ancestor(left, left) is False, "a commit is not its own ancestor"


def test_sibling_evidence_is_not_historically_valid(store, room):
    """The Codex sibling reproduction, via a merged (and so rejected) history."""
    evidence = room.post(thread_id="t1", type="evidence", body={"text": "e"},
                         evidence=[REPO_EVIDENCE])
    def sibling_claim():
        env = canonical.seal(room.build_envelope(
            thread_id="t1", type="claim", body={"text": "sibling claim"},
            claim={"status": "supported", "scope": f"at {FULL_SHA}",
                   "revision_condition": "a counterexample",
                   "evidence_basis": [evidence["message_id"]]}))
        raw_commit(store, store.message_path("t1", env["message_id"]),
                   canonical.canonical_text(env), "sibling claim")

    make_merge(store, sibling_claim)
    with pytest.raises(AgentRoomError):
        store.verify_store()


# ===== C. evidence must identify something inspectable =====================

def test_bare_external_evidence_is_refused(room):
    with pytest.raises(SchemaError, match="url"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "external"}])


def test_external_evidence_with_locator_is_accepted(room):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": "https://example.invalid/report"}])


@pytest.mark.parametrize("zero", ["0" * 40, "0" * 64])
def test_all_zero_object_id_is_refused(room, zero):
    with pytest.raises(SchemaError, match="all-zero"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, commit=zero)])


def test_local_object_that_is_not_a_commit_is_refused(store, room):
    """If we *do* hold the object, it must really be a commit."""
    blob = store._git("hash-object", "-w", "--stdin").stdout  # empty stdin
    blob = store._git("rev-parse", f"{store.branch}^{{tree}}").stdout.strip()
    with pytest.raises(SchemaError, match="not a commit"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, commit=blob)])


def test_foreign_commit_is_preserved_without_fabricated_verification(room):
    """A commit from a repo we do not have is a locator, not a claim of existence."""
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[dict(REPO_EVIDENCE, commit="b" * 40)])


@pytest.mark.parametrize("bad", [
    pytest.param({"kind": "run", "commit": FULL_SHA}, id="no-locator"),
    pytest.param({"kind": "run", "commit": FULL_SHA, "path": []}, id="path-array"),
    pytest.param({"kind": "run", "commit": FULL_SHA, "path": ""}, id="path-empty"),
    pytest.param({"kind": "run", "commit": FULL_SHA, "run_id": {}}, id="run-id-object"),
    pytest.param({"kind": "run", "commit": FULL_SHA, "path": "/abs/path"}, id="absolute-path"),
    pytest.param({"kind": "run", "commit": FULL_SHA, "path": "../escape"}, id="traversal"),
])
def test_malformed_run_locators_are_refused(room, bad):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"}, evidence=[bad])


def test_valid_run_locators_are_accepted(room):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "run", "commit": FULL_SHA, "run_id": "run-2026-09-22-1"}])
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "run", "commit": FULL_SHA, "path": "artifacts/report.json"}])


@pytest.mark.parametrize("bad", [
    pytest.param({"repo": REPO, "commit": FULL_SHA}, id="no-path"),
    pytest.param({"repo": "", "commit": FULL_SHA, "path": "x.py"}, id="empty-repo"),
    pytest.param({"commit": FULL_SHA, "path": "x.py"}, id="no-repo"),
    pytest.param({"repo": REPO, "commit": FULL_SHA, "path": "x.py", "lines": [0, 5]}, id="line-zero"),
    pytest.param({"repo": REPO, "commit": FULL_SHA, "path": "x.py", "lines": [9, 2]}, id="descending"),
    pytest.param({"repo": REPO, "commit": FULL_SHA, "path": "x.py", "lines": "1-5"}, id="lines-string"),
])
def test_malformed_repo_locators_are_refused(room, bad):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(bad, kind="repo")])


# ===== D. no writable approval/rejection bypass ============================

@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_low_level_append_cannot_author_reserved_types(store, room, mtype):
    """GitMessageStore.append is exported; it must not be a privileged path."""
    envelope = room.build_envelope(thread_id="t1", type="observation", body={"text": "x"})
    envelope["type"] = mtype
    with pytest.raises(ForbiddenOperation):
        store.append(canonical.seal(envelope))
    assert list(store.iter_messages()) == []


@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_reserved_types_remain_readable(store, room, mtype):
    """Issue #5 records must still parse once that path exists."""
    mid = uuid7()
    envelope = room.build_envelope(thread_id="t1", type="observation",
                                   body={"text": "x"}, message_id=mid)
    envelope["type"] = mtype
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(envelope)), "human record")
    assert store.read("t1", mid)["type"] == mtype


# ===== E. git timeouts stay in the error contract ==========================

def test_push_timeout_becomes_structured_delivery_error(tmp_path, bare_remote, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run

    def flaky(cmd, **kwargs):
        if "push" in cmd:
            raise subprocess.TimeoutExpired(cmd, 60)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", flaky)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "timed out"})

    # The timeout is wrapped as an ambiguous push; here the remote has no
    # branch at all, so non-delivery is genuinely provable.
    assert isinstance(exc.value.cause, PushAmbiguous)
    assert isinstance(exc.value.cause.cause, GitTimeout)
    assert exc.value.locally_committed is True
    assert exc.value.locally_committed_known is True
    assert exc.value.pushed is False and exc.value.pushed_known is True
    assert exc.value.message_id and exc.value.commit

    monkeypatch.undo()
    assert len(list(store.iter_messages())) == 1
    assert store.read("t1", exc.value.message_id)["body"]["text"] == "timed out"


def test_cli_push_timeout_is_reported_as_agent_room_error(tmp_path, bare_remote, monkeypatch, capsys):
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)

    real_run = subprocess.run

    def flaky(cmd, **kwargs):
        if "push" in cmd:
            raise subprocess.TimeoutExpired(cmd, 60)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", flaky)
    code = main(["--repo", str(repo), "--participant", "claude-code",
                 "--remote", str(bare_remote),
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}'])
    out = capsys.readouterr()
    assert code == EXIT_PARTIAL_DELIVERY
    payload = json.loads(out.out)
    assert payload["locally_committed"] is True and payload["pushed"] is False
    assert payload["message_id"] and payload["commit"]
    assert "TimeoutExpired" not in out.err, "raw subprocess error must not leak"


def test_git_timeout_is_an_agent_room_error(store, monkeypatch):
    monkeypatch.setattr(
        agent_room.gitstore.subprocess, "run",
        lambda cmd, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd, 60)))
    with pytest.raises(GitTimeout):
        store._git("status", "--porcelain")


# ===== F. delivery reports the surviving commit, even when the store is bad =

def test_delivery_error_commit_survives_corrupt_store(tmp_path, bare_remote):
    """current_add_commit must not fall back merely because verify_store fails."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    room = AgentRoom(store, "claude-code", None)
    posted = room.post(thread_id="t1", type="observation", body={"text": "good"})

    # Corrupt an unrelated part of the store, then confirm the exact-path
    # lookup still reports this message's real add commit.
    mid = uuid7()
    bad = room.build_envelope(thread_id="t1", type="observation",
                              body={"text": "bad"}, message_id=mid)
    bad["status"] = "validated"
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(bad)), "corrupt artifact")

    with pytest.raises(SchemaError):
        store.verify_store()
    assert store.current_add_commit(posted["path"]) == posted["commit"]


# ===== G. one canonical UUID spelling ======================================

@pytest.mark.parametrize("spelling", [
    lambda u: u.replace("-", ""),
    lambda u: u.upper(),
    lambda u: "{" + u + "}",
    lambda u: "urn:uuid:" + u,
])
def test_equivalent_uuid_spellings_are_refused(room, spelling):
    """uuid.UUID() accepts these; the room must not, or ids stop being unique."""
    mid = spelling(uuid7())
    assert not is_uuid7(mid)
    with pytest.raises(SchemaError, match="UUIDv7"):
        room.post(thread_id="t1", type="observation", body={"text": "x"}, message_id=mid)


def test_alternative_spelling_cannot_duplicate_an_existing_message(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "first"})
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "second"},
                  message_id=posted["message_id"].upper())


def test_parent_id_spelling_is_also_canonical(room):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    with pytest.raises(SchemaError, match="UUIDv7"):
        room.post(thread_id="t1", type="answer", body={"text": "!"},
                  parent_id=root["message_id"].replace("-", ""))


# ===== H. strict JSON and nested shapes ====================================

def test_duplicate_json_keys_in_a_stored_artifact_are_rejected(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    raw = (store.workdir / posted["path"]).read_text(encoding="utf-8")
    doubled = raw[:-1] + ',"type":"approval"}'
    mid = uuid7()
    write_raw(store, store.message_path("t1", mid), doubled, "duplicate keys")

    with pytest.raises(SchemaError, match="duplicate JSON key"):
        store.verify_store()


def test_cli_rejects_duplicate_keys_in_json_arguments(store, room, capsys):
    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "a", "text": "b"}'])
    assert code == 2
    assert "duplicate JSON key" in capsys.readouterr().err


@pytest.mark.parametrize("sender", [
    pytest.param({"model": {"nested": "object"}}, id="nested-object"),
    pytest.param({"operator": ["a", "b"]}, id="array"),
])
def test_malformed_sender_metadata_is_refused(room, sender):
    with pytest.raises(SchemaError, match="scalar"):
        room.post(thread_id="t1", type="observation", body={"text": "x"}, sender=sender)


@pytest.mark.parametrize("recipient", [
    pytest.param({"broadcast": "true"}, id="truthy-string-broadcast"),
    pytest.param({"broadcast": 1}, id="numeric-broadcast"),
    pytest.param({"agent": ""}, id="empty-agent"),
    pytest.param({"agent": []}, id="array-agent"),
    pytest.param({"broadcast": False}, id="broadcast-false-without-agent"),
])
def test_malformed_recipient_is_refused(room, recipient):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  recipient=recipient)


def test_envelope_addressed_to_nobody_is_refused(room):
    """An empty recipient object reaching validation directly."""
    from agent_room.schema import validate_envelope

    envelope = room.build_envelope(thread_id="t1", type="observation", body={"text": "x"})
    envelope["recipient"] = {}
    with pytest.raises(SchemaError, match="broadcast"):
        validate_envelope(envelope)


def test_valid_recipients_are_accepted(room):
    room.post(thread_id="t1", type="observation", body={"text": "x"},
              recipient={"broadcast": True})
    room.post(thread_id="t1", type="observation", body={"text": "x"},
              recipient={"agent": "openai-research"})


@pytest.mark.parametrize("project", [
    pytest.param({"repo": []}, id="array-repo"),
    pytest.param({"repo": ""}, id="empty-repo"),
    pytest.param({"commit": "abc"}, id="short-commit"),
    pytest.param({"commit": "0" * 40}, id="null-commit"),
])
def test_malformed_project_is_refused(room, project):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  project=project)


# ===== I. a local append may not extend corrupt history ====================

def test_local_only_append_refuses_corrupt_history(store, room):
    """No remote configured is not a licence to build on a bad artifact."""
    mid = uuid7()
    bad = room.build_envelope(thread_id="t1", type="observation",
                              body={"text": "bad"}, message_id=mid)
    bad["status"] = "validated"
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(bad)), "corrupt artifact")

    assert store.remote is None
    before = store._git("rev-parse", "HEAD").stdout.strip()
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "innocent"})
    assert store._git("rev-parse", "HEAD").stdout.strip() == before


def test_local_only_append_refuses_merge_history(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    make_merge(store, lambda: raw_message(store, room, "t1", "b"))
    with pytest.raises(AppendOnlyViolation):
        room.post(thread_id="t1", type="observation", body={"text": "c"})


# ===== J. CLI reply parity =================================================

def test_cli_reply_can_express_a_decision_request(store, room, capsys):
    root = room.post(thread_id="t1", type="question", body={"text": "which provider?"})
    argv = ["--repo", str(store.workdir), "--participant", "claude-code",
            "reply", "--parent-id", root["message_id"],
            "--type", "decision_request", "--body", '{"text": "needs a human"}',
            "--human-approval-required"]
    assert main(argv) == 0
    result = json.loads(capsys.readouterr().out)

    stored = store.read("t1", result["message_id"])
    assert stored["type"] == "decision_request"
    assert stored["human_approval_required"] is True
    assert stored["parent_id"] == root["message_id"]


def test_cli_reply_without_the_flag_still_refuses_decision_request(store, room, capsys):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "reply", "--parent-id", root["message_id"],
                 "--type", "decision_request", "--body", '{"text": "x"}'])
    assert code == 2
    assert "human_approval_required" in capsys.readouterr().err


def test_cli_reply_supports_reply_requested(store, room, capsys):
    root = room.post(thread_id="t1", type="question", body={"text": "?"})
    argv = ["--repo", str(store.workdir), "--participant", "claude-code",
            "reply", "--parent-id", root["message_id"],
            "--type", "answer", "--body", '{"text": "and you?"}', "--reply-requested"]
    assert main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert store.read("t1", result["message_id"])["reply_requested"] is True
