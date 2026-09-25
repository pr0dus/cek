"""Fourth-round Codex regressions: Git namespace, object integrity, receipts.

Sections Z-AJ. These attack the layer below the envelope: the Git directory
that history is read from, the object database that blobs come out of, and the
process results the store treats as receipts.
"""

import json
import os
import subprocess
import zlib

import pytest

import agent_room
from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.cli import EXIT_PARTIAL_DELIVERY, main
from agent_room.errors import (
    AgentRoomError,
    AppendOnlyViolation,
    DeliveryError,
    HistoryUnavailable,
    PushAmbiguous,
    SchemaError,
)
from agent_room.ids import uuid7
from tests.conftest_agent_room import configure_identity, git

REPO = "pr0dus/concept-evolution-kernel"
FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "repo": REPO, "commit": FULL_SHA, "path": "x.py"}


def loose_object_path(store, oid):
    return store._git_common_dir() / "objects" / oid[:2] / oid[2:]


def resealed_rewrite(store, posted, text="rewritten"):
    envelope = json.loads((store.workdir / posted["path"]).read_text(encoding="utf-8"))
    envelope["body"] = {"text": text}
    del envelope["envelope_sha256"]
    (store.workdir / posted["path"]).write_text(
        canonical.canonical_text(canonical.seal(envelope)), encoding="utf-8")
    git(store.workdir, "add", "--", posted["path"])
    git(store.workdir, "commit", "-q", "-m", "resealed rewrite")


def flaky_git(monkeypatch, predicate, error=None):
    real_run = subprocess.run

    def run(cmd, **kwargs):
        if predicate(cmd):
            raise (error or subprocess.TimeoutExpired(cmd, 60))
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)


# ===== Z. linked worktrees / common git dir ================================

def test_common_dir_graft_in_a_linked_worktree_is_rejected(tmp_path, store, room):
    """The exact reproduction: graft lives in the COMMON dir, not the worktree."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    base = git(store.workdir, "rev-parse", "HEAD").strip()
    resealed_rewrite(store, posted)
    tip = git(store.workdir, "rev-parse", "HEAD").strip()

    linked = tmp_path / "linked"
    git(store.workdir, "worktree", "add", "-q", "--detach", str(linked), tip)
    configure_identity(linked)
    git(linked, "checkout", "-q", "-B", "agent-room", tip)
    worktree_store = GitMessageStore(linked, branch="agent-room")

    # A linked worktree's own git dir differs from the common dir.
    assert worktree_store._git_dir() != worktree_store._git_common_dir()

    grafts = worktree_store._git_common_dir() / "info" / "grafts"
    grafts.parent.mkdir(parents=True, exist_ok=True)
    grafts.write_text(f"{tip} {base}\n", encoding="utf-8")

    with pytest.raises(HistoryUnavailable, match="graft"):
        worktree_store.verify_store()


def test_common_dir_is_resolved_absolutely(store):
    common = store._git_common_dir()
    assert common.is_absolute() and common.exists()


# ===== AA. fully-qualified branch refs =====================================

def test_local_tag_cannot_shadow_a_missing_branch(store, room, tmp_path):
    """A same-name tag must not let a missing branch appear to verify."""
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    tip = git(store.workdir, "rev-parse", "HEAD").strip()

    other = GitMessageStore(store.workdir, branch="ghost")
    git(store.workdir, "tag", "ghost", tip)

    assert other.ref == "refs/heads/ghost"
    with pytest.raises(HistoryUnavailable, match="does not exist"):
        other.verify_store()


def test_remote_tag_does_not_prove_branch_delivery(tmp_path, bare_remote, store, room):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    tip = git(store.workdir, "rev-parse", "HEAD").strip()
    # Publish only a TAG of the same name on the remote, never the branch.
    git(store.workdir, "tag", "-f", "agent-room", tip)
    git(store.workdir, "push", "-q", str(bare_remote), "refs/tags/agent-room")

    store.remote = str(bare_remote)
    pushed, known, _ = store._reconcile_push(tip)
    assert pushed is False and known is True, "a tag is not the branch"


def test_ref_is_fully_qualified_everywhere(store):
    assert store.ref == "refs/heads/agent-room"


# ===== AB. object corruption is not 'missing' ==============================

def test_corrupt_loose_object_raises_instead_of_reporting_absent(store, room):
    """A damaged object database must never read as foreign evidence."""
    head = git(store.workdir, "rev-parse", "HEAD").strip()
    path = loose_object_path(store, head)
    assert path.exists(), "expected a loose object in a fresh repo"
    path.chmod(0o644)          # git writes loose objects read-only
    path.write_bytes(b"this is not a valid zlib stream")

    with pytest.raises(AgentRoomError):
        store.commit_object_state(head)


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions")
def test_permission_denied_object_raises(store, room):
    head = git(store.workdir, "rev-parse", "HEAD").strip()
    path = loose_object_path(store, head)
    original = path.stat().st_mode
    path.chmod(0o000)
    try:
        with pytest.raises(AgentRoomError):
            store.commit_object_state(head)
    finally:
        path.chmod(original)


def test_clean_missing_object_is_still_absent(store):
    assert store.commit_object_state("f" * 40) == "absent"


# ===== AC. nonzero push results are ambiguous too ==========================

def test_accepted_push_with_substituted_failure_is_not_reported_false(
        tmp_path, bare_remote, monkeypatch):
    """The remote really takes it; the client is handed a nonzero result."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run
    state = {"done": False}

    def run(cmd, **kwargs):
        if "push" in cmd and not state["done"]:
            state["done"] = True
            real = real_run(cmd, **kwargs)          # genuinely accepted
            assert real.returncode == 0
            return subprocess.CompletedProcess(cmd, 1, real.stdout, "fatal: broken pipe")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    result = room.post(thread_id="t1", type="observation", body={"text": "landed"})

    assert result["pushed"] is not False, "delivery was never disproven"
    assert result["pushed"] is True and result["pushed_known"] is True
    assert result["push"].get("reconciled") is True


def test_reconciliation_proves_delivery_when_another_writer_advanced(
        tmp_path, bare_remote, monkeypatch):
    """Our tip is an ancestor of the remote head: delivery is proven."""
    first = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(first.workdir)
    first.remote = str(bare_remote)
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "a"})

    tip = git(first.workdir, "rev-parse", "HEAD").strip()
    # Someone else builds on our tip after we pushed it.
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "b"})

    pushed, known, _ = first._reconcile_push(tip)
    assert pushed is True and known is True


def test_genuine_rejection_is_still_proven_false(tmp_path, bare_remote):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert exc.value.pushed is False and exc.value.pushed_known is True


def test_unsettleable_nonzero_push_is_unknown(tmp_path, bare_remote, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run

    def run(cmd, **kwargs):
        if "push" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "fatal: broken pipe")
        if "ls-remote" in cmd:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: unreachable")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    # Recovery now streams output. Fail its actual runner as well as the
    # ordinary push call, preserving the original unavailable-query scenario.
    from agent_room.process import BoundedResult
    monkeypatch.setattr(agent_room.gitstore, 'run_bounded',
                        lambda *a, **k: BoundedResult(128, b'', b'fatal: unreachable'))
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert exc.value.pushed is None and exc.value.pushed_known is False
    assert isinstance(exc.value.cause, PushAmbiguous)


# ===== AD. Git object content integrity ====================================

def forge_loose_blob(store, rel, new_text):
    """Replace a loose blob's file with different valid zlib content."""
    oid = git(store.workdir, "rev-parse", f"HEAD:{rel}").strip()
    path = loose_object_path(store, oid)
    assert path.exists(), "expected a loose blob"
    payload = new_text.encode("utf-8")
    body = b"blob %d\0" % len(payload) + payload
    path.chmod(0o644)
    path.write_bytes(zlib.compress(body))
    return oid


def test_forged_loose_blob_is_detected(store, room):
    """Git hands back the forged content; the object id no longer matches."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})

    envelope = json.loads((store.workdir / posted["path"]).read_text(encoding="utf-8"))
    envelope["body"] = {"text": "forged"}
    del envelope["envelope_sha256"]
    forged = canonical.canonical_text(canonical.seal(envelope))
    oid = forge_loose_blob(store, posted["path"], forged)

    # The forgery is internally consistent at the envelope level...
    canonical.verify(canonical.strict_loads(forged))
    # ...and git fsck sees the object-id mismatch.
    fsck = subprocess.run(["git", "fsck", "--strict"], cwd=store.workdir,
                          capture_output=True, text=True)
    assert oid[:8] in (fsck.stdout + fsck.stderr) or fsck.returncode != 0

    with pytest.raises(AppendOnlyViolation):
        store.verify_store()
    with pytest.raises(AppendOnlyViolation):
        store.read("t1", posted["message_id"])


def test_integrity_gate_is_not_hidden_by_the_history_cache(store, room):
    """Corruption does not move the tip, so the cache must not mask it."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    assert store.verify_store() == 1          # warms _history_cache

    envelope = json.loads((store.workdir / posted["path"]).read_text(encoding="utf-8"))
    envelope["body"] = {"text": "forged"}
    del envelope["envelope_sha256"]
    forge_loose_blob(store, posted["path"],
                     canonical.canonical_text(canonical.seal(envelope)))

    with pytest.raises(AppendOnlyViolation):
        store.verify_store()


# ===== AE. proven absence is not uncertainty ===============================

def test_proven_no_commit_reports_not_created(tmp_path, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    room = AgentRoom(store, "claude-code", None)

    # Fail the commit itself; the add-commit lookup stays healthy, so absence
    # is provable.
    flaky_git(monkeypatch, lambda cmd: "commit" in cmd)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "never written"})

    assert exc.value.locally_committed is False
    assert exc.value.locally_committed_known is True
    assert exc.value.commit is None and exc.value.commit_known is True
    assert exc.value.status == "not_created"
    assert exc.value.as_result()["status"] == "not_created"

    monkeypatch.undo()
    # Proven absence: the staged artifact was cleaned, so a retry is possible.
    assert store._git("status", "--porcelain").stdout.strip() == ""
    assert room.post(thread_id="t1", type="observation",
                     body={"text": "retried"})["status"] == "created"


def test_unknown_persistence_cleans_nothing(tmp_path, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    room = AgentRoom(store, "claude-code", None)

    flaky_git(monkeypatch,
              lambda cmd: "commit" in cmd or "--diff-filter=A" in cmd)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "ambiguous"})

    assert exc.value.status == "unknown"
    assert exc.value.locally_committed is None
    monkeypatch.undo()
    # Nothing was cleaned - we could not prove it was safe to clean.
    assert store._git("status", "--porcelain").stdout.strip() != ""


def test_local_persistence_state_is_three_valued(store, room, monkeypatch):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert store.local_persistence_state(posted["path"])[1] == "present"
    assert store.local_persistence_state(
        store.message_path("t1", uuid7()))[1] == "absent"

    flaky_git(monkeypatch, lambda cmd: "--diff-filter=A" in cmd)
    assert store.local_persistence_state(posted["path"])[1] == "unknown"


# ===== AF. canonical / JSON error contract =================================

@pytest.mark.parametrize("root", [None, [], True, 123, "str", 1.5])
def test_seal_rejects_non_mapping_roots(root):
    with pytest.raises(SchemaError, match="must be a JSON object"):
        canonical.seal(root)


@pytest.mark.parametrize("text", ['{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'])
def test_non_finite_constants_are_refused(text):
    with pytest.raises(SchemaError, match="non-standard constant"):
        canonical.strict_loads(text)


@pytest.mark.parametrize("text", ["{", "not json", "", "{'a': 1}", '{"a": 1,}'])
def test_malformed_json_becomes_a_schema_error(text):
    with pytest.raises(SchemaError, match="not valid JSON"):
        canonical.strict_loads(text)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_do_not_serialise(value):
    with pytest.raises(SchemaError, match="not canonically serialisable"):
        canonical.canonical_bytes({"a": value})


def test_unsupported_types_do_not_serialise():
    with pytest.raises(SchemaError, match="not canonically serialisable"):
        canonical.canonical_bytes({"a": {1, 2}})


def test_lone_surrogate_is_a_schema_error():
    with pytest.raises(SchemaError, match="UTF-8"):
        canonical.canonical_bytes({"a": "\ud800"})


def test_malformed_committed_json_fails_as_agent_room_error(store, room):
    mid = uuid7()
    rel = store.message_path("t1", mid)
    (store.workdir / rel).parent.mkdir(parents=True, exist_ok=True)
    (store.workdir / rel).write_text("{not json", encoding="utf-8")
    store._git("add", "--", rel)
    store._commit("malformed json", rel)

    with pytest.raises(SchemaError, match="not valid JSON"):
        store.verify_store()


def test_cli_reports_malformed_committed_json_cleanly(store, room, capsys):
    mid = uuid7()
    rel = store.message_path("t1", mid)
    (store.workdir / rel).parent.mkdir(parents=True, exist_ok=True)
    (store.workdir / rel).write_text("{not json", encoding="utf-8")
    store._git("add", "--", rel)
    store._commit("malformed json", rel)

    code = main(["--repo", str(store.workdir), "--participant", "claude-code", "verify"])
    err = capsys.readouterr().err
    assert code == 2 and "SchemaError" in err and "Traceback" not in err
    assert "JSONDecodeError" not in err


# ===== AG. strict external URL syntax ======================================

@pytest.mark.parametrize("url", [
    pytest.param("https://user@@host.test/x", id="double-at"),
    pytest.param("https://user:pw@host.test/x", id="credentials"),
    pytest.param("https://host.test\\evil/x", id="backslash-authority"),
    pytest.param("https://host.test/x\\y", id="backslash-path"),
    pytest.param("https://host.test/%ZZ", id="bad-percent-escape"),
    pytest.param("https://host.test/%A", id="truncated-percent-escape"),
    pytest.param("https://-bad.test/x", id="leading-dash-label"),
    pytest.param("https://a..b.test/x", id="empty-label"),
    pytest.param("https://host.test:0/x", id="port-zero"),
])
def test_ambiguous_urls_are_refused(room, url):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "external", "url": url}])


@pytest.mark.parametrize("url", [
    "https://example.test/report.pdf",
    "http://192.0.2.10:8080/a",
    "http://[2001:db8::1]:8443/a",
    "https://xn--bcher-kva.example/a",
    "https://host.test/a%2Fb",
])
def test_valid_urls_are_accepted(room, url):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": url}])


# ===== AH. CLI empty strings are explicit input ============================

@pytest.mark.parametrize("option", ["--body", "--recipient", "--project", "--evidence"])
def test_cli_empty_string_arguments_are_rejected(store, option, capsys):
    argv = ["--repo", str(store.workdir), "--participant", "claude-code",
            "post", "--thread-id", "t1", "--type", "observation"]
    if option != "--body":
        argv += ["--body", '{"text": "x"}']
    argv += [option, ""]
    code = main(argv)
    assert code == 2
    assert "not valid JSON" in capsys.readouterr().err
    assert list(store.iter_messages()) == []


def test_cli_omitted_options_still_use_defaults(store, capsys):
    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}'])
    assert code == 0
    posted = json.loads(capsys.readouterr().out)
    assert store.read("t1", posted["message_id"])["recipient"] == {"broadcast": True}


# ===== AI. a failed ancestry query must not poison the cache ===============

def test_failed_ancestry_query_is_not_cached(store, room, monkeypatch):
    grounded = room.post(thread_id="t1", type="evidence", body={"text": "e"},
                         evidence=[REPO_EVIDENCE])
    room.post(thread_id="t1", type="claim", body={"text": "c"},
              claim={"status": "supported", "scope": f"at {FULL_SHA}",
                     "revision_condition": "a counterexample",
                     "evidence_basis": [grounded["message_id"]]})

    real_run = subprocess.run

    def run(cmd, **kwargs):
        if "merge-base" in cmd:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: bad object")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    with pytest.raises(AgentRoomError, match="ancestry query"):
        store.verify_store()

    # Same store instance, fault removed: the legitimate history must verify.
    monkeypatch.undo()
    assert store.verify_store() == 2


def test_established_ancestry_results_are_cached(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "a"})
    first = git(store.workdir, "rev-parse", "HEAD").strip()
    room.post(thread_id="t1", type="observation", body={"text": "b"})
    second = git(store.workdir, "rev-parse", "HEAD").strip()

    assert store.is_strict_ancestor(first, second) is True
    assert store.is_strict_ancestor(second, first) is False
    assert store.is_strict_ancestor(first, first) is False


# ===== AJ. rebase without ambient Git identity =============================

def test_concurrent_rebase_works_without_global_git_identity(
        tmp_path, bare_remote, monkeypatch):
    """A fresh participant checkout has no user.name/user.email at all."""
    first = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(first.workdir)
    first.remote = str(bare_remote)
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "from claude"})

    second_path = tmp_path / "b"
    git(tmp_path, "clone", "-q", str(bare_remote), str(second_path))
    git(second_path, "checkout", "-q", "agent-room")
    # Deliberately no identity: not in the clone, and HOME points nowhere.
    empty_home = tmp_path / "nohome"
    empty_home.mkdir()
    monkeypatch.setenv("HOME", str(empty_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(empty_home))
    identity = subprocess.run(
        ["git", "config", "--local", "--get-regexp", "^user\\."],
        cwd=second_path, capture_output=True, text=True)
    assert identity.stdout.strip() == "", "the clone must have no local identity"

    # The remote advances, so the second writer must rebase.
    AgentRoom(first, "claude-code", None).post(
        thread_id="t1", type="observation", body={"text": "claude again"})

    second = GitMessageStore(second_path, branch="agent-room", remote=str(bare_remote))
    result = AgentRoom(second, "openai-research", None).post(
        thread_id="t1", type="observation", body={"text": "from openai"})

    assert result["pushed"] is True
    texts = {m["body"]["text"] for m in second.iter_messages()}
    assert texts == {"from claude", "claude again", "from openai"}
