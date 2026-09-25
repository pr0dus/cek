"""Third-round Codex regressions: local Git trust through API boundaries.

Sections Q-Y. The recurring theme is that the store must not let an
*unverifiable* situation masquerade as a verified one — a replaced history, an
evidence message nobody checked intrinsically, an object lookup that failed,
or a commit/push whose outcome was never actually observed.
"""

import json
import subprocess

import pytest

import agent_room
from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.cli import EXIT_PARTIAL_DELIVERY, main
from agent_room.errors import (
    AgentRoomError,
    AppendOnlyViolation,
    DeliveryError,
    GitTimeout,
    HistoryUnavailable,
    PushAmbiguous,
    SchemaError,
)
from agent_room.ids import uuid7
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


def flaky_git(monkeypatch, predicate, error=None):
    real_run = subprocess.run
    real_bounded = agent_room.gitstore.run_bounded

    def run(cmd, **kwargs):
        if predicate(cmd):
            raise (error or subprocess.TimeoutExpired(cmd, 60))
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    def bounded(cmd, **kwargs):
        if predicate(cmd):
            raise (error or subprocess.TimeoutExpired(cmd, 60))
        return real_bounded(cmd, **kwargs)
    monkeypatch.setattr(agent_room.gitstore, 'run_bounded', bounded)


def resealed_rewrite(store, posted, text="rewritten"):
    envelope = json.loads((store.workdir / posted["path"]).read_text(encoding="utf-8"))
    envelope["body"] = {"text": text}
    del envelope["envelope_sha256"]
    (store.workdir / posted["path"]).write_text(
        canonical.canonical_text(canonical.seal(envelope)), encoding="utf-8")
    git(store.workdir, "add", "--", posted["path"])
    git(store.workdir, "commit", "-q", "-m", "resealed rewrite")


# ===== Q. local history overrides ==========================================

def test_resealed_rewrite_is_rejected_before_any_override(store, room):
    """Baseline for the two override reproductions below."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    resealed_rewrite(store, posted)
    with pytest.raises(AppendOnlyViolation):
        store.verify_store()


def test_replace_ref_cannot_launder_a_rewrite(store, room):
    """Installing a replace ref must not make the rewrite verify."""
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    clean_tip = git(store.workdir, "rev-parse", "HEAD").strip()
    resealed_rewrite(store, posted)
    dirty_tip = git(store.workdir, "rev-parse", "HEAD").strip()

    git(store.workdir, "replace", "-f", dirty_tip, clean_tip)
    assert git(store.workdir, "for-each-ref", "refs/replace/").strip() != ""

    with pytest.raises(HistoryUnavailable, match="replacement refs"):
        store.verify_store()
    with pytest.raises(HistoryUnavailable):
        room.post(thread_id="t1", type="observation", body={"text": "next"})


def test_graft_file_cannot_launder_a_rewrite(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "original"})
    base = git(store.workdir, "rev-parse", "HEAD").strip()
    resealed_rewrite(store, posted)

    grafts = store._git_dir() / "info" / "grafts"
    grafts.parent.mkdir(parents=True, exist_ok=True)
    grafts.write_text(f"{git(store.workdir, 'rev-parse', 'HEAD').strip()} {base}\n",
                      encoding="utf-8")

    with pytest.raises(HistoryUnavailable, match="graft"):
        store.verify_store()


def test_empty_graft_file_is_tolerated(store, room):
    grafts = store._git_dir() / "info" / "grafts"
    grafts.parent.mkdir(parents=True, exist_ok=True)
    grafts.write_text("\n  \n", encoding="utf-8")
    room.post(thread_id="t1", type="observation", body={"text": "fine"})
    assert store.verify_store() == 1


def test_verification_does_not_inherit_replacement_env(store, room, monkeypatch):
    """A caller environment must not change what verification sees."""
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/evil/")
    monkeypatch.setenv("GIT_DIR", "/nonexistent")
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert store.verify_store() == 1
    assert "GIT_DIR" not in store._clean_env()
    assert store._clean_env()["GIT_NO_REPLACE_OBJECTS"] == "1"


# ===== R. intrinsic evidence validation ====================================

def test_cross_message_blob_as_commit_fails_the_citing_claim(store, room):
    """The cited message must pass its own artifact validation first."""
    blob = store._git("rev-parse", f"{store.branch}^{{tree}}").stdout.strip()
    mid = uuid7()
    bad = room.build_envelope(thread_id="t1", type="evidence", body={"text": "e"},
                              message_id=mid,
                              evidence=[dict(REPO_EVIDENCE, commit=blob)])
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(bad)), "blob evidence")

    with pytest.raises(SchemaError, match="not a commit"):
        store.read("t1", mid)
    with pytest.raises(SchemaError):
        store.verify_store()


def test_cross_message_missing_local_path_fails_the_citing_claim(store, room):
    head = store._git("rev-parse", store.branch).stdout.strip()
    mid = uuid7()
    bad = room.build_envelope(
        thread_id="t1", type="evidence", body={"text": "e"}, message_id=mid,
        evidence=[{"kind": "repo", "repo": REPO, "commit": head, "path": "gone.py"}])
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(bad)), "missing path evidence")

    with pytest.raises(SchemaError, match="does not exist in locally available"):
        store.read("t1", mid)


def test_raw_load_still_defers_only_graph_traversal(store, room):
    """Intrinsic validation runs; cross-message traversal is what is deferred."""
    grounded = room.post(thread_id="t1", type="evidence", body={"text": "e"},
                         evidence=[REPO_EVIDENCE])
    room.post(thread_id="t1", type="claim", body={"text": "c"},
              claim={"status": "supported", "scope": f"at {FULL_SHA}",
                     "revision_condition": "a counterexample",
                     "evidence_basis": [grounded["message_id"]]})
    assert store.verify_store() == 2


# ===== S. run artifact paths ===============================================

def test_missing_local_run_path_is_refused(store, room):
    head = store._git("rev-parse", store.branch).stdout.strip()
    with pytest.raises(SchemaError, match="does not exist in locally available"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "run", "commit": head,
                             "path": "artifacts/never-written.json"}])


def test_present_local_run_path_is_accepted(store, room):
    head = store._git("rev-parse", store.branch).stdout.strip()
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "run", "commit": head,
                         "path": "README.agent-room.md"}])


def test_run_id_only_implies_no_path_lookup(store, room, monkeypatch):
    """A run_id is a stable locator; it must not trigger a filesystem check.

    The commit-object check still applies - that is section T, and an
    unreadable object database must fail rather than be assumed foreign.
    """
    def explode(*args, **kwargs):
        raise AssertionError("run_id-only evidence must not perform a path lookup")

    monkeypatch.setattr(GitMessageStore, "commit_path_state", explode)
    head = store._git("rev-parse", store.branch).stdout.strip()
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "run", "commit": head, "run_id": "run-1"}])


def test_object_database_failure_is_not_downgraded_for_run_evidence(room, monkeypatch):
    """Even a run_id-only locator fails closed if the object cannot be read."""
    flaky_git(monkeypatch, lambda cmd: "--batch-check" in cmd)
    with pytest.raises(AgentRoomError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "run", "commit": "d" * 40, "run_id": "run-1"}])


# ===== T. absence vs operational failure ===================================

def test_object_lookup_failure_raises_instead_of_claiming_absence(store, room, monkeypatch):
    """A broken object database must never read as 'foreign evidence'."""
    flaky_git(monkeypatch, lambda cmd: "--batch-check" in cmd)
    with pytest.raises(AgentRoomError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[REPO_EVIDENCE])


def test_object_states_are_distinguished(store, room):
    head = store._git("rev-parse", store.branch).stdout.strip()
    tree = store._git("rev-parse", f"{store.branch}^{{tree}}").stdout.strip()

    assert store.commit_object_state(head) == "commit"
    assert store.commit_object_state(tree) == "not-a-commit"
    assert store.commit_object_state("e" * 40) == "absent"
    assert store.commit_path_state(head, "README.agent-room.md") == "present"
    assert store.commit_path_state(head, "nope.py") == "absent"
    assert store.commit_path_state("e" * 40, "x.py") == "unknown"


def test_path_with_nul_is_refused_before_git(room):
    with pytest.raises(SchemaError, match="control characters"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, path="a\x00b.py")])


@pytest.mark.parametrize("path", ["a\nb.py", "a\tb.py", "a\rb.py", "a\x1bb.py"])
def test_control_characters_in_paths_are_refused(room, path):
    with pytest.raises(SchemaError, match="control characters"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, path=path)])


def test_subprocess_os_error_is_wrapped(store, monkeypatch):
    monkeypatch.setattr(
        agent_room.gitstore.subprocess, "run",
        lambda cmd, **kw: (_ for _ in ()).throw(OSError("argument list too long")))
    with pytest.raises(AgentRoomError, match="could not be executed"):
        store._git("status", "--porcelain")


# ===== U. commit-time ambiguity ============================================

def test_lost_commit_result_with_failed_reconciliation_is_unknown(tmp_path, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    room = AgentRoom(store, "claude-code", None)

    flaky_git(monkeypatch,
              lambda cmd: "commit" in cmd or "--diff-filter=A" in cmd)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "ambiguous"})

    assert exc.value.locally_committed is None
    assert exc.value.locally_committed_known is False
    assert exc.value.commit is None and exc.value.commit_known is False
    assert exc.value.message_id and exc.value.path
    assert "Do NOT repost" in str(exc.value)


def test_lost_commit_result_but_provable_persistence(tmp_path, monkeypatch):
    """The commit landed; only reading its result failed."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    room = AgentRoom(store, "claude-code", None)

    # Fail only the HEAD read that follows a successful `git commit`.
    flaky_git(monkeypatch, lambda cmd: cmd[-2:] == ["rev-parse", "HEAD"])
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "landed"})

    assert exc.value.locally_committed is True
    assert exc.value.locally_committed_known is True
    assert exc.value.commit_known is True and exc.value.commit

    monkeypatch.undo()
    assert len(list(store.iter_messages())) == 1


def test_cli_renders_commit_ambiguity_as_json(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)

    flaky_git(monkeypatch,
              lambda cmd: "commit" in cmd or "--diff-filter=A" in cmd)
    code = main(["--repo", str(repo), "--participant", "claude-code",
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}'])
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_PARTIAL_DELIVERY
    assert payload["locally_committed"] is None
    assert payload["locally_committed_known"] is False
    assert payload["commit"] is None and payload["commit_known"] is False
    assert payload["message_id"] and payload["path"]


# ===== V. push acknowledgement loss ========================================

def test_remote_accepted_but_acknowledgement_lost_is_not_false(tmp_path, bare_remote, monkeypatch):
    """The reproduction: the ref really is there; the result was lost."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)
    room.post(thread_id="t1", type="observation", body={"text": "first"})

    real_run = subprocess.run
    state = {"pushed": False}

    def run(cmd, **kwargs):
        if "push" in cmd and not state["pushed"]:
            state["pushed"] = True
            real_run(cmd, **kwargs)          # the remote really accepts it
            raise subprocess.TimeoutExpired(cmd, 60)   # ...ack is lost
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    result = room.post(thread_id="t1", type="observation", body={"text": "second"})

    assert result["pushed"] is not False, "delivery was not disproven"
    assert result["pushed"] is True and result["pushed_known"] is True
    assert result["push"].get("reconciled") is True


def test_unprovable_push_outcome_stays_unknown(tmp_path, bare_remote, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)
    room.post(thread_id="t1", type="observation", body={"text": "first"})

    # Both the push result and the reconciliation are lost.
    flaky_git(monkeypatch, lambda cmd: "push" in cmd or "ls-remote" in cmd)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "second"})

    assert exc.value.pushed is None, "must not claim non-delivery it cannot prove"
    assert exc.value.pushed_known is False
    assert isinstance(exc.value.cause, PushAmbiguous)
    assert "UNKNOWN" in str(exc.value)


def test_established_rejection_is_still_reported_false(tmp_path, bare_remote):
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


# ===== W. locator syntax containment =======================================

@pytest.mark.parametrize("url", [
    pytest.param("http://exa mple.com/x", id="space"),
    pytest.param("http://example.com/\nx", id="newline"),
    pytest.param("http://example.com/\x00x", id="nul"),
    pytest.param("http://[::1/x", id="malformed-ipv6"),
    pytest.param("http://example.com:notaport/x", id="non-numeric-port"),
    pytest.param("http://example.com:99999/x", id="out-of-range-port"),
    pytest.param("http:///nohost", id="empty-authority"),
])
def test_malformed_urls_fail_as_schema_errors(room, url):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "external", "url": url}])


def test_valid_ipv6_and_port_are_accepted(room):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": "http://[::1]:8080/report"}])


# ===== X. defaults only on None ============================================

@pytest.mark.parametrize("recipient", [[], False, 0, "", {}])
def test_falsy_recipient_never_silently_broadcasts(room, recipient):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  recipient=recipient)


def test_recipient_none_defaults_to_broadcast(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"},
                       recipient=None)
    assert room.get("t1", posted["message_id"])["recipient"] == {"broadcast": True}


@pytest.mark.parametrize("value", [[], False, 0, ""])
def test_falsy_project_is_rejected_not_defaulted(room, value):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  project=value)


@pytest.mark.parametrize("value", [False, 0, "", {}])
def test_falsy_evidence_is_rejected_not_defaulted(room, value):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  evidence=value)


@pytest.mark.parametrize("value", [False, 0, "", []])
def test_falsy_message_id_is_rejected_not_generated(room, value):
    with pytest.raises(SchemaError, match="UUIDv7"):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  message_id=value)


@pytest.mark.parametrize("value", [False, 0, "", []])
def test_falsy_timestamp_is_rejected_not_generated(room, value):
    with pytest.raises(SchemaError, match="timestamp"):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  timestamp=value)


@pytest.mark.parametrize("value", [[], "x", 0, False])
def test_malformed_sender_is_rejected_not_emptied(room, value):
    with pytest.raises(SchemaError, match="sender"):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  sender=value)


def test_none_defaults_still_produce_a_valid_message(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"},
                       recipient=None, project=None, evidence=None,
                       message_id=None, timestamp=None, sender=None)
    stored = room.get("t1", posted["message_id"])
    assert stored["sender"]["agent"] == "claude-code"
    assert stored["evidence"] == [] and stored["project"] == {}


def test_cli_recipient_array_fails_instead_of_broadcasting(store, capsys):
    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}', "--recipient", "[]"])
    assert code == 2
    assert "recipient" in capsys.readouterr().err
    assert list(store.iter_messages()) == []


# ===== Y. non-object JSON roots ============================================

@pytest.mark.parametrize("root", ["null", "[]", "true", "123", '"a string"', "[1,2]"])
def test_non_object_committed_roots_fail_closed(store, room, root):
    mid = uuid7()
    write_raw(store, store.message_path("t1", mid), root, "non-object root")
    with pytest.raises(SchemaError, match="must be a JSON object"):
        store.verify_store()


@pytest.mark.parametrize("root", [None, [], True, 123, "a string", 1.5])
def test_low_level_append_rejects_non_object_roots(store, root):
    with pytest.raises(SchemaError, match="must be a JSON object"):
        store.append(root)


@pytest.mark.parametrize("root", [None, [], True, 123, "a string"])
def test_canonical_helpers_reject_non_object_roots(root):
    with pytest.raises(SchemaError, match="must be a JSON object"):
        canonical.verify(root)
    with pytest.raises(SchemaError, match="must be a JSON object"):
        canonical.envelope_digest(root)


def test_cli_verify_reports_non_object_root_cleanly(store, room, capsys):
    mid = uuid7()
    write_raw(store, store.message_path("t1", mid), "null", "non-object root")
    code = main(["--repo", str(store.workdir), "--participant", "claude-code", "verify"])
    err = capsys.readouterr().err
    assert code == 2
    assert "SchemaError" in err
    assert "Traceback" not in err
