"""Second-round Codex regressions: history completeness through strict typing.

Sections K-P. The theme is that the store must never turn "I could not check"
into "everything is fine" — not for truncated history, not for a reference a
caller asserts, not for a commit SHA it failed to look up.
"""

import inspect
import json
import subprocess

import pytest

import agent_room
from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.cli import EXIT_PARTIAL_DELIVERY, main
from agent_room.errors import (
    AgentRoomError,
    AppendOnlyViolation,
    ClaimStateError,
    DeliveryError,
    HistoryUnavailable,
    SchemaError,
    UnresolvedReference,
)
from agent_room.ids import uuid7
from agent_room.namespace import NamespaceViolation
from agent_room.schema import validate_envelope
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
    """Make matching git invocations fail, leaving all others real."""
    real_run = subprocess.run

    def run(cmd, **kwargs):
        if predicate(cmd):
            raise (error or subprocess.TimeoutExpired(cmd, 60))
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)


# ===== K. history completeness =============================================

def test_shallow_clone_is_refused_for_verification(tmp_path, bare_remote, store, room):
    """A depth-1 clone cannot prove append-only history."""
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    room.post(thread_id="t1", type="observation", body={"text": "two"})
    store.remote = str(bare_remote)
    store.push()

    # file:// is required: git silently ignores --depth for local path clones.
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", "--branch", "agent-room",
        f"file://{bare_remote}", str(shallow))
    configure_identity(shallow)
    truncated = GitMessageStore(shallow, branch="agent-room")

    assert git(shallow, "rev-parse", "--is-shallow-repository").strip() == "true"
    with pytest.raises(HistoryUnavailable, match="shallow"):
        truncated.verify_store()


def test_shallow_clone_cannot_append_or_push(tmp_path, bare_remote, store, room):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    store.remote = str(bare_remote)
    store.push()

    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", "--branch", "agent-room",
        f"file://{bare_remote}", str(shallow))
    configure_identity(shallow)
    assert git(shallow, "rev-parse", "--is-shallow-repository").strip() == "true"
    truncated = GitMessageStore(shallow, branch="agent-room", remote=str(bare_remote))
    truncated_room = AgentRoom(truncated, "openai-research", None)

    with pytest.raises(HistoryUnavailable):
        truncated_room.post(thread_id="t1", type="observation", body={"text": "x"})
    with pytest.raises(HistoryUnavailable):
        truncated.push()


def test_missing_branch_is_an_error_not_an_empty_room(store):
    absent = GitMessageStore(store.workdir, branch="no-such-branch")
    with pytest.raises(HistoryUnavailable, match="does not exist"):
        absent.verify_store()
    with pytest.raises(HistoryUnavailable):
        list(absent.iter_messages())


def test_cli_verify_against_missing_branch_exits_non_zero(store, capsys):
    code = main(["--repo", str(store.workdir), "--participant", "claude-code",
                 "--branch", "no-such-branch", "verify"])
    out = capsys.readouterr()
    assert code != 0
    assert "HistoryUnavailable" in out.err
    assert '"verified": 0' not in out.out, "discovery failure must not look like an empty room"
    assert out.out.strip() == ""


def test_history_query_failure_is_not_empty_history(store, room, monkeypatch):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    flaky_git(monkeypatch, lambda cmd: "--name-status" in cmd)
    with pytest.raises(AgentRoomError):
        store.verify_store()


def test_merge_scan_failure_is_not_empty_history(store, room, monkeypatch):
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    flaky_git(monkeypatch, lambda cmd: "--merges" in cmd)
    with pytest.raises(AgentRoomError):
        store.verify_store()


def test_a_genuinely_empty_room_still_verifies(store):
    """Zero messages is a valid answer; unavailable history is not."""
    assert store.verify_store() == 0


# ===== L. no caller-supplied reference authority ===========================

def test_append_signature_accepts_no_resolver():
    params = inspect.signature(GitMessageStore.append).parameters
    assert "resolver" not in params, "append must not take a caller-supplied resolver"


def test_fabricated_parent_resolver_cannot_be_injected(store, room):
    class Liar:
        @staticmethod
        def resolve_message(message_id):
            return {"message_id": message_id, "thread_id": "t1"}

    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="answer", body={"text": "x"}, parent_id=uuid7()))

    with pytest.raises(TypeError):
        store.append(envelope, resolver=Liar())
    with pytest.raises(UnresolvedReference):
        store.append(envelope)
    assert store.verify_store() == 0


def test_fabricated_evidence_resolver_cannot_be_injected(store, room):
    class Liar:
        @staticmethod
        def resolve_message(message_id):
            return {"message_id": message_id, "thread_id": "t1",
                    "evidence": [REPO_EVIDENCE]}

    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="claim", body={"text": "c"},
        claim={"status": "supported", "scope": f"at {FULL_SHA}",
               "revision_condition": "a counterexample",
               "evidence_basis": [uuid7()]}))

    with pytest.raises(TypeError):
        store.append(envelope, resolver=Liar())
    with pytest.raises(UnresolvedReference):
        store.append(envelope)


def test_low_level_append_rejects_a_blob_as_a_pinned_commit(store, room):
    """The write resolver must verify artifacts exactly like the read side."""
    blob = store._git("rev-parse", f"{store.branch}^{{tree}}").stdout.strip()
    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="evidence", body={"text": "e"},
        evidence=[dict(REPO_EVIDENCE, commit=blob)]))

    with pytest.raises(SchemaError, match="not a commit"):
        store.append(envelope)
    assert store.verify_store() == 0


# ===== M. evidence locators: locally decidable only ========================

def test_missing_path_in_a_locally_available_commit_is_refused(store, room):
    """We hold this commit, so the cited path must really be in it."""
    head = store._git("rev-parse", store.branch).stdout.strip()
    with pytest.raises(SchemaError, match="does not exist in locally available"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "repo", "repo": REPO, "commit": head,
                             "path": "no/such/file.py"}])


def test_present_path_in_a_locally_available_commit_is_accepted(store, room):
    head = store._git("rev-parse", store.branch).stdout.strip()
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "repo", "repo": REPO, "commit": head,
                         "path": "README.agent-room.md"}])


def test_foreign_locator_is_preserved_without_network_verification(room, monkeypatch):
    """No fetch, no HTTP: an unavailable repo keeps its locator."""
    flaky_git(monkeypatch, lambda cmd: "fetch" in cmd or "clone" in cmd or "ls-remote" in cmd)
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[dict(REPO_EVIDENCE, commit="c" * 40)])


@pytest.mark.parametrize("url", [
    pytest.param("not a url", id="free-text"),
    pytest.param("example.com/report", id="no-scheme"),
    pytest.param("ftp://example.com/x", id="wrong-scheme"),
    pytest.param("file:///etc/passwd", id="file-scheme"),
    pytest.param("http://", id="no-host"),
    pytest.param("javascript:alert(1)", id="script-scheme"),
])
def test_invalid_external_urls_are_refused(room, url):
    with pytest.raises(SchemaError, match="url"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "external", "url": url}])


@pytest.mark.parametrize("url", [
    "https://example.invalid/report.pdf",
    "http://example.invalid:8080/a/b?c=d#e",
])
def test_valid_external_urls_are_accepted_without_fetching(room, url, monkeypatch):
    flaky_git(monkeypatch, lambda cmd: "fetch" in cmd)
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": url}])


def test_cross_message_evidence_gets_the_same_artifact_verification(store, room):
    """A resolver-returned message is validated like an in-message one."""
    head = store._git("rev-parse", store.branch).stdout.strip()
    mid = uuid7()
    bad = room.build_envelope(
        thread_id="t1", type="evidence", body={"text": "smuggled"}, message_id=mid,
        evidence=[{"kind": "repo", "repo": REPO, "commit": head, "path": "nope.py"}])
    write_raw(store, store.message_path("t1", mid),
              canonical.canonical_text(canonical.seal(bad)), "bad evidence")

    with pytest.raises(SchemaError, match="does not exist in locally available"):
        store.verify_store()


# ===== N. delivery recovery never lies =====================================

def test_recovery_timeout_after_successful_push_keeps_pushed_true(
        tmp_path, bare_remote, monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    flaky_git(monkeypatch, lambda cmd: "--diff-filter=A" in cmd)
    result = room.post(thread_id="t1", type="observation", body={"text": "landed"})

    assert result["pushed"] is True, "a failed receipt lookup is not a delivery failure"
    assert result["commit_known"] is False
    assert result["commit"] is None, "never a stale SHA presented as current"
    assert result["message_id"] and result["path"]
    assert "recovery_error" in result

    monkeypatch.undo()
    assert len(list(store.iter_messages())) == 1


def test_recovery_failure_after_failed_push_reports_unknown_commit(
        tmp_path, bare_remote, monkeypatch):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    flaky_git(monkeypatch, lambda cmd: "--diff-filter=A" in cmd)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "held"})

    assert exc.value.commit is None
    assert exc.value.commit_known is False
    assert exc.value.recovery_error is not None
    assert exc.value.locally_committed is True and exc.value.pushed is False
    assert exc.value.message_id and exc.value.path

    monkeypatch.undo()
    assert len(list(store.iter_messages())) == 1


def test_proven_commit_is_reported_with_commit_known_true(tmp_path, bare_remote):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    result = room.post(thread_id="t1", type="observation", body={"text": "ok"})
    assert result["commit_known"] is True
    assert result["commit"] == store.recover_add_commit(result["path"])[0]


def test_recover_add_commit_reports_structured_uncertainty(store, room, monkeypatch):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    commit, known, error = store.recover_add_commit(posted["path"])
    assert known is True and commit == posted["commit"] and error is None

    flaky_git(monkeypatch, lambda cmd: "--diff-filter=A" in cmd)
    commit, known, error = store.recover_add_commit(posted["path"])
    assert commit is None and known is False and error is not None


def test_cli_reports_structured_delivery_state_on_recovery_failure(
        tmp_path, bare_remote, monkeypatch, capsys):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)

    flaky_git(monkeypatch, lambda cmd: "--diff-filter=A" in cmd)
    code = main(["--repo", str(repo), "--participant", "claude-code",
                 "--remote", str(bare_remote),
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}'])
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_PARTIAL_DELIVERY
    assert payload["locally_committed"] is True
    assert payload["pushed"] is False
    assert payload["commit"] is None
    assert payload["commit_known"] is False
    assert payload["message_id"] and payload["path"]


# ===== O. the namespace root is reserved ===================================

def test_tracked_file_at_the_namespace_root_is_rejected(store, room):
    """`.agent-room/messages` exactly — no trailing slash to match on."""
    room.post(thread_id="t1", type="observation", body={"text": "legit"})
    git(store.workdir, "rm", "-rq", "--cached", ".agent-room/messages")
    (store.workdir / ".agent-room" / "messages").rename(
        store.workdir / ".agent-room" / "_tmp")
    (store.workdir / ".agent-room" / "messages").write_text("not a directory\n",
                                                            encoding="utf-8")
    git(store.workdir, "add", "--", ".agent-room/messages")
    git(store.workdir, "commit", "-q", "-m", "file at the namespace root")

    with pytest.raises(NamespaceViolation, match="canonical"):
        store.verify_store()


# ===== P. strict schema typing =============================================

def envelope_for(room, **over):
    envelope = room.build_envelope(thread_id="t1", type="observation",
                                   body={"text": "x"})
    envelope.update(over)
    return envelope


@pytest.mark.parametrize("version", [
    pytest.param(True, id="bool-true"),
    pytest.param(False, id="bool-false"),
    pytest.param("1", id="string"),
    pytest.param(1.0, id="float"),
    pytest.param([1], id="array"),
])
def test_schema_version_must_be_a_real_integer(room, version):
    with pytest.raises(SchemaError, match="schema_version"):
        validate_envelope(envelope_for(room, schema_version=version))


@pytest.mark.parametrize("timestamp", [
    pytest.param("yesterday", id="free-text"),
    pytest.param("2026-09-22", id="date-only"),
    pytest.param("2026-09-22T10:00:00+02:00", id="offset-not-utc"),
    pytest.param("2026-13-45T99:99:99Z", id="impossible"),
    pytest.param("2026-09-22 10:00:00Z", id="space-separator"),
])
def test_timestamp_must_be_canonical_utc(room, timestamp):
    with pytest.raises(SchemaError, match="timestamp"):
        validate_envelope(envelope_for(room, timestamp=timestamp))


def test_valid_timestamp_is_accepted(room):
    validate_envelope(envelope_for(room, timestamp="2026-09-22T10:00:00Z"))


@pytest.mark.parametrize("scope", [[], {}, "", "   ", 7, None])
def test_claim_scope_must_be_a_non_empty_string(room, scope):
    with pytest.raises(ClaimStateError, match="scope"):
        room.post(thread_id="t1", type="claim", body={"text": "c"},
                  evidence=[dict(REPO_EVIDENCE, id="e1")],
                  claim={"status": "supported", "scope": scope,
                         "revision_condition": "r", "evidence_basis": ["e1"]})


@pytest.mark.parametrize("condition", [[], {}, "", "  ", 3, None])
def test_claim_revision_condition_must_be_a_non_empty_string(room, condition):
    with pytest.raises(ClaimStateError, match="revision_condition"):
        room.post(thread_id="t1", type="claim", body={"text": "c"},
                  evidence=[dict(REPO_EVIDENCE, id="e1")],
                  claim={"status": "supported", "scope": "s",
                         "revision_condition": condition, "evidence_basis": ["e1"]})


@pytest.mark.parametrize("value", [[], {}, 7, None, True])
def test_wrong_type_message_type_is_a_schema_error(room, value):
    with pytest.raises(SchemaError, match="type"):
        validate_envelope(envelope_for(room, type=value))


@pytest.mark.parametrize("value", [[], {}, 7, None])
def test_wrong_type_lifecycle_status_is_a_schema_error(room, value):
    with pytest.raises(SchemaError, match="status"):
        validate_envelope(envelope_for(room, status=value))


@pytest.mark.parametrize("value", [[], {}, 7, None])
def test_wrong_type_evidence_kind_is_a_schema_error(room, value):
    with pytest.raises(SchemaError, match="kind"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": value}])


@pytest.mark.parametrize("value", [[], {}, 7, None])
def test_wrong_type_claim_status_is_a_claim_error(room, value):
    with pytest.raises(ClaimStateError, match="status"):
        room.post(thread_id="t1", type="claim", body={"text": "c"},
                  claim={"status": value})


@pytest.mark.parametrize("flag", ["reply_requested", "human_approval_required"])
@pytest.mark.parametrize("value", [
    pytest.param("false", id="string-false"),
    pytest.param("true", id="string-true"),
    pytest.param(0, id="zero"),
    pytest.param(1, id="one"),
    pytest.param([], id="array"),
    pytest.param({}, id="object"),
    pytest.param(None, id="null"),
])
def test_boolean_flags_are_not_coerced(room, flag, value):
    """build_envelope must preserve the caller value so validation can reject it."""
    with pytest.raises(SchemaError, match=flag):
        room.post(thread_id="t1", type="observation", body={"text": "x"},
                  **{flag: value})


def test_real_booleans_are_accepted(room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"},
                       reply_requested=True, human_approval_required=False)
    stored = room.get("t1", posted["message_id"])
    assert stored["reply_requested"] is True
    assert stored["human_approval_required"] is False


def test_no_probe_escapes_as_a_raw_python_error(room):
    """Every malformed shape must stay inside the Agent Room contract."""
    probes = [
        dict(schema_version=True), dict(timestamp="nope"), dict(type=[]),
        dict(status={}), dict(reply_requested="false"), dict(thread_id=[]),
        dict(sender=[]), dict(recipient=[]), dict(project=[]), dict(body=[]),
    ]
    for over in probes:
        with pytest.raises(AgentRoomError):
            validate_envelope(envelope_for(room, **over))
