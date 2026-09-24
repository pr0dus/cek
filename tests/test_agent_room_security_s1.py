"""Issue #13 Stage S1: the reproduced attacks, now failing closed.

Every test here corresponds to an exploit the supervisor's red team actually
ran against `426089ce…` and observed succeeding. The names of the observations
are kept in the docstrings so a reader can match a test to the report.

One test deliberately asserts that an attack still works. `CRITICAL A` — raw
Git forging human authority — is not in S1's scope, and the contract is
explicit that S1 must not pretend otherwise. It is written down here rather
than left implicit, so the gap is visible and S2 has something to invert.
"""

import hashlib
import json
import os
import stat
import subprocess
import textwrap
import threading
import time

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.auth import sign_envelope
from agent_room.claude_participant import ClaudeAdapterError, ClaudeInvoker
from agent_room.codex_participant import CodexAdapterError, CodexInvoker
from agent_room.decision import HumanDecisionAuthority, evaluate_gate
from agent_room.ids import uuid7
from agent_room.limits import (
    MAX_BODY_TEXT_CHARS,
    MAX_EVIDENCE_ITEMS,
    MAX_THREAD_MESSAGES,
    LimitExceeded,
)
from agent_room.errors import LockTimeout, ReceiptStateError
from agent_room.namespace import NamespaceViolation
from agent_room.process import run_bounded, sanitised_env
from agent_room.proof import (
    ProofArtifactConflict,
    ProofError,
    run_isolated_proof,
    run_proof,
    verify_artifact,
)
from agent_room.release import (
    ReleaseBlocked,
    ReleaseError,
    RepositoryIdentityError,
    _normalise_remote_url,
    authorise,
    canonical_repo_identity,
    identity_matches,
    receipt_state,
)
from agent_room.release import reconcile as _reconcile
from agent_room.release import reserve as _reserve
from agent_room.snapshot import SnapshotError, snapshot_manifest
from agent_room.supervisor import context_digest
from agent_room.tool_profiles import QUALIFIED_PROFILES, ToolProfileUnavailable, resolve
from tests.conftest_agent_room import (
    ACTION_SAMPLES,
    build_trust,
    configure_identity,
    git,
)


# ===== fixtures ============================================================
#
# This whole module now runs **authenticated**. S2 makes a pinned trust policy
# mandatory on every release-capable path, so verifying S1's properties in the
# unauthenticated configuration would be verifying a configuration that is no
# longer reachable. The disposable keys below stand in for credentials that in
# production live on a phone (the human) or in owner-only files (participants).


@pytest.fixture
def store(tmp_path):
    room_store = GitMessageStore.initialise(tmp_path / "room",
                                            branch="agent-room")
    configure_identity(room_store.workdir)
    policy, signers = build_trust(tmp_path / "keys", room_store)
    room_store.trust = policy
    # Test-only scaffolding: private keys never live on a store in production,
    # and nothing in `agent_room` reads this attribute.
    room_store._test_signers = signers
    return room_store


@pytest.fixture
def signers(store):
    return store._test_signers


@pytest.fixture
def room(store, signers, tmp_path):
    return AgentRoom(store, "claude-code",
                     ParticipantCursor(tmp_path / "state", "claude-code"),
                     signer=signers["claude-code"])


#: Populated per test by the autouse fixture below, so the S1 assertions keep
#: reading as assertions about S1 rather than about signing.
_SIGNERS: dict = {}


@pytest.fixture(autouse=True)
def _wire_signers(request):
    _SIGNERS.clear()
    if "store" in request.fixturenames:
        _SIGNERS.update(request.getfixturevalue("signers"))
    yield
    _SIGNERS.clear()


def reserve(store, *args, **kwargs):
    kwargs.setdefault("signer", _SIGNERS.get("release-recorder"))
    return _reserve(store, *args, **kwargs)


def reconcile(store, *args, **kwargs):
    kwargs.setdefault("signer", _SIGNERS.get("release-recorder"))
    return _reconcile(store, *args, **kwargs)

@pytest.fixture
def target(tmp_path):
    """A disposable checkout: one baseline commit, then one committed change."""
    repo = tmp_path / "target"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "work")
    configure_identity(repo)
    # A repository identity the release path can derive. Never fetched; it is
    # configuration, which is exactly the threat boundary documented for it.
    git(repo, "remote", "add", "origin", "https://github.com/pr0dus/cek.git")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "baseline")
    base = git(repo, "rev-parse", "HEAD").strip()

    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "the change under review")
    head = git(repo, "rev-parse", "HEAD").strip()
    return {"path": repo, "base": base, "head": head}


@pytest.fixture
def consequential(store, room, target):
    """A fully bound, human-approved consequential action.

    Built the way the real flow builds one: a reviewed message, a cutoff, a
    measured snapshot, a derived context, then a human decision.
    """
    reviewed = room.post(thread_id="t1", type="question",
                         body={"text": "please review the change"},
                         recipient={"agent": "openai-research"})
    cutoff = room.post(thread_id="t1", type="observation",
                       body={"text": "review complete"},
                       parent_id=reviewed["message_id"])

    manifest = snapshot_manifest(target["path"], target["base"])
    thread = store.thread_messages("t1")
    context = context_digest(store.resolve_message(reviewed["message_id"]), thread)

    action = {
        "action_id": "activate-agent-room-transport",
        "scope": "create the production agent-room transport branch",
        "consequential": True,
        "parameters": dict(ACTION_SAMPLES["activate-agent-room-transport"]),
        "binding": {
            "snapshot_sha256": manifest["manifest_sha256"],
            "supervisor_context_sha256": context,
            "project": {"repo": "pr0dus/cek", "commit": target["head"]},
            "measurement": {
                "snapshot": {"kind": "git-worktree-manifest",
                             "snapshot_schema_version":
                                 manifest["snapshot_schema_version"],
                             "base_commit": target["base"]},
                "context": {"kind": "agent-room-thread-context",
                            "thread_id": "t1",
                            "target_message_id": reviewed["message_id"],
                            "cutoff_message_id": cutoff["message_id"]},
            },
            "action_nonce": "nonce-s1-000001",
        },
    }
    request = room.post(thread_id="t1", type="decision_request",
                        body={"text": "activate the transport"},
                        human_approval_required=True, action=action,
                        parent_id=cutoff["message_id"])
    return {"request_id": request["message_id"], "action": action,
            "reviewed": reviewed["message_id"], "cutoff": cutoff["message_id"],
            "manifest": manifest}


def approve(store, consequential):
    """A human approval signed by the disposable human credential.

    In production this is `prepare()` here and `submit()` with what a phone
    returns; the signature is the same shape either way.
    """
    return HumanDecisionAuthority(store).record(
        consequential["request_id"], "approve", decision_id="hd-s1",
        signer=_SIGNERS.get("human"))


def raw_commit(repo, rel, text, message):
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    git(repo, "add", "-f", "--", rel)
    git(repo, "commit", "-q", "-m", message)


# ===== HIGH E — the branch namespace is closed =============================

def test_gitattributes_beside_the_messages_is_rejected(store, room):
    """EXTRA_NAMESPACE_FILE: `{"tracked": [".gitattributes", …], "verify_store": 0}`.

    It verified clean because verification only looked under
    `.agent-room/messages/`. `.gitattributes` is the worst possible thing to
    ignore: it changes what the bytes of a checked-out file are.
    """
    room.post(thread_id="t1", type="observation", body={"text": "legit"})
    raw_commit(store.workdir, ".gitattributes", "* text=auto\n", "inject")

    with pytest.raises(NamespaceViolation, match="Git metadata file"):
        store.verify_store()


@pytest.mark.parametrize("path,content", [
    (".gitmodules", '[submodule "x"]\n\tpath = x\n'),
    (".gitignore", "*.json\n"),
    ("evil.sh", "#!/bin/sh\necho hi\n"),
    ("docs/notes.md", "# notes\n"),
    (".agent-room/config.json", "{}\n"),
])
def test_no_unexpected_tracked_path_survives_verification(store, room, path,
                                                          content):
    room.post(thread_id="t1", type="observation", body={"text": "legit"})
    raw_commit(store.workdir, path, content, f"inject {path}")
    with pytest.raises(NamespaceViolation):
        store.verify_store()


def test_a_symlink_in_the_namespace_is_rejected(store, room):
    """A symlink is a pointer out of the verified namespace."""
    room.post(thread_id="t1", type="observation", body={"text": "legit"})
    link = store.workdir / ".agent-room" / "messages" / "t1" / f"{uuid7()}.json"
    link.symlink_to("/etc/passwd")
    git(store.workdir, "add", "-f", "--", str(link.relative_to(store.workdir)))
    git(store.workdir, "commit", "-q", "-m", "symlink")

    with pytest.raises(NamespaceViolation, match="symbolic link"):
        store.verify_store()


def test_an_executable_message_is_rejected(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    git(store.workdir, "update-index", "--chmod=+x", "--", posted["path"])
    git(store.workdir, "commit", "-q", "-m", "make it executable")

    with pytest.raises(NamespaceViolation, match="executable"):
        store.verify_store()


def test_the_genesis_marker_is_immutable(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    raw_commit(store.workdir, "README.agent-room.md", "rewritten\n", "rewrite")
    with pytest.raises(Exception, match="immutable"):
        store.verify_store()


def test_a_clean_room_still_verifies(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert store.verify_store() == 1
    assert store.assert_namespace_closed() == {"genesis": 1, "message": 1}


# ===== HIGH F — proof id containment =======================================

@pytest.mark.parametrize("bad", [
    "../escaped-proof", "../../escaped", "a/b", "/abs", ".hidden", "",
    "with space", "x" * 65, "nul\0byte",
])
def test_a_proof_id_cannot_reach_outside_the_run_directory(target, tmp_path, bad):
    """`proof_id="../escaped-proof"` wrote outside run_dir (`escaped: true`)."""
    with pytest.raises(ProofError, match="proof_id"):
        run_proof(["python3", "-c", "pass"], cwd=target["path"],
                  run_dir=tmp_path / "runs", proof_id=bad)
    assert not list(tmp_path.glob("escaped*")), "nothing was written outside"


def test_a_symlinked_run_directory_cannot_smuggle_a_write_out(target, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    runs = tmp_path / "runs"
    runs.symlink_to(outside)
    record = run_proof(["python3", "-c", "pass"], cwd=target["path"],
                       run_dir=runs, proof_id="ok")
    # Resolved containment: the artifact is inside the *resolved* run dir, and
    # the check is made against that, not against the symlink's name.
    assert os.path.realpath(record["artifact_path"]).startswith(
        str(outside.resolve()))


# ===== HIGH G — proof artifacts are write-once =============================

def test_the_same_proof_id_twice_never_overwrites(target, tmp_path):
    """PROOF_OVERWRITE: `{"same_path": true, "content_changed": true}`."""
    runs = tmp_path / "runs"
    first = run_proof(["python3", "-c", "print('one')"], cwd=target["path"],
                      run_dir=runs, proof_id="dup")
    before = open(first["artifact_path"], "rb").read()
    second = run_proof(["python3", "-c", "print('two')"], cwd=target["path"],
                       run_dir=runs, proof_id="dup")

    assert first["artifact_path"] != second["artifact_path"], "not the same path"
    assert open(first["artifact_path"], "rb").read() == before, "unchanged"
    assert b"one" in before and b"two" in open(second["artifact_path"], "rb").read()


def test_an_artifact_is_read_only_once_written(target, tmp_path):
    record = run_proof(["python3", "-c", "pass"], cwd=target["path"],
                       run_dir=tmp_path / "runs", proof_id="ro")
    mode = stat.S_IMODE(os.stat(record["artifact_path"]).st_mode)
    assert mode == 0o400, f"artifact mode {oct(mode)} is not read-only"
    assert stat.S_IMODE(os.stat(tmp_path / "runs").st_mode) == 0o700


def test_an_identical_record_conflicts_rather_than_overwriting(target, tmp_path,
                                                               monkeypatch):
    """Byte-identical records collide by design; the answer is never a rewrite."""
    import agent_room.proof as proof_mod

    monkeypatch.setattr(proof_mod, "_now_iso", lambda: "2026-09-23T00:00:00Z")
    monkeypatch.setattr(proof_mod.time, "monotonic", lambda: 0.0)
    kwargs = dict(cwd=target["path"], run_dir=tmp_path / "runs",
                  proof_id="same")
    run_proof(["python3", "-c", "pass"], **kwargs)
    with pytest.raises(ProofArtifactConflict, match="write-once"):
        run_proof(["python3", "-c", "pass"], **kwargs)


def test_a_stored_artifact_is_rehashed_on_verification(target, tmp_path):
    record = run_proof(["python3", "-c", "print('x')"], cwd=target["path"],
                       run_dir=tmp_path / "runs", proof_id="rehash")
    checked = verify_artifact(record["artifact_path"])
    assert checked["proof_sha256"] == record["proof_sha256"]
    assert checked["artifact_sha256"] == record["artifact_sha256"]

    path = record["artifact_path"]
    os.chmod(path, 0o600)
    stored = json.loads(open(path).read())
    stored["exit_status"] = 99
    open(path, "w").write(json.dumps(stored))
    with pytest.raises(ProofError, match="digest mismatch"):
        verify_artifact(path)


# ===== HIGH (process trees) — timeout kills descendants ====================

CHILD_LAUNCHER = """\
import os, subprocess, sys, time
child = subprocess.Popen(["sleep", "120"])
open(sys.argv[1], "w").write(str(child.pid))
time.sleep(120)
"""


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_gone(pid: int, seconds: float = 8.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


def test_a_proof_timeout_leaves_no_surviving_child(tmp_path, target):
    """PROOF_TIMEOUT_CHILD: `{"status": "timeout", "child_alive": true}`."""
    script = tmp_path / "launcher.py"
    script.write_text(CHILD_LAUNCHER, encoding="utf-8")
    pidfile = tmp_path / "child.pid"

    record = run_proof(["python3", str(script), str(pidfile)],
                       cwd=target["path"], run_dir=tmp_path / "runs",
                       proof_id="tree", timeout=2)
    assert record["status"] == "timeout"
    assert record["teardown"] in ("terminated", "killed")
    child = int(pidfile.read_text())
    assert wait_gone(child), f"child {child} survived the timeout"


def fake_client(tmp_path, name: str, pidfile) -> str:
    """A client that spawns a child and then hangs, like a wedged model call."""
    path = tmp_path / name
    path.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        sleep 120 &
        echo $! > {pidfile}
        sleep 120
        """), encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def test_a_claude_turn_timeout_leaves_no_surviving_child(tmp_path):
    """CLAUDE_TIMEOUT_CHILD: `{"child_alive": true}`."""
    pidfile = tmp_path / "claude.pid"
    invoker = ClaudeInvoker(fake_client(tmp_path, "claude", pidfile), timeout=2)
    with pytest.raises(ClaudeAdapterError, match="process group"):
        invoker("prompt")
    assert wait_gone(int(pidfile.read_text()))


def test_a_codex_turn_timeout_leaves_no_surviving_child(tmp_path):
    pidfile = tmp_path / "codex.pid"
    invoker = CodexInvoker(fake_client(tmp_path, "codex", pidfile), timeout=2)
    with pytest.raises(CodexAdapterError, match="process group"):
        invoker("prompt")
    assert wait_gone(int(pidfile.read_text()))


def test_an_interrupted_bounded_run_still_tears_down_the_group(tmp_path):
    script = tmp_path / "launcher.py"
    script.write_text(CHILD_LAUNCHER, encoding="utf-8")
    pidfile = tmp_path / "irq.pid"

    result = run_bounded(["python3", str(script), str(pidfile)],
                         timeout=2, env=sanitised_env())
    assert result.timed_out
    assert wait_gone(int(pidfile.read_text()))


# ===== HIGH H — ignored execution state ====================================

def test_an_ignored_file_moves_the_manifest(target):
    """IGNORED_STATE_UNBOUND: `{"entries": [], "ignored_present": true,
    "same_manifest": true}`.

    The manifest no longer pretends the tree is unchanged when an ignored
    execution-affecting file appears beside it.
    """
    repo = target["path"]
    (repo / ".gitignore").write_text("sitecustomize.py\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "ignore it")
    base = git(repo, "rev-parse", "HEAD").strip()
    before = snapshot_manifest(repo, base)

    (repo / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    after = snapshot_manifest(repo, base)

    assert before["entries"] == after["entries"], "tracked content is unchanged"
    assert after["manifest_sha256"] != before["manifest_sha256"], (
        "an ignored file that can change what executes must move the binding"
    )
    assert after["ignored"]["count"] == 1
    assert "sitecustomize.py" in after["ignored"]["sample"]


def test_the_manifest_states_what_it_does_not_bind(target):
    manifest = snapshot_manifest(target["path"], target["base"])
    assert manifest["binds"] == "tracked-content-only"
    assert manifest["ignored"]["contents_measured"] is False


def test_an_isolated_proof_cannot_see_ignored_state(target, tmp_path):
    """The real fix: the proof runs from the commit, not from the tree."""
    repo = target["path"]
    (repo / ".gitignore").write_text("sitecustomize.py\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "ignore it")
    head = git(repo, "rev-parse", "HEAD").strip()
    # An ignored file that would change what any python in this tree does.
    (repo / "sitecustomize.py").write_text(
        "open('/tmp/agent-room-pwned', 'w').write('x')\n", encoding="utf-8")

    record = run_isolated_proof(
        ["python3", "-c", "import os; print(os.path.exists('sitecustomize.py'))"],
        repo=repo, commit=head, run_dir=tmp_path / "runs",
        proof_id="isolated", timeout=60)
    assert record["exit_status"] == 0
    assert "False" in record["stdout_tail"], (
        "the isolated checkout must not contain the ignored file"
    )
    assert record["isolation"]["mode"] == "git-archive"
    assert record["isolation"]["binds_execution_state"] is True


def test_an_isolated_proof_refuses_a_manifest_that_is_not_that_commit(target,
                                                                     tmp_path):
    repo = target["path"]
    (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
    manifest = snapshot_manifest(repo, target["base"])
    with pytest.raises(ProofError, match="uncommitted content"):
        run_isolated_proof(["python3", "-c", "pass"], repo=repo,
                           commit=target["head"], run_dir=tmp_path / "runs",
                           proof_id="dirty", manifest=manifest)


# ===== HIGH D — the release path measures for itself =======================

def test_the_release_api_has_no_parameter_for_a_supplied_digest():
    """CALLER_SUPPLIED_MEASUREMENT: `{"state":"released","releasable":true}`.

    The red-team echoed the digests out of the decision request back into the
    gate. The release path closes that by construction: there is nowhere to
    put a digest.
    """
    import inspect

    supplied = set(inspect.signature(authorise).parameters)
    assert supplied == {"store", "request_message_id", "workdir"}
    assert not any("sha256" in name for name in supplied)


def test_release_derives_the_measurements_itself(store, room, target,
                                                 consequential):
    approve(store, consequential)
    result = authorise(store, consequential["request_id"],
                       workdir=target["path"])
    assert result["authorised"] is True
    assert result["derived"]["measured_by"] == "release.authorise"
    assert result["derived"]["snapshot_sha256"] == \
        consequential["action"]["binding"]["snapshot_sha256"]
    assert result["executor"] is None, "nothing here executes anything"


def test_echoed_digests_do_not_release_when_the_tree_has_moved(
        store, room, target, consequential):
    """The exact red-team move, against the authoritative path this time."""
    approve(store, consequential)
    bound = consequential["action"]["binding"]

    # The advisory diagnostic still believes what it is told.
    echoed = evaluate_gate(
        store, consequential["request_id"],
        snapshot_sha256=bound["snapshot_sha256"],
        supervisor_context_sha256=bound["supervisor_context_sha256"])
    assert echoed["releasable"] is True
    assert echoed["advisory"] is True, "and says so"

    # The tree moves. The release path measures, so it refuses.
    (target["path"] / "app.py").write_text("VALUE = 99\n", encoding="utf-8")
    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_stale"


def test_an_unreviewed_message_after_the_cutoff_blocks_release(
        store, room, target, consequential):
    approve(store, consequential)
    assert authorise(store, consequential["request_id"],
                     workdir=target["path"])["authorised"]

    room.post(thread_id="t1", type="claim", body={"text": "something new"})
    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_unreviewed"
    assert len(caught.value.report["unreviewed_since_cutoff"]) == 1


def test_no_approval_means_no_authorisation(store, target, consequential):
    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_no_decision"


# ===== HIGH M — the project binding is mandatory and checked ===============

def test_a_consequential_action_must_bind_a_project(room):
    from agent_room.errors import SchemaError

    action = {
        "action_id": "activate-agent-room-transport",
        "scope": "x", "consequential": True,
        "parameters": dict(ACTION_SAMPLES["activate-agent-room-transport"]),
        "binding": {"snapshot_sha256": "a" * 64,
                    "supervisor_context_sha256": "b" * 64},
    }
    with pytest.raises(SchemaError, match="project is mandatory"):
        room.post(thread_id="t1", type="decision_request", body={"text": "x"},
                  human_approval_required=True, action=action)


def test_an_approval_for_one_commit_does_not_release_another(
        store, room, target, consequential):
    approve(store, consequential)
    git(target["path"], "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "--allow-empty", "-m", "the world moved on")

    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_wrong_target"


def test_an_approval_does_not_release_in_a_different_repository(
        store, room, target, consequential, tmp_path):
    """An approval for repo A must never release the same action in repo B."""
    approve(store, consequential)
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q", "-b", "work")
    configure_identity(other)
    (other / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    git(other, "add", "-A")
    git(other, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "look-alike")

    with pytest.raises((ReleaseBlocked, SnapshotError)):
        authorise(store, consequential["request_id"], workdir=other)


# ===== HIGH I — one-shot actions and receipts ==============================

def test_a_reserved_action_cannot_be_authorised_again(store, room, target,
                                                      consequential):
    """APPROVAL_REUSABLE: `{"first": true, "second": true}`."""
    approve(store, consequential)
    reserved = reserve(store, consequential["request_id"],
                       workdir=target["path"])
    assert reserved["receipt"]["receipt_status"] == "uncertain"

    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_unresolved_execution"


def test_a_completed_action_stays_consumed(store, room, target, consequential):
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    reconcile(store, consequential["request_id"], status="executed",
              result={"branch": "agent-room", "created": True})

    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_consumed"
    assert "a retry needs a new human decision" in \
        " ".join(caught.value.report["reasons"])


def test_a_failed_action_also_consumes_the_nonce(store, room, target,
                                                 consequential):
    """One-shot means one-shot; a retry is a new decision, not a second use."""
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    reconcile(store, consequential["request_id"], status="failed",
              result={"error": "push rejected"})

    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=target["path"])
    assert caught.value.report["state"] == "blocked_consumed"


def test_reconciling_with_uncertain_is_refused(store, room, target,
                                               consequential):
    from agent_room.release import ReleaseError

    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    with pytest.raises(ReleaseError, match="leave the action unresolved"):
        reconcile(store, consequential["request_id"], status="uncertain",
                  result={})


def test_no_agent_surface_can_author_an_execution_receipt(store, room):
    from agent_room.errors import ForbiddenOperation
    from agent_room.participant import AGENT_MESSAGE_TYPES

    assert "execution_receipt" not in AGENT_MESSAGE_TYPES
    with pytest.raises(ForbiddenOperation):
        room.post(thread_id="t1", type="execution_receipt",
                  body={"text": "I did it"})


def test_the_release_module_performs_no_side_effect():
    """Structural: there is no executor here, by inspection of the source."""
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "agent_room" / "release.py").read_text(encoding="utf-8")
    for forbidden in ("subprocess", "run_bounded", "os.system", "push(",
                      "shutil"):
        assert forbidden not in source, (
            f"release.py mentions {forbidden!r}; it must contain no executor"
        )


# ===== Git / process environment hygiene ===================================

def test_an_alternates_file_blocks_verification(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    alternates = store.workdir / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text("/tmp/somewhere-else/objects\n", encoding="utf-8")

    with pytest.raises(Exception, match="alternate object directories"):
        store.verify_store()


def test_snapshot_refuses_a_checkout_with_replacement_refs(target):
    repo = target["path"]
    git(repo, "replace", "--graft", target["head"])
    with pytest.raises(SnapshotError, match="replacement refs"):
        snapshot_manifest(repo, target["base"])


def test_dangerous_environment_variables_are_stripped(monkeypatch):
    for name in ("GIT_DIR", "PYTHONPATH", "LD_PRELOAD", "BASH_ENV",
                 "PYTHONSTARTUP", "NODE_OPTIONS"):
        monkeypatch.setenv(name, "/tmp/evil")
    env = sanitised_env()
    assert not [k for k in env if k.startswith(("GIT_", "PYTHON", "LD_"))]
    assert "BASH_ENV" not in env and "NODE_OPTIONS" not in env


def test_a_hostile_git_dir_does_not_redirect_the_store(store, room, monkeypatch,
                                                       tmp_path):
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    git(decoy, "init", "-q", "-b", "agent-room")
    room.post(thread_id="t1", type="observation", body={"text": "real"})
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(decoy))

    assert store.verify_store() == 1, "verification stayed in the real room"


def test_store_commands_disable_hooks(store, room):
    hooks = store.workdir / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    marker = store.workdir.parent / "hook-ran"
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)

    room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert not marker.exists(), "a hook in the room checkout must not run"


# ===== resource limits =====================================================

def test_an_oversize_body_fails_before_the_commit(store, room):
    with pytest.raises(LimitExceeded, match="body.text"):
        room.post(thread_id="t1", type="observation",
                  body={"text": "x" * (MAX_BODY_TEXT_CHARS + 1)})
    assert store.verify_store() == 0, "nothing was committed"


def test_too_much_evidence_fails_before_the_commit(store, room):
    evidence = [{"kind": "external", "url": f"https://example.com/{i}"}
                for i in range(MAX_EVIDENCE_ITEMS + 1)]
    with pytest.raises(LimitExceeded, match="evidence"):
        room.post(thread_id="t1", type="evidence", body={"text": "x"},
                  evidence=evidence)
    assert store.verify_store() == 0


def test_an_oversize_envelope_fails_at_the_store_boundary(store, room):
    from agent_room import limits

    envelope = canonical.seal(room.build_envelope(
        thread_id="t1", type="observation", body={"text": "x" * 1024}))
    original = limits.MAX_ENVELOPE_BYTES
    try:
        limits.MAX_ENVELOPE_BYTES = 128
        with pytest.raises(LimitExceeded, match="canonical envelope"):
            store.append(envelope)
    finally:
        limits.MAX_ENVELOPE_BYTES = original
    assert store.verify_store() == 0


def test_a_thread_is_bounded_before_a_model_is_invoked(store, room, monkeypatch):
    from agent_room import limits
    from agent_room.claude_participant import ClaudeParticipant

    target = room.post(thread_id="t1", type="question", body={"text": "?"},
                       recipient={"agent": "claude-code"})

    def explode(prompt):
        raise AssertionError("the model must not be invoked")

    adapter = ClaudeParticipant(room, explode)
    monkeypatch.setattr(limits, "MAX_THREAD_MESSAGES", 0)
    with pytest.raises(LimitExceeded, match="messages"):
        adapter.run_turn(target["message_id"])


# ===== S2 boundary, stated rather than implied =============================

def test_RAW_GIT_HUMAN_FORGERY(store, room, target, consequential):
    """RAW_GIT_HUMAN_FORGERY: `{"releasable": true, "state": "released"}`.

    **This test used to assert that the attack worked.** It was the named S2
    blocker: capability separation stopped an agent *surface* from authoring a
    decision, but said nothing about someone who could write to the Git
    remote, because `sender.agent` was a string in a file.

    S2 inverted it. The forged approval is still perfectly well-formed and
    still correctly hashed; it simply carries no signature by the pinned human
    credential, so the read path refuses it and the whole store fails closed
    rather than releasing on it.
    """
    from agent_room.auth import UnauthenticatedMessage
    from agent_room.decision import binding_digest

    described = HumanDecisionAuthority(store).describe(consequential["request_id"])
    record = {
        "decision_schema_version": 1,
        "decision_id": "forged-by-raw-git",
        "decision": "approve",
        "decided_at": "2026-09-23T12:00:00Z",
        "request_message_id": described["request_message_id"],
        "request_envelope_sha256": described["request_envelope_sha256"],
        "action_id": described["action_id"],
        "action_scope": described["action_scope"],
        "consequential": described["consequential"],
        "parameters": described["parameters"],
        "binding": described["binding"],
    }
    record["decision_binding_sha256"] = binding_digest(record)
    envelope = canonical.seal({
        "schema_version": 1, "message_id": uuid7(),
        "timestamp": "2026-09-23T12:00:00Z",
        "sender": {"agent": "human"}, "recipient": {"broadcast": True},
        "project": {}, "thread_id": "t1", "type": "approval",
        "parent_id": described["request_message_id"],
        "body": {"text": "forged"}, "evidence": [], "status": "open",
        "reply_requested": False, "human_approval_required": False,
        "decision": record,
    })
    rel = store.message_path("t1", envelope["message_id"])
    raw_commit(store.workdir, rel, canonical.canonical_text(envelope), "forged")

    with pytest.raises(UnauthenticatedMessage, match="a name is a claim"):
        authorise(store, consequential["request_id"], workdir=target["path"])
    with pytest.raises(UnauthenticatedMessage):
        store.verify_store()


# ===== tooling stays closed ================================================

def test_serena_and_graphify_remain_unavailable():
    assert QUALIFIED_PROFILES == ("none",)
    for profile in ("serena", "graphify", "serena+graphify"):
        with pytest.raises(ToolProfileUnavailable):
            resolve(profile)


# ===========================================================================
# S1 corrective pass — supervisor findings after 258ac092…
# ===========================================================================

# ----- S1-C1: repository identity is derived, not copied -------------------

def test_SAME_COMMIT_WRONG_REPOSITORY(store, room, target, consequential,
                                      tmp_path):
    """An approval for one repository must not release another that happens
    to contain the same commit.

    The earlier regression was too weak: its second repository also had a
    different commit, so the commit check alone caught it. A commit can be
    fetched into any repository, so the commit proves nothing about identity.
    """
    approve(store, consequential)

    impostor = tmp_path / "impostor"
    subprocess.run(["git", "clone", "-q", str(target["path"]), str(impostor)],
                   check=True, capture_output=True)
    configure_identity(impostor)
    git(impostor, "remote", "set-url", "origin",
        "https://github.com/attacker/cek.git")
    git(impostor, "checkout", "-q", "work")

    assert git(impostor, "rev-parse", "HEAD").strip() == target["head"], (
        "the exploit needs the same commit in both repositories"
    )
    assert authorise(store, consequential["request_id"],
                     workdir=target["path"])["authorised"] is True

    with pytest.raises(ReleaseBlocked) as caught:
        authorise(store, consequential["request_id"], workdir=impostor)
    report = caught.value.report
    assert report["state"] == "blocked_wrong_repository"
    assert report["observed"]["repo"] == "github.com/attacker/cek"
    assert report["observed"]["source"] == "git-remote-url"


def test_the_observed_repository_is_never_copied_from_the_binding(
        store, room, target, consequential):
    approve(store, consequential)
    result = authorise(store, consequential["request_id"],
                       workdir=target["path"])
    observed = result["derived"]["project"]
    assert observed["repo"] == "github.com/pr0dus/cek", "derived, with its host"
    assert observed["repo"] != consequential["action"]["binding"]["project"]["repo"]
    assert observed["source"] == "git-remote-url"


def test_a_checkout_with_no_remote_fails_closed(store, room, target,
                                                consequential):
    approve(store, consequential)
    git(target["path"], "remote", "remove", "origin")
    with pytest.raises(RepositoryIdentityError, match="no configured remote"):
        authorise(store, consequential["request_id"], workdir=target["path"])


def test_an_ambiguous_repository_identity_fails_closed(store, room, target,
                                                       consequential):
    approve(store, consequential)
    git(target["path"], "remote", "remove", "origin")
    git(target["path"], "remote", "add", "one", "https://github.com/a/cek.git")
    git(target["path"], "remote", "add", "two", "https://github.com/b/cek.git")
    with pytest.raises(RepositoryIdentityError, match="ambiguous"):
        authorise(store, consequential["request_id"], workdir=target["path"])


def test_a_bare_repository_name_is_not_an_identity():
    with pytest.raises(RepositoryIdentityError, match="owner/name"):
        identity_matches("cek", "github.com/pr0dus/cek")


@pytest.mark.parametrize("url,identity", [
    ("https://github.com/pr0dus/cek.git", "github.com/pr0dus/cek"),
    ("git@github.com:pr0dus/cek.git", "github.com/pr0dus/cek"),
    ("ssh://git@github.com/pr0dus/cek/", "github.com/pr0dus/cek"),
    ("https://GitHub.com/pr0dus/cek", "github.com/pr0dus/cek"),
])
def test_equivalent_remote_spellings_are_one_identity(url, identity):
    assert _normalise_remote_url(url) == identity
    assert identity_matches("pr0dus/cek", identity)


def test_a_local_clone_does_not_inherit_a_hosted_identity(tmp_path, target):
    local = tmp_path / "local"
    subprocess.run(["git", "clone", "-q", str(target["path"]), str(local)],
                   check=True, capture_output=True)
    derived = canonical_repo_identity(local)
    assert derived["identity"].startswith("path:")
    assert not identity_matches("pr0dus/cek", derived["identity"])


# ----- S1-C2 / C3: one-shot transitions are atomic -------------------------

def race(fn, workers: int = 2):
    """Run `fn` on N threads released together, and collect what each got."""
    barrier = threading.Barrier(workers)
    results, errors = [], []

    def attempt(index):
        barrier.wait()
        try:
            results.append(fn(index))
        except Exception as exc:                    # noqa: BLE001 - recorded
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    return results, errors


def test_CONCURRENT_RESERVE(store, room, target, consequential):
    """At most one reservation may succeed for a one-shot nonce.

    The check and the consuming write used to be separate: both callers could
    read "unconsumed" before either wrote. They now share one critical
    section, and `flock` is per open file description, so two store objects in
    one process exclude each other exactly as two processes would.
    """
    approve(store, consequential)

    def attempt(_index):
        own = GitMessageStore(store.workdir, branch=store.branch,
                              trust=store.trust)
        return reserve(own, consequential["request_id"],
                       workdir=target["path"])

    results, errors = race(attempt)
    assert len(results) == 1, f"two reservations succeeded: {results}"
    assert len(errors) == 1 and isinstance(errors[0], (ReleaseBlocked, ReleaseError))

    receipts = [m for m in store.thread_messages("t1")
                if m["type"] == "execution_receipt"]
    assert len(receipts) == 1, "exactly one reservation receipt is durable"
    assert receipts[0]["receipt"]["status"] == "uncertain"
    assert store.verify_store() > 0


def test_a_duplicate_reservation_is_refused(store, room, target, consequential):
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    with pytest.raises(ReleaseBlocked) as caught:
        reserve(store, consequential["request_id"], workdir=target["path"])
    # `authorise` inside `reserve` refuses first: the outstanding reservation
    # is already visible to it, so the second attempt never reaches the
    # transition check. Either refusal is correct; this one is earlier.
    assert caught.value.report["state"] == "blocked_unresolved_execution"


def test_SECOND_TERMINAL_RECONCILE(store, room, target, consequential):
    """`uncertain -> executed` settles it. There is no transition out."""
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    reconcile(store, consequential["request_id"], status="executed",
              result={"created": True})

    with pytest.raises(ReleaseBlocked, match="already settled"):
        reconcile(store, consequential["request_id"], status="failed",
                  result={"second": "attempt"})
    with pytest.raises(ReleaseBlocked, match="already settled"):
        reconcile(store, consequential["request_id"], status="executed",
                  result={"same": "again"})


def test_reconcile_after_failed_is_also_refused(store, room, target,
                                                consequential):
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])
    reconcile(store, consequential["request_id"], status="failed",
              result={"error": "push rejected"})
    with pytest.raises(ReleaseBlocked, match="already settled"):
        reconcile(store, consequential["request_id"], status="executed",
                  result={"actually": "it worked"})


def test_CONCURRENT_RECONCILE(store, room, target, consequential):
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])

    def attempt(index):
        own = GitMessageStore(store.workdir, branch=store.branch,
                              trust=store.trust)
        return reconcile(own, consequential["request_id"], status="executed",
                         result={"worker": index})

    results, errors = race(attempt)
    assert len(results) == 1, f"two terminal receipts were written: {results}"
    assert len(errors) == 1

    terminal = [m["receipt"] for m in store.thread_messages("t1")
                if m["type"] == "execution_receipt"
                and m["receipt"]["status"] in ("executed", "failed")]
    assert len(terminal) == 1


def test_reconcile_without_a_reservation_is_refused(store, room, target,
                                                    consequential):
    approve(store, consequential)
    with pytest.raises(ReleaseError, match="never reserved"):
        reconcile(store, consequential["request_id"], status="executed",
                  result={})


def test_an_impossible_receipt_history_fails_verification(store, room, target,
                                                          consequential,
                                                          signers):
    """Two reservations for one nonce are not a history to read past.

    The write path cannot produce this; a Git writer can. Verification refuses
    it rather than reading through evidence that the action was released twice.
    """
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])

    duplicate = [m for m in store.thread_messages("t1")
                 if m["type"] == "execution_receipt"][0]
    forged = {k: v for k, v in duplicate.items()
              if k not in (canonical.DIGEST_FIELD, "auth")}
    forged["message_id"] = uuid7()
    forged["receipt"] = dict(forged["receipt"], receipt_id="rx-forged")
    # Signed with the real release-recorder key: the lifecycle invariant has
    # to hold even against a correctly authenticated impossible history, which
    # is what a compromised host key would produce.
    sealed = canonical.seal(sign_envelope(
        forged, signers["release-recorder"], room_id=store.room_id()))
    raw_commit(store.workdir, store.message_path("t1", sealed["message_id"]),
               canonical.canonical_text(sealed), "second reservation")

    with pytest.raises(ReceiptStateError, match="second reservation"):
        store.verify_store()


def test_a_terminal_receipt_without_a_reservation_fails_verification(
        store, room, target, consequential, signers):
    approve(store, consequential)
    request = store.resolve_message(consequential["request_id"])
    receipt = {
        "receipt_schema_version": 1, "receipt_id": "rx-orphan",
        "action_nonce": request["action"]["binding"]["action_nonce"],
        "action_id": request["action"]["action_id"],
        "request_message_id": request["message_id"],
        "decision_id": "hd-s1", "status": "executed",
        "recorded_at": "2026-09-24T09:00:00Z", "result": {},
    }
    sealed = canonical.seal(sign_envelope({
        "schema_version": 1, "message_id": uuid7(),
        "timestamp": "2026-09-24T09:00:00Z",
        "sender": {"agent": "release-recorder"}, "recipient": {"broadcast": True},
        "project": {}, "thread_id": "t1", "type": "execution_receipt",
        "parent_id": request["message_id"], "body": {"text": "orphan"},
        "evidence": [], "status": "open", "reply_requested": False,
        "human_approval_required": False, "receipt": receipt,
    }, signers["release-recorder"], room_id=store.room_id()))
    raw_commit(store.workdir, store.message_path("t1", sealed["message_id"]),
               canonical.canonical_text(sealed), "orphan terminal receipt")

    with pytest.raises(ReceiptStateError, match="never reserved"):
        store.verify_store()


# ----- S1-C4: authorise is not permission to act ---------------------------

def test_AUTHORISE_WITHOUT_RESERVE_IS_NOT_ACTION_PERMISSION(
        store, room, target, consequential):
    """The old wording told the operator to act and then record it.

    Following it would have performed the real side effect while the nonce was
    still unconsumed — the exact window `reserve` exists to close.
    """
    approve(store, consequential)
    result = authorise(store, consequential["request_id"],
                       workdir=target["path"])

    assert result["action_permitted"] is False
    assert result["next_step"] == "release.reserve"
    assert "NOT PERMISSION TO ACT" in result["note"]
    assert "reserve" in result["note"]
    assert result["executor"] is None

    lowered = result["note"].lower()
    assert "carried out manually and then recorded" not in lowered, (
        "authorise must not instruct anyone to perform the action"
    )
    # And the nonce really is still free, which is why acting now is wrong.
    assert receipt_state(store, store.resolve_message(
        consequential["request_id"]))["consumed"] is False


def test_reserve_is_what_grants_the_manual_step(store, room, target,
                                                consequential):
    approve(store, consequential)
    reserved = reserve(store, consequential["request_id"],
                       workdir=target["path"])
    authorisation = reserved["authorisation"]
    assert authorisation["action_permitted"] is True
    assert "perform the action" in authorisation["next_step"]
    assert reserved["receipt"]["receipt_status"] == "uncertain"


def test_the_cli_authorise_output_says_it_is_not_permission(store, room, target,
                                                            consequential,
                                                            capsys, tmp_path):
    from agent_room.cli import build_parser, main

    approve(store, consequential)
    policy_path = tmp_path / "trust.json"
    store.trust.save(policy_path)
    code = main(["--repo", str(store.workdir), "--participant", "coordinator",
                 "--trust-policy", str(policy_path),
                 "release-authorise", "--request-id",
                 consequential["request_id"], "--target", str(target["path"])])
    assert code == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["action_permitted"] is False
    assert "NOT PERMISSION TO ACT" in emitted["note"]

    # The help text is part of the operator contract too, so a future edit
    # cannot quietly reintroduce "go ahead and do it" wording.
    choices = build_parser()._subparsers._group_actions[0].choices
    listing = {name: sub._defaults for name, sub in choices.items()}
    assert "release-authorise" in listing and "release-reserve" in listing

    help_lines = build_parser().format_help()
    assert "NOT PERMISSION TO ACT" in help_lines
    assert "release-reserve before acting" in help_lines


# ----- S1-C5: an isolated proof binds the commit it claims -----------------

def test_STAGED_STATE_NOT_BOUND_BY_ARCHIVE(target, tmp_path):
    """A staged change is not in the commit, so the archive silently drops it."""
    repo = target["path"]
    (repo / "app.py").write_text("VALUE = 'staged'\n", encoding="utf-8")
    git(repo, "add", "app.py")

    manifest = snapshot_manifest(repo, target["base"])
    assert manifest["counts"]["staged_vs_head"] == 1, "staged, not committed"
    assert manifest["counts"]["unstaged"] == 0
    assert manifest["counts"]["untracked"] == 0

    with pytest.raises(ProofError, match="staged change counts"):
        run_isolated_proof(["python3", "-c", "pass"], repo=repo,
                           commit=target["head"], run_dir=tmp_path / "runs",
                           proof_id="staged", manifest=manifest)


def test_TAMPERED_MANIFEST(target, tmp_path):
    manifest = snapshot_manifest(target["path"], target["base"])
    assert manifest["counts"]["staged_vs_head"] == 0, "clean before tampering"
    # Claim the tree was clean of ignored state when it was measured. Only
    # recomputing the digest catches it — which is why the manifest is
    # verified before anything it says is believed.
    manifest["ignored"]["count"] = 99
    with pytest.raises(SnapshotError, match="digest mismatch"):
        run_isolated_proof(["python3", "-c", "pass"], repo=target["path"],
                           commit=target["head"], run_dir=tmp_path / "runs",
                           proof_id="tampered", manifest=manifest)


def test_a_contradictory_snapshot_digest_is_refused(target, tmp_path):
    manifest = snapshot_manifest(target["path"], target["base"])
    with pytest.raises(ProofError, match="contradicts the manifest"):
        run_isolated_proof(["python3", "-c", "pass"], repo=target["path"],
                           commit=target["head"], run_dir=tmp_path / "runs",
                           proof_id="contra", manifest=manifest,
                           snapshot_sha256="f" * 64)


def test_a_snapshot_digest_without_its_manifest_is_refused(target, tmp_path):
    with pytest.raises(ProofError, match="binds nothing checkable"):
        run_isolated_proof(["python3", "-c", "pass"], repo=target["path"],
                           commit=target["head"], run_dir=tmp_path / "runs",
                           proof_id="bare", snapshot_sha256="f" * 64)


def test_a_verified_manifest_supplies_the_proof_binding(target, tmp_path):
    manifest = snapshot_manifest(target["path"], target["base"])
    record = run_isolated_proof(["python3", "-c", "print('ok')"],
                                repo=target["path"], commit=target["head"],
                                run_dir=tmp_path / "runs", proof_id="derived",
                                manifest=manifest)
    assert record["snapshot_sha256"] == manifest["manifest_sha256"]


@pytest.mark.parametrize("revision", ["HEAD", "work", "HEAD~1", "work^{}"])
def test_revision_syntax_cannot_bind_an_isolated_proof(target, tmp_path,
                                                       revision):
    with pytest.raises(ProofError, match="full Git object id"):
        run_isolated_proof(["python3", "-c", "pass"], repo=target["path"],
                           commit=revision, run_dir=tmp_path / "runs",
                           proof_id="rev")


def test_a_blob_id_is_not_a_commit(target, tmp_path):
    blob = git(target["path"], "rev-parse", "HEAD:app.py").strip()
    with pytest.raises(ProofError, match="not a commit object"):
        run_isolated_proof(["python3", "-c", "pass"], repo=target["path"],
                           commit=blob, run_dir=tmp_path / "runs",
                           proof_id="blob")


# ----- S1-C6: output is bounded while it is produced -----------------------

FLOOD = "import sys\nwhile True: sys.stdout.write('x' * 4096)\n"


def test_PROOF_OUTPUT_LIMIT(target, tmp_path, monkeypatch):
    """`MAX_PROOF_STREAM_BYTES` only trimmed what was stored; the whole stream
    had already been buffered in memory by `communicate()`."""
    import agent_room.proof as proof_mod

    monkeypatch.setattr(proof_mod, "MAX_PROOF_STREAM_BYTES", 64 * 1024)
    record = run_proof(["python3", "-c", FLOOD], cwd=target["path"],
                       run_dir=tmp_path / "runs", proof_id="flood", timeout=60)

    assert record["status"] == "output_limited"
    assert record["output_limited"] is True
    assert record["teardown"] in ("terminated", "killed")
    assert record["stdout_bytes"] <= 64 * 1024 + 65536, "bounded capture"
    assert record["digest_covers"] == "captured-prefix", (
        "the digest must not claim to cover output that was never accepted"
    )
    assert os.path.getsize(record["artifact_path"]) < 1024 * 1024


def test_a_flooding_proof_never_buffers_the_whole_stream(target, tmp_path):
    """The bound is applied by the runner, independently of the proof layer."""
    result = run_bounded(["python3", "-c", FLOOD], cwd=target["path"],
                         timeout=60, env=sanitised_env(),
                         max_output_bytes=32 * 1024)
    assert result.output_limited is True
    assert result.limited_streams == ("stdout",)
    assert len(result.stdout) <= 32 * 1024 + 65536
    assert result.teardown in ("terminated", "killed")


def test_a_flooding_claude_turn_is_refused(tmp_path, monkeypatch):
    import agent_room.claude_participant as claude_mod

    monkeypatch.setattr(claude_mod, "MAX_MODEL_OUTPUT_BYTES", 32 * 1024)
    flood = tmp_path / "claude"
    flood.write_text("#!/bin/sh\nwhile :; do printf 'x%.0s' $(seq 1 1000); done\n",
                     encoding="utf-8")
    flood.chmod(0o755)
    with pytest.raises(ClaudeAdapterError, match="more than"):
        ClaudeInvoker(str(flood), timeout=60)("prompt")


def test_a_flooding_codex_turn_is_refused(tmp_path, monkeypatch):
    import agent_room.codex_participant as codex_mod

    monkeypatch.setattr(codex_mod, "MAX_MODEL_OUTPUT_BYTES", 32 * 1024)
    flood = tmp_path / "codex"
    flood.write_text("#!/bin/sh\nwhile :; do printf 'x%.0s' $(seq 1 1000); done\n",
                     encoding="utf-8")
    flood.chmod(0o755)
    with pytest.raises(CodexAdapterError, match="more than"):
        CodexInvoker(str(flood), timeout=60)("prompt")


def test_an_oversize_codex_result_file_is_refused_before_reading(tmp_path,
                                                                 monkeypatch):
    """The structured result arrives as a file, so the stream cap never saw it."""
    import agent_room.codex_participant as codex_mod

    monkeypatch.setattr(codex_mod, "MAX_MODEL_OUTPUT_BYTES", 4096)
    script = tmp_path / "codex"
    script.write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = '--output-last-message' ]; then out=$2; fi\n"
        "  shift\n"
        "done\n"
        "head -c 200000 /dev/zero | tr '\\\\0' 'y' > \"$out\"\n",
        encoding="utf-8")
    script.chmod(0o755)
    with pytest.raises(LimitExceeded, match="codex final message"):
        CodexInvoker(str(script), timeout=60)("prompt")


# ----- S1-C7: a detached descendant escapes the group ----------------------

def test_DETACHED_CHILD_TIMEOUT(tmp_path):
    """**This test asserts that the escape works.**

    `killpg` signals a process group. A descendant that calls `setsid()` is by
    definition no longer in it, so it survives — measured here rather than
    assumed in either direction. Closing this needs a cgroup or a PID
    namespace, which belongs to the S3 systemd transport boundary; until then
    the S1 guarantee is narrowed to descendants that remain in the group, and
    `docs/AGENT_ROOM_SECURITY.md` says so.

    S3 must invert this test.
    """
    launcher = tmp_path / "detach.py"
    pidfile = tmp_path / "escapee.pid"
    launcher.write_text(textwrap.dedent(f"""\
        import subprocess, time
        child = subprocess.Popen(["sleep", "90"], start_new_session=True)
        open({str(pidfile)!r}, "w").write(str(child.pid))
        time.sleep(90)
        """), encoding="utf-8")

    result = run_bounded(["python3", str(launcher)], timeout=2,
                         env=sanitised_env())
    assert result.timed_out and result.teardown in ("terminated", "killed")
    escapee = int(pidfile.read_text())
    try:
        time.sleep(1.0)
        assert alive(escapee), (
            "if this now fails, the escape is closed and the S1 guarantee and "
            "the security document should be widened to match"
        )
        assert os.getpgid(escapee) == escapee, "it is its own group leader"
    finally:
        try:
            os.kill(escapee, 9)
        except ProcessLookupError:
            pass


def test_an_ordinary_descendant_is_still_killed(tmp_path, target):
    """The narrowed guarantee, stated as a test: same group, still dies."""
    script = tmp_path / "launcher.py"
    script.write_text(CHILD_LAUNCHER, encoding="utf-8")
    pidfile = tmp_path / "ordinary.pid"
    record = run_proof(["python3", str(script), str(pidfile)],
                       cwd=target["path"], run_dir=tmp_path / "runs",
                       proof_id="ordinary", timeout=2)
    assert record["status"] == "timeout"
    assert wait_gone(int(pidfile.read_text()))


# ----- S1 final corrective: writer-lock re-entrancy is thread-owned --------

def test_SAME_STORE_CONCURRENT_RESERVE(store, room, target, consequential):
    """Two threads, **one** store instance, one one-shot nonce.

    The first re-entrant lock counted depth on the store alone, so a second
    thread sharing that store saw a non-zero depth, concluded it was a nested
    call, and entered the critical section the first thread was holding. The
    earlier concurrency regressions used separate store objects and so never
    touched this path.
    """
    approve(store, consequential)

    def attempt(_index):
        return reserve(store, consequential["request_id"],
                       workdir=target["path"])

    results, errors = race(attempt)
    assert len(results) == 1, f"two reservations succeeded: {results}"
    assert len(errors) == 1 and isinstance(errors[0], (ReleaseBlocked, ReleaseError))

    receipts = [m["receipt"] for m in store.thread_messages("t1")
                if m["type"] == "execution_receipt"]
    assert len(receipts) == 1, "exactly one reservation is durable"
    assert receipts[0]["status"] == "uncertain"
    assert store.verify_store() > 0


def test_SAME_STORE_CONCURRENT_RECONCILE(store, room, target, consequential):
    approve(store, consequential)
    reserve(store, consequential["request_id"], workdir=target["path"])

    def attempt(index):
        return reconcile(store, consequential["request_id"], status="executed",
                         result={"worker": index})

    results, errors = race(attempt)
    assert len(results) == 1, f"two terminal receipts were written: {results}"
    assert len(errors) == 1

    terminal = [m["receipt"] for m in store.thread_messages("t1")
                if m["type"] == "execution_receipt"
                and m["receipt"]["status"] in ("executed", "failed")]
    assert len(terminal) == 1
    assert store.verify_store() > 0


def test_a_second_thread_cannot_enter_while_the_owner_holds_the_lock(store):
    """The escape itself, with the owner deliberately holding the lock.

    Ordering is the assertion: the intruder's entry must fall after the
    owner's exit, not between its entry and exit.
    """
    store.lock_timeout = 5.0
    sequence, ready = [], threading.Event()

    def owner():
        with store.writer_lock():
            sequence.append("owner-in")
            ready.set()
            time.sleep(1.0)
            sequence.append("owner-out")

    def intruder():
        ready.wait(timeout=10)
        time.sleep(0.2)
        with store.writer_lock():
            sequence.append("intruder-in")

    threads = [threading.Thread(target=owner), threading.Thread(target=intruder)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sequence == ["owner-in", "owner-out", "intruder-in"], sequence


def test_a_second_thread_times_out_rather_than_entering(store):
    """Bounded, not indefinite: the waiter fails cleanly on a held lock."""
    store.lock_timeout = 0.4
    ready, outcome = threading.Event(), []

    def owner():
        with store.writer_lock():
            ready.set()
            time.sleep(2.0)

    def waiter():
        ready.wait(timeout=10)
        try:
            with store.writer_lock():
                outcome.append("entered")
        except LockTimeout:
            outcome.append("timed-out")

    threads = [threading.Thread(target=owner), threading.Thread(target=waiter)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert outcome == ["timed-out"], outcome


def test_nesting_in_the_owning_thread_still_works(store, room):
    """Three deep, then a real append inside - the reason nesting exists."""
    with store.writer_lock():
        with store.writer_lock():
            with store.writer_lock():
                assert store._lock_depth == 3
                assert store._lock_owner == threading.get_ident()
            assert store._lock_depth == 2
        assert store._lock_depth == 1
    assert store._lock_depth == 0 and store._lock_owner is None

    with store.writer_lock():
        posted = room.post(thread_id="t1", type="observation",
                           body={"text": "written while nested"})
    assert store.read("t1", posted["message_id"])["type"] == "observation"


def test_the_lock_is_released_when_the_body_raises(store):
    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with store.writer_lock():
            with store.writer_lock():
                raise Boom()
    assert store._lock_depth == 0 and store._lock_owner is None
    with store.writer_lock():
        assert store._lock_depth == 1


def test_re_entrancy_is_never_inherited_by_another_thread(store):
    """Unit-level: the depth counter alone must not grant entry."""
    ready, seen = threading.Event(), []

    def owner():
        with store.writer_lock():
            ready.set()
            time.sleep(0.6)

    def observer():
        ready.wait(timeout=10)
        # Depth is non-zero, but it belongs to someone else.
        seen.append((store._lock_depth,
                     store._lock_owner == threading.get_ident()))

    threads = [threading.Thread(target=owner), threading.Thread(target=observer)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert seen == [(1, False)], seen
