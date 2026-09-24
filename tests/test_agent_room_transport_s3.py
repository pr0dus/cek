"""Issue #13 Stage S3: the narrow transport, and what it refuses.

The existing bridge takes an argv and runs it. Every test here asks the same
question of the replacement in a different way: can a writer to the untrusted
control repository express something other than the three operations — a
command, a path, a signer, a human decision, a release, a model turn? The
answer has to be no by *schema*, not by filtering, which is why most of these
tests are about fields that simply have nowhere to go.

The control branch is hostile input by assumption. Its writer is in the threat
model, so these tests play that writer.
"""

import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.auth import Ed25519Signer
from agent_room.checkpoint import RollbackRejected, TrustCheckpoint, policy_digest
from agent_room.control_store import (
    MAX_PENDING_REQUESTS,
    MAX_REQUEST_BYTES,
    ControlAppendOnlyViolation,
    ControlError,
    ControlNamespaceViolation,
    ControlStore,
)
from agent_room.ids import uuid7
from agent_room.supervisor import PARTICIPANT as SUPERVISOR
from agent_room.supervisor import SupervisorBoundary
from agent_room.transport import (
    FORBIDDEN_RESPONSE_TYPES,
    OPERATIONS,
    REVIEWER_RESPONSE_TYPES,
    TransportConfig,
    TransportRefused,
    TransportWorker,
    validate_request,
)
from tests.conftest_agent_room import build_trust, configure_identity, git

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
UNIT = DEPLOY / "agent-room-transport.service"
PACKAGE = Path(__file__).resolve().parents[1] / "agent_room"


# ===== fixtures ============================================================

@pytest.fixture
def env(tmp_path):
    """A room awaiting supervisor input, a control queue, and a worker."""
    room_store = GitMessageStore.initialise(tmp_path / "room",
                                            branch="agent-room")
    configure_identity(room_store.workdir)
    policy, signers = build_trust(tmp_path / "keys", room_store)
    room_store.trust = policy

    claude = AgentRoom(room_store, "claude-code",
                       ParticipantCursor(tmp_path / "state", "claude-code"),
                       signer=signers["claude-code"])
    target = claude.post(thread_id="t1", type="question",
                         body={"text": "please review this"},
                         recipient={"agent": SUPERVISOR})

    policy_path = tmp_path / "trust.json"
    policy.save(policy_path)
    checkpoint = TrustCheckpoint.bootstrap(
        room_store, expected_genesis=room_store.room_id(),
        expected_trust_policy_sha256=policy_digest(policy),
        path=tmp_path / "checkpoint.json")

    control = ControlStore.initialise(tmp_path / "control",
                                      branch="agent-room-control")
    config = TransportConfig(
        room_workdir=str(room_store.workdir),
        control_workdir=str(control.workdir),
        trust_policy_path=str(policy_path),
        checkpoint_path=str(tmp_path / "checkpoint.json"),
        state_dir=str(tmp_path / "state"),
        signing_key_path=str(signers[SUPERVISOR].key_path),
        signing_key_id=signers[SUPERVISOR].key_id,
    )
    return {"room": room_store, "control": control, "config": config,
            "signers": signers, "target": target["message_id"],
            "claude": claude, "checkpoint": checkpoint, "tmp": tmp_path,
            "policy": policy}


def request_document(operation="status", params=None, **overrides):
    document = {
        "control_schema_version": 1,
        "request_id": uuid7(),
        "created_at": "2026-09-24T12:00:00Z",
        "operation": operation,
        "params": {} if params is None else params,
    }
    document.update(overrides)
    return document


def submit(env, document):
    env["control"].submit_request(document)
    return document["request_id"]


def run_worker(env):
    return TransportWorker(env["config"]).run()


def result_for(env, request_id):
    control = env["control"]
    history = control._history()
    path = f".agent-room-control/results/{request_id}.json"
    assert path in history, f"no result for {request_id}"
    return json.loads(control._blob(path, history[path]).decode())


def supervisor_messages(env):
    return [m for m in env["room"].thread_messages("t1")
            if m["sender"].get("agent") == SUPERVISOR]


def bound_response(env, response_type="observation", **extra):
    """A response document bound to the current context, as ChatGPT would send."""
    boundary = SupervisorBoundary(AgentRoom(
        env["room"], SUPERVISOR,
        ParticipantCursor(env["tmp"] / "export-state", SUPERVISOR),
        signer=env["signers"][SUPERVISOR]))
    packet = boundary.export(env["target"])
    response = {"type": response_type, "body": {"text": "reviewer content"}}
    response.update(extra)
    return {"packet_schema_version": packet["packet_schema_version"],
            "target_message_id": packet["target_message_id"],
            "context_sha256": packet["context_sha256"],
            "response": response}


# ===== the schema has nowhere to put a command =============================

@pytest.mark.parametrize("field,value", [
    ("command", "rm -rf /"),
    ("argv", ["bash", "-lc", "id"]),
    ("shell", True),
    ("cwd", "/home/pr0"),
])
def test_TRANSPORT_REJECTS_COMMAND_FIELD(env, field, value):
    """The bridge's entire capability, expressed as a field that does not exist."""
    with pytest.raises(TransportRefused, match="unknown fields"):
        validate_request(request_document(**{field: value}))


def test_TRANSPORT_REJECTS_ARGV(env):
    """Inside params, where a filtered design would have put an allowlist."""
    for params in ({"argv": ["sh", "-c", "id"]}, {"command": "id"},
                   {"exec": "python3"}):
        with pytest.raises(TransportRefused):
            validate_request(request_document("status", params))
        with pytest.raises(TransportRefused):
            validate_request(request_document("supervisor_export", params))


@pytest.mark.parametrize("params", [
    {"message_id": None, "repo": "/home/pr0/projects/cek"},
    {"message_id": None, "workdir": "/etc"},
    {"message_id": None, "trust_policy_path": "/tmp/mine.json"},
    {"message_id": None, "checkpoint_path": "/tmp/cp.json"},
    {"message_id": None, "branch": "main"},
    {"message_id": None, "remote": "git@evil:x/y"},
    {"message_id": None, "signing_key_path": "/tmp/k.pem"},
])
def test_TRANSPORT_REJECTS_PATH_OVERRIDE(env, params):
    """Every path the worker touches is service state; none is addressable."""
    with pytest.raises(TransportRefused, match="extra"):
        validate_request(request_document("supervisor_export", params))


@pytest.mark.parametrize("operation", [
    "human_decide", "human_prepare", "human_submit",
    "release_authorise", "release_reserve", "release_reconcile",
    "trust_update", "trust_rotate", "checkpoint_bootstrap",
    "claude_turn", "codex_turn", "proof", "post", "reply", "run_command",
])
def test_the_operation_allowlist_is_three_long(env, operation):
    """TRANSPORT_REJECTS_HUMAN_DECISION / _RELEASE / _TRUST_UPDATE /
    _MODEL_EXEC / _GENERIC_POST, all the same refusal."""
    with pytest.raises(TransportRefused, match="unknown operation"):
        validate_request(request_document(operation))
    assert operation not in OPERATIONS


def test_the_worker_records_a_refusal_without_any_side_effect(env):
    request_id = submit(env, request_document("run_command",
                                              {"argv": ["id"]}))
    before = env["room"].current_tip()
    summary = run_worker(env)

    assert summary["processed"] == 1
    result = result_for(env, request_id)
    assert result["status"] == "refused"
    assert "unknown operation" in result["detail"]["error"]
    assert env["room"].current_tip() == before, "the room did not move"


# ===== the transport is not a signing oracle ===============================

@pytest.mark.parametrize("kind", sorted(FORBIDDEN_RESPONSE_TYPES))
def test_TRANSPORT_REJECTS_CONSEQUENTIAL_SUPERVISOR_RESPONSE(env, kind):
    """The one place untrusted input becomes a signed message carries opinion,
    never authority."""
    document = bound_response(env, kind)
    with pytest.raises(TransportRefused, match="may not be"):
        validate_request(request_document("supervisor_import",
                                          {"response": document}))


def test_a_transported_response_may_not_summon_the_human_gate(env):
    document = bound_response(env, "observation", human_approval_required=True)
    with pytest.raises(TransportRefused, match="human_approval_required"):
        validate_request(request_document("supervisor_import",
                                          {"response": document}))


def test_a_transported_response_may_not_carry_an_action(env):
    document = bound_response(env, "observation",
                              action={"action_id": "activate-agent-room-transport"})
    with pytest.raises(TransportRefused, match="'action'"):
        validate_request(request_document("supervisor_import",
                                          {"response": document}))


@pytest.mark.parametrize("field", ["sender", "auth", "message_id", "thread_id",
                                   "parent_id", "recipient", "decision",
                                   "receipt"])
def test_TRANSPORT_FIXED_SIGNER(env, field):
    """Identity and placement are the service's, not the request's."""
    document = bound_response(env, "observation", **{field: "anything"})
    with pytest.raises(TransportRefused, match="identity"):
        validate_request(request_document("supervisor_import",
                                          {"response": document}))


def test_the_signer_comes_from_config_and_nothing_else(env):
    """A successful import is signed by the configured key, full stop."""
    request_id = submit(env, request_document(
        "supervisor_import", {"response": bound_response(env, "observation")}))
    run_worker(env)
    assert result_for(env, request_id)["status"] == "ok"

    posted = supervisor_messages(env)
    assert len(posted) == 1
    auth = posted[0]["auth"]
    assert auth["signer"] == SUPERVISOR
    assert auth["key_id"] == env["config"].signing_key_id
    assert auth["room_id"] == env["room"].room_id()
    assert posted[0]["type"] in REVIEWER_RESPONSE_TYPES


def test_TRANSPORT_CONTEXT_STALE(env):
    """A review of a thread that has since moved is refused, not forced."""
    document = bound_response(env, "observation")
    env["claude"].post(thread_id="t1", type="observation",
                       body={"text": "the thread moved on"})
    request_id = submit(env, request_document("supervisor_import",
                                              {"response": document}))
    run_worker(env)

    result = result_for(env, request_id)
    assert result["status"] == "failed"
    assert "StaleSupervisorContext" in result["detail"]["error_type"]
    assert supervisor_messages(env) == []


# ===== checkpoint before anything ==========================================

def test_TRANSPORT_CHECKPOINT_REJECTS_ROLLBACK(env):
    """A rolled-back room is not exported from, imported into, or reported on."""
    env["claude"].post(thread_id="t1", type="observation", body={"text": "b"})
    env["checkpoint"].accept(env["room"])
    advanced = env["checkpoint"].document["last_accepted_tip"]

    git(env["room"].workdir, "reset", "-q", "--hard", env["room"].room_id())
    submit(env, request_document("status"))
    summary = run_worker(env)

    # A synchronisation failure is not a per-request result: nothing about the
    # room can be trusted, so nothing is attempted and nothing is claimed.
    assert summary["lifecycle"]["status"] == "failed"
    assert summary["lifecycle"]["error_type"] == "RollbackRejected"
    assert summary["processed"] == 0
    reloaded = TrustCheckpoint.load(env["config"].checkpoint_path)
    assert reloaded.document["last_accepted_tip"] == advanced


def test_TRANSPORT_BAD_ROOM_SIGNATURE_BLOCKS_BEFORE_OPERATION(env):
    """An unsigned artifact on the room branch stops the worker at the gate."""
    forged = canonical.seal({
        "schema_version": 1, "message_id": uuid7(),
        "timestamp": "2026-09-24T12:00:00Z",
        "sender": {"agent": "codex"}, "recipient": {"broadcast": True},
        "project": {}, "thread_id": "t1", "type": "claim",
        "body": {"text": "unsigned"}, "evidence": [], "status": "open",
        "reply_requested": False, "human_approval_required": False})
    rel = env["room"].message_path("t1", forged["message_id"])
    path = env["room"].workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(forged), encoding="utf-8")
    git(env["room"].workdir, "add", "-f", "--", rel)
    git(env["room"].workdir, "commit", "-q", "-m", "forged")

    submit(env, request_document(
        "supervisor_export", {"message_id": env["target"]}))
    summary = run_worker(env)
    assert summary["lifecycle"]["status"] == "failed"
    assert "Unauthenticated" in summary["lifecycle"]["error_type"]
    assert summary["processed"] == 0, "no operation ran on unverified state"


# ===== replay, races, crash ================================================

def test_TRANSPORT_REQUEST_REPLAY(env):
    """An immutable request is processed at most once."""
    request_id = submit(env, request_document(
        "supervisor_import", {"response": bound_response(env, "observation")}))
    first = run_worker(env)
    assert first["processed"] == 1
    assert len(supervisor_messages(env)) == 1

    second = run_worker(env)
    assert second["processed"] == 0, "the result already exists"
    assert len(supervisor_messages(env)) == 1
    assert result_for(env, request_id)["status"] == "ok"


def test_a_duplicate_identical_request_is_idempotent(env):
    document = request_document("status")
    submit(env, document)
    again = env["control"].submit_request(document)
    assert again["status"] == "duplicate"


def test_the_same_request_id_with_different_content_fails(env):
    document = request_document("status")
    submit(env, document)
    from agent_room.control_store import ControlConflict

    changed = dict(document, created_at="2026-09-24T13:00:00Z")
    with pytest.raises(ControlConflict, match="immutable"):
        env["control"].submit_request(changed)


def test_TRANSPORT_IMPORT_CRASH_RECONCILES(env, monkeypatch):
    """Crash after the room mutation, before the result. Restart must not
    post the same supervisor response twice."""
    request_id = submit(env, request_document(
        "supervisor_import", {"response": bound_response(env, "observation")}))

    real_write = ControlStore.write_result
    crashed = {}

    def crash_once(self, rid, document):
        if not crashed:
            crashed["yes"] = True
            raise RuntimeError("worker died after mutating the room")
        return real_write(self, rid, document)

    monkeypatch.setattr(ControlStore, "write_result", crash_once)
    with pytest.raises(RuntimeError):
        run_worker(env)
    assert len(supervisor_messages(env)) == 1, "the room was mutated"

    # Restart: the request has no result, so it is retried — and reconciles.
    run_worker(env)
    assert len(supervisor_messages(env)) == 1, "no second response"
    assert result_for(env, request_id)["status"] == "ok"


# ===== the control namespace is closed =====================================

def raw_control_commit(control, rel, content, message, mode=None):
    path = control.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode:
        os.chmod(path, mode)
    git(control.workdir, "add", "-f", "--", rel)
    git(control.workdir, "commit", "-q", "-m", message)


@pytest.mark.parametrize("rel,content", [
    (".gitattributes", "* text=auto\n"),
    (".gitmodules", '[submodule "x"]\n\tpath = x\n'),
    ("evil.sh", "#!/bin/sh\nid\n"),
    (".agent-room-control/requests/not-a-uuid.json", "{}\n"),
    (".agent-room-control/other/x.json", "{}\n"),
    (".agent-room/messages/t1/x.json", "{}\n"),
])
def test_TRANSPORT_NAMESPACE_INJECTION(env, rel, content):
    control = env["control"]
    configure_identity(control.workdir)
    raw_control_commit(control, rel, content, "inject")
    with pytest.raises(ControlNamespaceViolation):
        control.pending()


def test_an_executable_control_artifact_is_rejected(env):
    control = env["control"]
    configure_identity(control.workdir)
    rel = f".agent-room-control/requests/{uuid7()}.json"
    raw_control_commit(control, rel, "{}\n", "executable", mode=0o755)
    with pytest.raises(ControlNamespaceViolation, match="non-executable"):
        control.pending()


def test_TRANSPORT_REQUEST_MODIFICATION(env):
    """A request artifact is evidence; changing it is tampering, not an update."""
    control = env["control"]
    configure_identity(control.workdir)
    document = request_document("status")
    submit(env, document)
    rel = f".agent-room-control/requests/{document['request_id']}.json"
    raw_control_commit(control, rel,
                       canonical.canonical_text(request_document("status")),
                       "rewrite the request")
    with pytest.raises(ControlAppendOnlyViolation, match="append-only"):
        control.pending()


def test_a_deleted_request_is_rejected(env):
    control = env["control"]
    configure_identity(control.workdir)
    document = request_document("status")
    submit(env, document)
    rel = f".agent-room-control/requests/{document['request_id']}.json"
    git(control.workdir, "rm", "-q", "--", rel)
    git(control.workdir, "commit", "-q", "-m", "delete the request")
    with pytest.raises(ControlAppendOnlyViolation):
        control.pending()


# ===== resource abuse ======================================================

def test_TRANSPORT_OVERSIZE_REQUEST(env):
    control = env["control"]
    configure_identity(control.workdir)
    request_id = uuid7()
    rel = f".agent-room-control/requests/{request_id}.json"
    huge = json.dumps({"control_schema_version": 1, "request_id": request_id,
                       "created_at": "2026-09-24T12:00:00Z",
                       "operation": "status",
                       "params": {}, "pad": "x" * (MAX_REQUEST_BYTES + 1024)})
    raw_control_commit(control, rel, huge, "oversize request")

    summary = run_worker(env)
    assert summary["processed"] == 1
    result = result_for(env, request_id)
    assert result["status"] == "refused"
    assert "over the" in result["detail"]["error"]


def test_an_oversize_response_document_is_bounded(env):
    document = bound_response(env, "observation")
    document["response"]["body"]["text"] = "x" * (MAX_REQUEST_BYTES + 1024)
    with pytest.raises(ControlError, match="over the"):
        submit(env, request_document("supervisor_import",
                                     {"response": document}))


def test_TRANSPORT_BACKLOG_BOUND(env):
    """A writer cannot make the worker scan an unbounded queue."""
    control = env["control"]
    for _ in range(MAX_PENDING_REQUESTS + 1):
        control.submit_request(request_document("status"))
    with pytest.raises(ControlError, match="backlog limit"):
        control.pending()


def test_only_a_bounded_number_is_processed_per_invocation(env):
    for _ in range(env["config"].max_requests_per_run + 3):
        env["control"].submit_request(request_document("status"))
    summary = run_worker(env)
    assert summary["processed"] == env["config"].max_requests_per_run
    assert summary["remaining"] == 3


def test_an_unknown_operation_flood_stays_bounded_and_harmless(env):
    for _ in range(5):
        env["control"].submit_request(request_document("run_command",
                                                       {"argv": ["id"]}))
    before = env["room"].current_tip()
    summary = run_worker(env)
    assert summary["processed"] == 5
    assert env["room"].current_tip() == before


# ===== static guarantees ===================================================

def code_of(path: Path) -> str:
    """Source with comments and docstrings removed.

    Scanning raw text finds the module's own prose about *not* having a
    subprocess surface. That mistake has now been made three times in this
    project on three different greps, so the scan reads code.
    """
    import ast
    import io
    import tokenize

    stripped = []
    with io.open(path, "rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type == tokenize.COMMENT:
                continue
            stripped.append(token)
    text = tokenize.untokenize(stripped).decode("utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                text = text.replace(doc, "", 1)
    return text


def test_the_transport_module_has_no_execution_surface():
    source = code_of(PACKAGE / "transport.py")
    for token in ("subprocess", "os.system", "popen", "exec(", "eval(",
                  "shell=True", "run_bounded", "/bin/sh", "bash"):
        assert token not in source, f"transport.py references {token!r}"


def test_TRANSPORT_NO_APPROVE_FOR_ME():
    for name in ("transport.py", "transport_worker.py", "control_store.py"):
        source = code_of(PACKAGE / name)
        assert "approve-for-me" not in source
        assert "approve_for_me" not in source
        assert "elevate_bridge" not in source


def test_TRANSPORT_NO_GENERIC_BRIDGE_IMPORT():
    for name in ("transport.py", "transport_worker.py", "control_store.py"):
        source = code_of(PACKAGE / name)
        assert "bridge_worker" not in source
        assert "run_command" not in source


def test_the_transport_imports_no_authority_or_model_surface():
    """A module that cannot import the release path cannot call it."""
    import ast

    tree = ast.parse((PACKAGE / "transport.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.lstrip("."))
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {"decision", "release", "proof", "snapshot", "orchestrator",
                 "claude_participant", "codex_participant", "tool_profiles",
                 "subprocess", "os"}
    assert not (imported & forbidden), sorted(imported & forbidden)


def test_the_only_git_surface_is_the_fixed_control_helper():
    """One reviewed Git runner for the whole transport, not three."""
    for name in ("control_store.py", "transport.py"):
        source = code_of(PACKAGE / name)
        assert "shell=True" not in source
        assert "subprocess" not in source, f"{name} should use run_git"
    runner = code_of(PACKAGE / "remote_sync.py")
    assert "run_bounded(" in runner, "the runner goes through the bounded one"
    assert "shell=True" not in runner
    assert "subprocess" not in runner
    # argv is built from constants and values this module validated.
    assert "_validate(" in runner


# ===== the deployment template =============================================

@pytest.mark.parametrize("directive", [
    "User=agentroom", "Group=agentroom", "UMask=0077",
    "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
    "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict",
    "ProtectHome=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes",
    "ProtectHostname=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
    "RestrictRealtime=yes", "RemoveIPC=yes", "KeyringMode=private",
    "ProtectProc=invisible", "ProcSubset=pid",
    "SystemCallArchitectures=native", "MemoryDenyWriteExecute=yes",
    "KillMode=control-group", "SendSIGKILL=yes", "Delegate=no",
    "StateDirectoryMode=0700", "InaccessiblePaths=/home/pr0",
])
def test_the_unit_template_carries_the_hardening_directive(directive):
    assert directive in UNIT.read_text(encoding="utf-8")


def unit_directives() -> str:
    """Only the directive lines — the comments explain, they do not configure."""
    return "\n".join(
        line for line in UNIT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    )


def test_the_unit_runs_frozen_root_owned_code_not_the_working_tree():
    directives = unit_directives()
    assert "/opt/agent-room/current" in directives
    assert "/home/pr0/projects/cek" not in directives, (
        "production must never execute the developer working tree")
    assert "transport_worker" in directives
    assert "bridge" not in directives.lower().replace("agent-room", "")


def test_the_unit_is_not_installed():
    """S3 versions the template. Installing it is a later human-gated step."""
    for path in ("/etc/systemd/system/agent-room-transport.service",
                 "/etc/agent-room/transport.json", "/opt/agent-room"):
        assert not Path(path).exists(), f"{path} exists; S3 must not deploy"


def test_the_permission_script_is_read_only():
    script = (DEPLOY / "verify-permissions.sh").read_text(encoding="utf-8")
    for token in ("rm ", "chmod ", "chown ", "install ", "systemctl enable",
                  "systemctl start", "> /etc", "mkdir "):
        assert token not in script, f"verify-permissions.sh contains {token!r}"
    assert "sudo -n true" in script, "it must check for passwordless root"


# ===== cgroup integration ==================================================

DETACHER = """\
import os, subprocess, sys, time
child = subprocess.Popen(["sleep", "300"], start_new_session=True)
open(sys.argv[1], "w").write(f"{os.getpid()} {child.pid}\\n")
time.sleep(300)
"""


def systemd_available() -> bool:
    if not shutil.which("systemd-run"):
        return False
    probe = subprocess.run(["systemctl", "--user", "is-system-running"],
                           capture_output=True, text=True)
    return probe.returncode in (0, 1) and probe.stdout.strip() != ""


@pytest.mark.skipif(not systemd_available(),
                    reason="no usable systemd user manager here")
def test_SYSTEMD_CGROUP_KILLS_DETACHED_SETSID_CHILD(tmp_path):
    """The escape S1 documented, closed by the cgroup rather than by killpg.

    `run_bounded` signals a process group; a descendant that calls `setsid()`
    has left it. S1's test asserts that escape still works and must keep
    asserting it — this one shows the *production* containment: the child
    never leaves the cgroup, so `KillMode=control-group` reaches it.
    """
    launcher = tmp_path / "detach.py"
    launcher.write_text(DETACHER, encoding="utf-8")
    pids = tmp_path / "pids"
    unit = f"agent-room-cgroup-test-{os.getpid()}"

    subprocess.run(["systemctl", "--user", "reset-failed", f"{unit}.service"],
                   capture_output=True)
    started = subprocess.run(
        ["systemd-run", "--user", f"--unit={unit}",
         "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
         "--property=TimeoutStopSec=5",
         "/usr/bin/python3", str(launcher), str(pids)],
        capture_output=True, text=True)
    assert started.returncode == 0, started.stderr

    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not pids.exists():
            time.sleep(0.1)
        assert pids.exists(), "the probe never reported its pids"
        parent, child = (int(v) for v in pids.read_text().split())

        # The child really has escaped the process group.
        assert os.getpgid(child) != os.getpgid(parent)
        assert os.getpgid(child) == child, "it leads its own group"
        # …but not the cgroup.
        parent_cg = Path(f"/proc/{parent}/cgroup").read_text()
        child_cg = Path(f"/proc/{child}/cgroup").read_text()
        assert unit in parent_cg and unit in child_cg

        subprocess.run(["systemctl", "--user", "stop", f"{unit}.service"],
                       capture_output=True, timeout=60)
        gone = time.monotonic() + 15
        while time.monotonic() < gone:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        with pytest.raises(ProcessLookupError):
            os.kill(child, 0)
    finally:
        subprocess.run(["systemctl", "--user", "stop", f"{unit}.service"],
                       capture_output=True)
        subprocess.run(["systemctl", "--user", "reset-failed",
                        f"{unit}.service"], capture_output=True)
