"""S3 corrective: the transport synchronises its own remotes, or it is stale.

The versioned worker operated on local checkouts. Something outside it would
have had to run Git — which is either a service that never sees new work, or
the broad synchronisation path S3 exists to remove. These tests use disposable
**bare remotes**, so "fetch" and "push" mean what they mean in production.

The security case is the compare-and-swap. A supervisor response reviewed
against head H must not be rebased onto H+1 and delivered as though it still
applied; a generic push-with-rebase would do exactly that. Two of the tests
below create that race deliberately, one where the reviewed thread moves and
one where an unrelated thread does, and they must come out differently.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.checkpoint import TrustCheckpoint, policy_digest
from agent_room.control_store import ControlStore
from agent_room.ids import uuid7
from agent_room.remote_sync import Anchor, RemoteRefMoved, RoomRemote, run_git
from agent_room.supervisor import PARTICIPANT as SUPERVISOR
from agent_room.supervisor import SupervisorBoundary
from agent_room.transport import (
    TransportConfig,
    TransportError,
    TransportRefused,
    TransportWorker,
)
from tests.conftest_agent_room import build_trust, configure_identity, git


def bare(path: Path) -> Path:
    path.mkdir(parents=True)
    git(path, "init", "-q", "--bare")
    return path


def clone(source: Path, dest: Path, branch: str) -> Path:
    subprocess.run(["git", "clone", "-q", "--branch", branch,
                    str(source), str(dest)], check=True, capture_output=True)
    configure_identity(dest)
    return dest


@pytest.fixture
def net(tmp_path):
    """Two bare remotes, a worker checkout of each, and two other writers."""
    origin_room = tmp_path / "origin-room.git"
    origin_control = tmp_path / "origin-control.git"
    bare(origin_room)
    bare(origin_control)

    # Seed the room and push it.
    seed = GitMessageStore.initialise(tmp_path / "seed-room",
                                      branch="agent-room")
    configure_identity(seed.workdir)
    policy, signers = build_trust(tmp_path / "keys", seed)
    seed.trust = policy
    claude = AgentRoom(seed, "claude-code",
                       ParticipantCursor(tmp_path / "seed-state", "claude-code"),
                       signer=signers["claude-code"])
    target = claude.post(thread_id="t1", type="question",
                         body={"text": "please review"},
                         recipient={"agent": SUPERVISOR})
    git(seed.workdir, "remote", "add", "origin", str(origin_room))
    git(seed.workdir, "push", "-q", "origin", "agent-room")

    seed_control = ControlStore.initialise(tmp_path / "seed-control",
                                           branch="agent-room-control")
    configure_identity(seed_control.workdir)
    git(seed_control.workdir, "remote", "add", "origin", str(origin_control))
    git(seed_control.workdir, "push", "-q", "origin", "agent-room-control")

    policy_path = tmp_path / "trust.json"
    policy.save(policy_path)

    # The worker's own checkouts.
    room_dir = clone(origin_room, tmp_path / "worker-room", "agent-room")
    control_dir = clone(origin_control, tmp_path / "worker-control",
                        "agent-room-control")
    worker_store = GitMessageStore(room_dir, branch="agent-room", trust=policy)
    checkpoint = TrustCheckpoint.bootstrap(
        worker_store, expected_genesis=worker_store.room_id(),
        expected_trust_policy_sha256=policy_digest(policy),
        path=tmp_path / "checkpoint.json")

    config = TransportConfig(
        room_workdir=str(room_dir), control_workdir=str(control_dir),
        trust_policy_path=str(policy_path),
        checkpoint_path=str(tmp_path / "checkpoint.json"),
        state_dir=str(tmp_path / "state"),
        signing_key_path=str(signers[SUPERVISOR].key_path),
        signing_key_id=signers[SUPERVISOR].key_id,
        room_remote="origin", control_remote="origin",
    )

    # Two independent writers against the same remotes.
    other_room = clone(origin_room, tmp_path / "other-room", "agent-room")
    other_store = GitMessageStore(other_room, branch="agent-room", trust=policy)
    other = AgentRoom(other_store, "claude-code",
                      ParticipantCursor(tmp_path / "other-state", "claude-code"),
                      signer=signers["claude-code"])
    writer_control = clone(origin_control, tmp_path / "writer-control",
                           "agent-room-control")

    return {
        "tmp": tmp_path, "config": config, "policy": policy,
        "signers": signers, "target": target["message_id"],
        "origin_room": origin_room, "origin_control": origin_control,
        "room": worker_store, "control": ControlStore(control_dir,
                                                      "agent-room-control"),
        "checkpoint": checkpoint,
        "other_room": other_store, "other": other,
        "writer_control": ControlStore(writer_control, "agent-room-control"),
        "seed": seed,
    }


def push_other(net):
    git(net["other_room"].workdir, "push", "-q", "origin", "agent-room")


def remote_tip(net, which="origin_room", branch="agent-room") -> str:
    out = git(net[which], "rev-parse", f"refs/heads/{branch}")
    return out.strip()


def request_document(operation="status", params=None):
    return {"control_schema_version": 1, "request_id": uuid7(),
            "created_at": "2026-09-24T12:00:00Z", "operation": operation,
            "params": {} if params is None else params}


def submit_remote(net, document):
    """The untrusted writer pushes a request to the control remote."""
    net["writer_control"].submit_request(document)
    git(net["writer_control"].workdir, "push", "-q", "origin",
        "agent-room-control")
    return document["request_id"]


def bound_response(net, response_type="observation"):
    boundary = SupervisorBoundary(AgentRoom(
        net["room"], SUPERVISOR,
        ParticipantCursor(net["tmp"] / "export", SUPERVISOR),
        signer=net["signers"][SUPERVISOR]))
    packet = boundary.export(net["target"])
    return {"packet_schema_version": packet["packet_schema_version"],
            "target_message_id": packet["target_message_id"],
            "context_sha256": packet["context_sha256"],
            "response": {"type": response_type,
                         "body": {"text": "reviewer content"}}}


_PROBE = {"n": 0}


def remote_supervisor_messages(net):
    """What is actually on the remote, not what is local."""
    _PROBE["n"] += 1
    probe = net["tmp"] / f"probe-{_PROBE['n']}"
    clone(net["origin_room"], probe, "agent-room")
    store = GitMessageStore(probe, branch="agent-room", trust=net["policy"])
    return [m for m in store.thread_messages("t1")
            if m["sender"].get("agent") == SUPERVISOR]


def run(net):
    return TransportWorker(net["config"]).run()


# ===== the worker synchronises its own remotes =============================

def test_a_request_that_exists_only_on_the_remote_is_processed(net):
    """Before this pass the worker never saw it: nothing fetched the queue."""
    request_id = submit_remote(net, request_document("status"))
    summary = run(net)

    assert summary["lifecycle"]["status"] == "ok"
    assert summary["processed"] == 1
    assert summary["results"][0]["request_id"] == request_id
    assert summary["lifecycle"]["control"]["mode"] == "remote"


def test_a_result_reaches_the_remote_without_an_external_push(net):
    request_id = submit_remote(net, request_document("status"))
    run(net)

    probe = net["tmp"] / "control-probe"
    clone(net["origin_control"], probe, "agent-room-control")
    remote_control = ControlStore(probe, "agent-room-control")
    assert remote_control.has_result(request_id)
    history = remote_control._history()
    path = f".agent-room-control/results/{request_id}.json"
    result = json.loads(remote_control._blob(path, history[path]).decode())
    assert result["status"] == "ok"
    # A success claim the far side can check against signed room state.
    assert result["room_tip"] == remote_tip(net)


def test_a_remote_room_descendant_is_fetched_verified_and_installed(net):
    before = net["room"].current_tip()
    net["other"].post(thread_id="t1", type="observation",
                      body={"text": "from another participant"})
    push_other(net)

    summary = run(net)
    assert summary["lifecycle"]["room"]["mode"] == "remote"
    assert net["room"].current_tip() == remote_tip(net) != before
    reloaded = TrustCheckpoint.load(net["config"].checkpoint_path)
    assert reloaded.document["last_accepted_tip"] == remote_tip(net)


def test_a_rolled_back_remote_is_refused_and_the_local_room_is_untouched(net):
    net["other"].post(thread_id="t1", type="observation", body={"text": "one"})
    push_other(net)
    run(net)
    accepted = net["room"].current_tip()

    # The remote is rolled back to the genesis by force.
    genesis = net["room"].room_id()
    git(net["other_room"].workdir, "reset", "-q", "--hard", genesis)
    git(net["other_room"].workdir, "push", "-q", "--force", "origin",
        "agent-room")

    summary = run(net)
    assert summary["lifecycle"]["status"] == "failed"
    assert summary["lifecycle"]["error_type"] == "RollbackRejected"
    assert net["room"].current_tip() == accepted, "local room untouched"
    reloaded = TrustCheckpoint.load(net["config"].checkpoint_path)
    assert reloaded.document["last_accepted_tip"] == accepted


def test_an_unsigned_remote_candidate_is_refused_before_installation(net):
    accepted = net["room"].current_tip()
    forged = canonical.seal({
        "schema_version": 1, "message_id": uuid7(),
        "timestamp": "2026-09-24T12:00:00Z",
        "sender": {"agent": "codex"}, "recipient": {"broadcast": True},
        "project": {}, "thread_id": "t1", "type": "claim",
        "body": {"text": "unsigned"}, "evidence": [], "status": "open",
        "reply_requested": False, "human_approval_required": False})
    rel = net["other_room"].message_path("t1", forged["message_id"])
    path = net["other_room"].workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(forged), encoding="utf-8")
    git(net["other_room"].workdir, "add", "-f", "--", rel)
    git(net["other_room"].workdir, "commit", "-q", "-m", "forged")
    push_other(net)

    summary = run(net)
    assert summary["lifecycle"]["status"] == "failed"
    assert "Unauthenticated" in summary["lifecycle"]["error_type"]
    assert net["room"].current_tip() == accepted, "candidate never installed"


# ===== the compare-and-swap ================================================

def race_on_push(monkeypatch, net, action):
    """Fire `action` once, between the lease being taken and the push."""
    real = RoomRemote.push_with_lease
    fired = {}

    def raced(self, expected):
        if not fired:
            fired["yes"] = True
            action()
        return real(self, expected)

    monkeypatch.setattr(RoomRemote, "push_with_lease", raced)
    return fired


def test_REMOTE_CONTEXT_RACE_SAME_THREAD(net, monkeypatch):
    """The reviewed thread moves mid-delivery. The response must not land.

    This is the attack the lease exists for: a generic rebase-and-push would
    deliver a review of context H on top of H+1, which the supervisor never
    saw.
    """
    document = bound_response(net)
    request_id = submit_remote(net, request_document("supervisor_import",
                                                     {"response": document}))

    def append_to_reviewed_thread():
        net["other"].post(thread_id="t1", type="observation",
                          body={"text": "the reviewed thread moved"})
        push_other(net)

    race_on_push(monkeypatch, net, append_to_reviewed_thread)
    summary = run(net)

    assert summary["results"][0]["status"] == "refused"
    assert remote_supervisor_messages(net) == [], "nothing was delivered"


def test_REMOTE_CONTEXT_RACE_OTHER_THREAD(net, monkeypatch):
    """An unrelated thread moves. The reviewed digest is unchanged, so a
    bounded retry may deliver — exactly once."""
    document = bound_response(net)
    submit_remote(net, request_document("supervisor_import",
                                        {"response": document}))

    def append_to_another_thread():
        net["other"].post(thread_id="t2", type="observation",
                          body={"text": "unrelated traffic"})
        push_other(net)

    race_on_push(monkeypatch, net, append_to_another_thread)
    summary = run(net)

    assert summary["results"][0]["status"] == "ok"
    delivered = remote_supervisor_messages(net)
    assert len(delivered) == 1, "delivered exactly once"
    assert delivered[0]["auth"]["signer"] == SUPERVISOR


def test_REMOTE_REF_MOVES_DURING_IMPORT_is_caught_by_the_lease(net):
    """The lease itself, at the primitive: an exact expected OID or nothing."""
    remote = RoomRemote(net["config"].room_workdir, "origin", "agent-room")
    net["other"].post(thread_id="t1", type="observation", body={"text": "x"})
    push_other(net)
    stale = net["room"].current_tip()

    # Build a local commit on the stale head and try to deliver it.
    room = AgentRoom(net["room"], SUPERVISOR,
                     ParticipantCursor(net["tmp"] / "lease", SUPERVISOR),
                     signer=net["signers"][SUPERVISOR])
    room.post(thread_id="t1", type="observation", body={"text": "late"})
    with pytest.raises(RemoteRefMoved, match="no longer"):
        remote.push_with_lease(stale)


def test_the_room_store_used_for_delivery_has_no_generic_push_path(net):
    """The generic store push rebases on non-fast-forward. Not here."""
    store = TransportWorker(net["config"])._room_store()
    assert store.remote is None


# ===== crash windows, with a real remote ===================================

def test_a_crash_after_remote_delivery_does_not_post_twice(net, monkeypatch):
    """The push landed; the worker died before recording it."""
    document = bound_response(net)
    request_id = submit_remote(net, request_document("supervisor_import",
                                                     {"response": document}))

    real = TransportWorker._record
    crashed = {}

    def crash_once(self, *args, **kwargs):
        if not crashed:
            crashed["yes"] = True
            raise RuntimeError("worker died after the remote push")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(TransportWorker, "_record", crash_once)
    with pytest.raises(RuntimeError):
        run(net)
    assert len(remote_supervisor_messages(net)) == 1, "the push landed"

    monkeypatch.undo()
    summary = run(net)
    assert len(remote_supervisor_messages(net)) == 1, "no second response"
    assert summary["results"][0]["status"] == "ok"


def test_an_undelivered_local_commit_is_discarded_on_restart(net):
    """A crash before the push leaves a commit nobody has seen."""
    room = AgentRoom(net["room"], SUPERVISOR,
                     ParticipantCursor(net["tmp"] / "orphan", SUPERVISOR),
                     signer=net["signers"][SUPERVISOR])
    room.post(thread_id="t1", type="observation",
              body={"text": "never delivered"})
    orphan = net["room"].current_tip()
    assert orphan != remote_tip(net)

    summary = run(net)
    assert summary["lifecycle"]["recover"]["recovered"] is True
    assert summary["lifecycle"]["recover"]["discarded"] == orphan
    assert net["room"].current_tip() == remote_tip(net)


# ===== the control queue ===================================================

def test_a_rewritten_remote_request_history_is_refused(net):
    request_id = submit_remote(net, request_document("status"))
    run(net)

    # The writer rewrites history to erase the request it already sent.
    writer = net["writer_control"]
    git(writer.workdir, "fetch", "-q", "origin")
    git(writer.workdir, "reset", "-q", "--hard", writer.genesis())
    git(writer.workdir, "push", "-q", "--force", "origin",
        "agent-room-control")

    summary = run(net)
    assert summary["lifecycle"]["status"] == "failed"
    assert "does not descend" in summary["lifecycle"]["error"]


def test_erasing_a_result_does_not_make_the_worker_repeat_the_work(net):
    """The point of the control anchor: availability, not authority."""
    document = bound_response(net)
    submit_remote(net, request_document("supervisor_import",
                                        {"response": document}))
    run(net)
    assert len(remote_supervisor_messages(net)) == 1

    writer = net["writer_control"]
    git(writer.workdir, "fetch", "-q", "origin")
    git(writer.workdir, "reset", "-q", "--hard", writer.genesis())
    git(writer.workdir, "push", "-q", "--force", "origin",
        "agent-room-control")

    summary = run(net)
    assert summary["lifecycle"]["status"] == "failed", "the rewrite is refused"
    assert len(remote_supervisor_messages(net)) == 1, "not done twice"


def test_a_forged_result_does_not_suppress_processing(net):
    """FORGED_RESULT_BEFORE_PROCESSING.

    The control writer can create a syntactically valid result. It is
    telemetry, not authority: the service's own ledger decides what has run.
    """
    document = request_document("status")
    request_id = document["request_id"]
    writer = net["writer_control"]
    writer.submit_request(document)
    writer.write_result(request_id, {
        "control_schema_version": 1, "request_id": request_id,
        "operation": "status", "request_sha256": "0" * 64,
        "status": "ok", "completed_at": "2026-09-24T12:00:00Z",
        "room_tip": None, "detail": {"forged": True}})
    git(writer.workdir, "push", "-q", "origin", "agent-room-control")

    summary = run(net)
    # The worker still processes it — a file in an untrusted repo is not a
    # record of what this service did.
    assert summary["processed"] == 1
    ledger = Anchor(Path(net["config"].state_dir) / "processed.json",
                    "processed-ledger")
    assert request_id in (ledger.get("requests") or {})
    # …and the forged artifact is immutable, so the real result cannot
    # overwrite it. That is a denial of service by the writer, and it is the
    # documented limit of option B.
    delivered = summary["lifecycle"]["delivered"]
    assert any(d["status"] == "conflict" for d in delivered)


def test_a_concurrent_remote_request_and_a_local_result_both_survive(net):
    first = submit_remote(net, request_document("status"))

    # The worker produces a result while a second request is pushed remotely.
    worker = TransportWorker(net["config"])
    worker.recover_room()
    worker.sync_room()
    worker.sync_control()
    second = submit_remote(net, request_document("status"))

    summary = run(net)
    probe = net["tmp"] / "both"
    clone(net["origin_control"], probe, "agent-room-control")
    remote_control = ControlStore(probe, "agent-room-control")
    assert remote_control.has_result(first)
    history = remote_control._history()
    assert f".agent-room-control/requests/{second}.json" in history
    assert summary["lifecycle"]["status"] == "ok"


def test_an_exact_duplicate_result_is_idempotent(net):
    request_id = submit_remote(net, request_document("status"))
    run(net)
    control = net["control"]
    history = control._history()
    path = f".agent-room-control/results/{request_id}.json"
    document = json.loads(control._blob(path, history[path]).decode())
    assert control.write_result(request_id, document)["status"] == "duplicate"


# ===== bounds ==============================================================

def test_the_worker_deadline_is_enforced_not_merely_configured(net):
    """S3-C7: a security-looking configuration value that does nothing is
    worse than no value at all."""
    from dataclasses import replace

    submit_remote(net, request_document("status"))
    config = replace(net["config"], worker_timeout_seconds=0)
    worker = TransportWorker(config)
    with pytest.raises(TransportError, match="deadline"):
        worker.run()


def test_a_production_config_without_remotes_fails_closed(tmp_path):
    path = tmp_path / "transport.json"
    path.write_text(json.dumps({
        "room_workdir": "/var/lib/agent-room/room",
        "control_workdir": "/var/lib/agent-room/control",
        "trust_policy_path": "/etc/agent-room/trust-policy.json",
        "checkpoint_path": "/var/lib/agent-room/checkpoint.json",
        "state_dir": "/var/lib/agent-room/state",
        "signing_key_path": "/var/lib/agent-room/keys/k.pem",
        "signing_key_id": "openai-research-1",
    }), encoding="utf-8")
    with pytest.raises(TransportError, match="room_remote"):
        TransportConfig.load(path)


def test_the_shipped_example_config_names_both_remotes():
    example = json.loads(
        (Path(__file__).resolve().parents[1]
         / "deploy" / "transport.json.example").read_text(encoding="utf-8"))
    assert example["room_remote"] and example["control_remote"]


# ===== the production Git lifecycle under containment ======================

def systemd_available() -> bool:
    if not shutil.which("systemd-run"):
        return False
    probe = subprocess.run(["systemctl", "--user", "is-system-running"],
                           capture_output=True, text=True)
    return probe.returncode in (0, 1) and probe.stdout.strip() != ""


@pytest.mark.skipif(not systemd_available(), reason="no systemd user manager")
def test_the_worker_git_lifecycle_runs_under_the_hardened_restrictions(net,
                                                                       tmp_path):
    """S3-C8: fetch, verify, sign, push and the checkpoint, under the unit's
    restrictions rather than merely beside them.

    A local bare remote exercises the worker's Git lifecycle and the systemd
    containment. It does **not** prove SSH credential isolation — that needs
    real credentials and a network, and stays an activation prerequisite.
    """
    submit_remote(net, request_document(
        "supervisor_import", {"response": bound_response(net)}))
    config_path = tmp_path / "transport.json"
    config_path.write_text(json.dumps({
        "room_workdir": net["config"].room_workdir,
        "control_workdir": net["config"].control_workdir,
        "trust_policy_path": net["config"].trust_policy_path,
        "checkpoint_path": net["config"].checkpoint_path,
        "state_dir": net["config"].state_dir,
        "signing_key_path": net["config"].signing_key_path,
        "signing_key_id": net["config"].signing_key_id,
        "room_remote": "origin", "control_remote": "origin",
    }), encoding="utf-8")

    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "worker.out"
    unit = f"agent-room-worker-{os.getpid()}"
    subprocess.run(["systemctl", "--user", "reset-failed", f"{unit}.service"],
                   capture_output=True)
    started = subprocess.run([
        "systemd-run", "--user", f"--unit={unit}", "--wait", "--collect",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=SystemCallFilter=@system-service",
        "--property=SystemCallFilter=~@privileged",
        "--property=SystemCallFilter=~@resources",
        "--property=LockPersonality=yes",
        "--property=NoNewPrivileges=yes",
        "--property=KillMode=control-group",
        "--property=UMask=0077",
        f"--property=Environment=PYTHONPATH={root}",
        "--property=Environment=PYTHONDONTWRITEBYTECODE=1",
        f"--property=StandardOutput=file:{out}",
        f"--property=StandardError=append:{out}",
        "/usr/bin/python3", "-m", "agent_room.transport_worker",
        str(config_path)], capture_output=True, text=True, timeout=300)
    subprocess.run(["systemctl", "--user", "reset-failed", f"{unit}.service"],
                   capture_output=True)

    produced = out.read_text(encoding="utf-8") if out.exists() else ""
    assert started.returncode == 0, f"{started.stderr}\n{produced}"
    summary = json.loads(produced)
    assert summary["lifecycle"]["status"] == "ok"
    assert summary["processed"] == 1
    assert summary["results"][0]["status"] == "ok"
    assert len(remote_supervisor_messages(net)) == 1, "signed and pushed"
