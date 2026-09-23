"""Issue #4 acceptance: the OpenAI supervisor handoff boundary.

There is no second OpenAI process and no API key here. The supervisor is the
ChatGPT host conversation, which already reaches this machine through the
existing bridge; what is under test is the durable export/import boundary it
uses, and the context binding that stops a stale review being posted as
current.
"""

import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.cli import main
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7
from agent_room.participant import MalformedResponse
from agent_room.supervisor import (
    ADAPTER_MARKER,
    PACKET_SCHEMA_VERSION,
    PARTICIPANT,
    MalformedSupervisorResponse,
    StaleSupervisorContext,
    SupervisorBoundary,
    SupervisorError,
    context_digest,
)
from tests.conftest_agent_room import configure_identity, git

REPO = "pr0dus/cek"
FULL_SHA = "4941d76f2eb9e5ea8d6d69796b8c745eb0c0e3ff"


@pytest.fixture
def supervisor_room(store, tmp_path):
    return AgentRoom(store, PARTICIPANT,
                     ParticipantCursor(tmp_path / "openai", PARTICIPANT))


@pytest.fixture
def claim_from_claude(store, tmp_path, supervisor_room):
    """Claude posts a substantive, evidence-citing claim to openai-research."""
    claude = AgentRoom(store, "claude-code",
                       ParticipantCursor(tmp_path / "claude", "claude-code"))
    posted = claude.post(
        thread_id="research-7", type="claim",
        body={"text": "The turn lock makes concurrent turns safe, so duplicate "
                      "responses are impossible under any failure."},
        recipient={"agent": PARTICIPANT}, reply_requested=True,
        project={"repo": REPO},
        evidence=[{"kind": "repo", "repo": REPO, "commit": FULL_SHA,
                   "path": "agent_room/participant.py", "lines": [200, 240]}],
        claim={"status": "proposed"},
    )
    return claude, supervisor_room, posted


def response_document(packet, **overrides):
    document = {
        "packet_schema_version": PACKET_SCHEMA_VERSION,
        "target_message_id": packet["target_message_id"],
        "context_sha256": packet["context_sha256"],
        "response": {
            "type": "challenge",
            "body": {"text": "The cited range shows single-flight within one "
                             "participant; it does not establish impossibility "
                             "under every failure. That is an unsupported jump."},
        },
    }
    document.update(overrides)
    return document


# ===== no local OpenAI process or key ====================================

def test_no_openai_api_key_or_model_process_is_introduced():
    """Issue #4 is a handoff boundary, not another model adapter."""
    import agent_room.supervisor as module

    source = open(module.__file__, encoding="utf-8").read()
    for forbidden in ("OPENAI_API_KEY", "api_key", "openai.", "import openai",
                      "chat.completions", "https://api.openai.com"):
        assert forbidden not in source, forbidden
    assert "subprocess" not in source, "the supervisor spawns no process"


def test_the_boundary_has_no_default_model_invoker(supervisor_room):
    boundary = SupervisorBoundary(supervisor_room)
    with pytest.raises(SupervisorError, match="supplied response"):
        type(boundary).default_invoker(boundary)


# ===== export =============================================================

def test_export_selects_the_message_addressed_to_the_supervisor(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    assert packet["target_message_id"] == posted["message_id"]
    assert packet["participant"] == PARTICIPANT
    assert packet["thread_id"] == "research-7"


def test_packet_carries_the_required_fields(claim_from_claude, store):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()

    assert packet["packet_schema_version"] == PACKET_SCHEMA_VERSION
    stored = supervisor_room.get("research-7", posted["message_id"])
    assert packet["target_envelope_sha256"] == stored[canonical.DIGEST_FIELD]
    assert len(packet["target_envelope_sha256"]) == 64
    assert packet["project"] == {"repo": REPO}
    assert packet["room"]["ref"] == store.ref
    assert packet["room"]["tip"] == git(store.workdir, "rev-parse", store.ref).strip()
    assert len(packet["context_sha256"]) == 64

    message = packet["thread"][0]
    assert message["sender"]["agent"] == "claude-code"          # identities
    assert "parent_id" in message or message.get("parent_id") is None
    assert message["evidence"][0]["commit"] == FULL_SHA          # locators
    assert message["evidence"][0]["path"] == "agent_room/participant.py"


def test_export_is_read_only_and_deterministic(claim_from_claude, store):
    _, supervisor_room, posted = claim_from_claude
    head_before = git(store.workdir, "rev-parse", store.ref).strip()

    first = SupervisorBoundary(supervisor_room).export()
    second = SupervisorBoundary(supervisor_room).export()

    assert canonical.canonical_text(first) == canonical.canonical_text(second)
    assert git(store.workdir, "rev-parse", store.ref).strip() == head_before
    assert supervisor_room.inbox(), "export must not acknowledge"


def test_packet_references_evidence_without_inlining_bodies(claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    serialised = canonical.canonical_text(packet)
    # The locator is present; the file it names is not read into the packet.
    assert "agent_room/participant.py" in serialised
    assert "def turn_lock" not in serialised
    assert "flock" not in serialised


# ===== context hash / stale protection ====================================

def test_context_hash_is_stable_for_unchanged_context(claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    boundary = SupervisorBoundary(supervisor_room)
    assert boundary.export()["context_sha256"] == boundary.export()["context_sha256"]


def test_context_hash_is_computed_from_durable_state_only(claim_from_claude, store,
                                                          tmp_path):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()

    reopened = AgentRoom(GitMessageStore(store.workdir, branch="agent-room"),
                         PARTICIPANT, ParticipantCursor(tmp_path / "fresh", PARTICIPANT))
    assert SupervisorBoundary(reopened).export()["context_sha256"] == \
        packet["context_sha256"]


def test_a_new_message_in_the_thread_makes_the_review_stale(claim_from_claude):
    claude, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()

    claude.reply(posted["message_id"], type="observation",
                 body={"text": "material addition after export"})

    with pytest.raises(StaleSupervisorContext, match="has changed"):
        SupervisorBoundary(supervisor_room).import_response(
            json.dumps(response_document(packet)))
    assert len(supervisor_room.thread("research-7")) == 2, "nothing posted"


def test_activity_in_another_thread_does_not_invalidate(claim_from_claude, store,
                                                        tmp_path):
    claude, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()

    claude.post(thread_id="unrelated", type="observation",
                body={"text": "different thread entirely"})

    result = SupervisorBoundary(supervisor_room).import_response(
        json.dumps(response_document(packet)))
    assert result["status"] == "responded"


def test_staleness_is_mechanical_not_temporal(claim_from_claude):
    """Waiting changes nothing; only the thread's content binding matters."""
    _, supervisor_room, posted = claim_from_claude
    boundary = SupervisorBoundary(supervisor_room)
    first = boundary.export()["context_sha256"]
    time.sleep(1.1)
    assert boundary.export()["context_sha256"] == first


def test_context_digest_covers_target_and_ordered_thread(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    target = supervisor_room.get("research-7", posted["message_id"])
    thread = supervisor_room.thread("research-7")

    assert context_digest(target, thread) == \
        SupervisorBoundary(supervisor_room).export()["context_sha256"]

    mutated = list(thread)
    mutated.append(dict(target, message_id=uuid7()))
    assert context_digest(target, mutated) != context_digest(target, thread)


def test_a_tampered_context_hash_is_refused(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, context_sha256="0" * 64)
    with pytest.raises(StaleSupervisorContext):
        SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    assert len(supervisor_room.thread("research-7")) == 1


# ===== import =============================================================

def test_a_valid_challenge_posts_with_correct_identity_and_linkage(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    result = SupervisorBoundary(supervisor_room).import_response(
        json.dumps(response_document(packet)))

    assert result["status"] == "responded"
    assert result["participant"] == PARTICIPANT
    assert result["context_sha256"] == packet["context_sha256"]
    assert result["acknowledged"] is True

    thread = supervisor_room.thread("research-7")
    assert len(thread) == 2
    reply = thread[1]
    assert reply["sender"] == {"agent": PARTICIPANT, "via": ADAPTER_MARKER}
    assert reply["parent_id"] == posted["message_id"]
    assert reply["type"] == "challenge"
    assert "unsupported jump" in reply["body"]["text"]


def test_the_supervisor_may_propose_a_falsification_test(claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, response={
        "type": "proposed_test",
        "body": {"text": "Kill the writer mid-append and assert no duplicate."},
    })
    result = SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    assert supervisor_room.get("research-7",
                               result["response_message_id"])["type"] == "proposed_test"


def test_the_supervisor_may_support_only_within_evidenced_scope(claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, response={
        "type": "claim",
        "body": {"text": "Single-flight holds for one participant."},
        "evidence": [{"kind": "repo", "repo": REPO, "commit": FULL_SHA,
                      "path": "agent_room/participant.py", "id": "e1"}],
        "claim": {"status": "supported",
                  "scope": f"one participant, at commit {FULL_SHA}",
                  "revision_condition": "a duplicate under the same lock",
                  "evidence_basis": ["e1"]},
    })
    result = SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    stored = supervisor_room.get("research-7", result["response_message_id"])
    assert stored["claim"]["status"] == "supported"
    assert FULL_SHA in stored["claim"]["scope"]


def test_the_supervisor_may_request_a_human_decision(claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, response={
        "type": "decision_request", "body": {"text": "needs a human"},
        "human_approval_required": True})
    result = SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    assert supervisor_room.get(
        "research-7", result["response_message_id"])["human_approval_required"] is True


@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_the_supervisor_cannot_author_human_authority(claim_from_claude, mtype):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, response={"type": mtype,
                                                   "body": {"text": "approved"}})
    with pytest.raises(MalformedResponse, match="may not author"):
        SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    assert len(supervisor_room.thread("research-7")) == 1
    assert not supervisor_room.is_acknowledged(posted["message_id"])


@pytest.mark.parametrize("document", [
    pytest.param("not json", id="not-json"),
    pytest.param("[]", id="array-root"),
    pytest.param('{"packet_schema_version": 1}', id="missing-fields"),
    pytest.param('{"packet_schema_version": "1", "target_message_id": "x",'
                 ' "context_sha256": "y", "response": {}}', id="version-not-int"),
    pytest.param('{"packet_schema_version": 99, "target_message_id": "x",'
                 ' "context_sha256": "y", "response": {}}', id="wrong-version"),
    pytest.param('{"packet_schema_version": 1, "target_message_id": "",'
                 ' "context_sha256": "y", "response": {}}', id="empty-target"),
    pytest.param('{"packet_schema_version": 1, "target_message_id": "x",'
                 ' "context_sha256": "y", "response": []}', id="response-not-object"),
])
def test_malformed_supervisor_documents_post_nothing(claim_from_claude, document):
    _, supervisor_room, posted = claim_from_claude
    with pytest.raises(MalformedSupervisorResponse):
        SupervisorBoundary(supervisor_room).import_response(document)
    assert len(supervisor_room.thread("research-7")) == 1
    assert not supervisor_room.is_acknowledged(posted["message_id"])


def test_a_malformed_inner_response_posts_nothing(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = response_document(packet, response={"type": "challenge",
                                                   "body": {"text": ""}})
    with pytest.raises(MalformedResponse):
        SupervisorBoundary(supervisor_room).import_response(json.dumps(document))
    assert len(supervisor_room.thread("research-7")) == 1
    assert not supervisor_room.is_acknowledged(posted["message_id"])


def test_a_response_for_another_target_is_refused(claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    with pytest.raises(MalformedSupervisorResponse, match="not the requested"):
        SupervisorBoundary(supervisor_room).import_response(
            json.dumps(response_document(packet)), message_id=uuid7())


# ===== idempotence, reconciliation, single-flight =========================

def test_post_then_failed_ack_does_not_duplicate_on_retry(claim_from_claude, store,
                                                          tmp_path):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()

    def explode(message_id):
        raise AgentRoomError("simulated cursor failure")

    supervisor_room.acknowledge = explode
    first = SupervisorBoundary(supervisor_room).import_response(
        json.dumps(response_document(packet)))
    assert first["acknowledged"] is False

    retry_room = AgentRoom(GitMessageStore(store.workdir, branch="agent-room"),
                           PARTICIPANT,
                           ParticipantCursor(tmp_path / "openai", PARTICIPANT))
    retry = SupervisorBoundary(retry_room).import_response(
        json.dumps(response_document(packet)))
    assert retry["status"] == "already_responded"
    assert retry["response_message_id"] == first["response_message_id"]
    assert len(retry_room.thread("research-7")) == 2


def test_process_loss_after_post_reconciles(claim_from_claude, store, tmp_path):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document = json.dumps(response_document(packet))

    script = textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {os.getcwd()!r})
        from agent_room import AgentRoom, GitMessageStore, ParticipantCursor
        from agent_room.supervisor import SupervisorBoundary, PARTICIPANT
        store = GitMessageStore({str(store.workdir)!r}, branch='agent-room')
        room = AgentRoom(store, PARTICIPANT,
                         ParticipantCursor({str(tmp_path / 'openai')!r}, PARTICIPANT))
        def die(message_id):
            raise SystemExit(7)
        room.acknowledge = die
        SupervisorBoundary(room).import_response({document!r})
    """)
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 7, proc.stderr

    restarted = AgentRoom(GitMessageStore(store.workdir, branch="agent-room"),
                          PARTICIPANT,
                          ParticipantCursor(tmp_path / "openai", PARTICIPANT))
    assert len(restarted.thread("research-7")) == 2
    result = SupervisorBoundary(restarted).import_response(document)
    assert result["status"] == "already_responded"
    assert len(restarted.thread("research-7")) == 2


def test_concurrent_supervisor_imports_cannot_duplicate(store, tmp_path,
                                                        claim_from_claude):
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    document_path = tmp_path / "response.json"
    document_path.write_text(json.dumps(response_document(packet)), encoding="utf-8")

    argv = ["--repo", str(store.workdir), "--participant", PARTICIPANT,
            "--state-dir", str(tmp_path / "openai"), "supervisor-import",
            "--response", str(document_path), "--turn-timeout", "60"]
    procs = [subprocess.Popen([sys.executable, "-m", "agent_room.cli", *argv],
                              cwd=os.getcwd(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outs = [p.communicate(timeout=180) for p in procs]

    statuses = []
    for proc, (out, err) in zip(procs, outs):
        assert "Traceback" not in err
        if proc.returncode == 0:
            statuses.append(json.loads(out)["status"])
    assert "responded" in statuses
    assert statuses.count("responded") == 1, statuses

    room = AgentRoom(GitMessageStore(store.workdir, branch="agent-room"), PARTICIPANT,
                     ParticipantCursor(tmp_path / "openai", PARTICIPANT))
    assert len(room.thread("research-7")) == 2, "exactly one supervisor reply"
    assert room.store.verify_store() == 2


def test_supervisor_lock_is_its_own(store, tmp_path, supervisor_room):
    from agent_room.claude_participant import ClaudeParticipant

    claude_room = AgentRoom(store, "claude-code",
                            ParticipantCursor(tmp_path / "c", "claude-code"))
    boundary = SupervisorBoundary(supervisor_room)
    claude = ClaudeParticipant(claude_room, lambda p: "")
    assert boundary.turn_lock_path() != claude.turn_lock_path()
    with boundary.turn_lock():
        with claude.turn_lock():
            pass


# ===== fresh session recovers everything =================================

def test_a_fresh_process_reconstructs_all_required_state(store, tmp_path,
                                                         claim_from_claude):
    """No hidden conversational memory: a new session works from artifacts."""
    _, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    SupervisorBoundary(supervisor_room).import_response(
        json.dumps(response_document(packet)))

    script = textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {os.getcwd()!r})
        from agent_room import AgentRoom, GitMessageStore, ParticipantCursor
        from agent_room.supervisor import SupervisorBoundary, PARTICIPANT
        store = GitMessageStore({str(store.workdir)!r}, branch='agent-room')
        room = AgentRoom(store, PARTICIPANT,
                         ParticipantCursor({str(tmp_path / 'openai')!r}, PARTICIPANT))
        thread = room.thread("research-7")
        print(json.dumps({{
            "senders": [m["sender"]["agent"] for m in thread],
            "types": [m["type"] for m in thread],
            "evidence": thread[0]["evidence"],
            "acknowledged": room.is_acknowledged({posted['message_id']!r}),
        }}))
    """)
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    recovered = json.loads(proc.stdout)
    assert recovered["senders"] == ["claude-code", PARTICIPANT]
    assert recovered["types"] == ["claim", "challenge"]
    assert recovered["evidence"][0]["commit"] == FULL_SHA
    assert recovered["acknowledged"] is True


# ===== CLI ================================================================

def test_cli_export_then_import_without_copying_any_body(store, tmp_path,
                                                         claim_from_claude, capsys):
    """The handoff the bridge performs: two commands, no human transcription."""
    _, supervisor_room, posted = claim_from_claude
    base = ["--repo", str(store.workdir), "--participant", PARTICIPANT,
            "--state-dir", str(tmp_path / "openai")]

    assert main(base + ["supervisor-export"]) == 0
    packet = json.loads(capsys.readouterr().out)

    document = tmp_path / "response.json"
    document.write_text(json.dumps(response_document(packet)), encoding="utf-8")
    assert main(base + ["supervisor-import", "--response", str(document)]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "responded"
    room = AgentRoom(GitMessageStore(store.workdir, branch="agent-room"), PARTICIPANT,
                     ParticipantCursor(tmp_path / "openai", PARTICIPANT))
    assert room.thread("research-7")[1]["sender"]["agent"] == PARTICIPANT


def test_cli_export_to_a_file_reports_the_binding(store, tmp_path,
                                                  claim_from_claude, capsys):
    out = tmp_path / "packet.json"
    assert main(["--repo", str(store.workdir), "--participant", PARTICIPANT,
                 "--state-dir", str(tmp_path / "openai"),
                 "supervisor-export", "--out", str(out)]) == 0
    reported = json.loads(capsys.readouterr().out)
    packet = json.loads(out.read_text(encoding="utf-8"))
    assert reported["context_sha256"] == packet["context_sha256"]


def test_cli_import_accepts_stdin(store, tmp_path, claim_from_claude, monkeypatch,
                                  capsys):
    import io

    _, supervisor_room, _ = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    monkeypatch.setattr(sys, "stdin",
                        io.StringIO(json.dumps(response_document(packet))))
    code = main(["--repo", str(store.workdir), "--participant", PARTICIPANT,
                 "--state-dir", str(tmp_path / "openai"),
                 "supervisor-import", "--response", "-"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "responded"


def test_cli_reports_a_stale_review_without_a_traceback(store, tmp_path,
                                                        claim_from_claude, capsys):
    claude, supervisor_room, posted = claim_from_claude
    packet = SupervisorBoundary(supervisor_room).export()
    claude.reply(posted["message_id"], type="observation",
                 body={"text": "changes the context"})

    document = tmp_path / "response.json"
    document.write_text(json.dumps(response_document(packet)), encoding="utf-8")
    code = main(["--repo", str(store.workdir), "--participant", PARTICIPANT,
                 "--state-dir", str(tmp_path / "openai"),
                 "supervisor-import", "--response", str(document)])
    err = capsys.readouterr().err
    assert code == 2
    assert "StaleSupervisorContext" in err and "Traceback" not in err


# ===== no production mutation ============================================

def test_the_handoff_makes_no_repository_change_outside_the_room(store, tmp_path,
                                                                 claim_from_claude):
    _, supervisor_room, _ = claim_from_claude
    cek = "/home/pr0/projects/cek"
    before = subprocess.run(["git", "status", "--porcelain"], cwd=cek,
                            capture_output=True, text=True).stdout
    packet = SupervisorBoundary(supervisor_room).export()
    SupervisorBoundary(supervisor_room).import_response(
        json.dumps(response_document(packet)))
    after = subprocess.run(["git", "status", "--porcelain"], cwd=cek,
                           capture_output=True, text=True).stdout
    assert after == before
