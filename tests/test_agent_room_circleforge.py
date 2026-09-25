"""Acceptance tests for CircleForge issues #12-#16.

Each section is the reproduction named in the corresponding issue, plus the
controls that issue asks to retain. The common thread is that an *unverifiable*
situation must never be reported as a verified one.
"""

import json
import os
import subprocess
import zlib

import pytest

import agent_room
from agent_room import AgentRoom, GitMessageStore, canonical
from agent_room.cli import main
from agent_room.errors import (
    AgentRoomError,
    AppendOnlyViolation,
    CursorStateError,
    DeliveryError,
    InvalidBranchName,
    PushAmbiguous,
    SchemaError,
)
from agent_room.cursor import ParticipantCursor
from agent_room.ids import uuid7
from agent_room.process import BoundedResult
from tests.conftest_agent_room import configure_identity, git

REPO = "pr0dus/concept-evolution-kernel"
FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"


def loose_object_path(store, oid):
    return store._git_common_dir() / "objects" / oid[:2] / oid[2:]


def flaky_git(monkeypatch, predicate, error=None):
    real_run = subprocess.run

    def run(cmd, **kwargs):
        if predicate(cmd):
            raise (error or subprocess.TimeoutExpired(cmd, 60))
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)


def remote_contains(bare_remote, commit):
    """Independent confirmation, bypassing the store entirely."""
    out = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"],
                         cwd=bare_remote, capture_output=True)
    return out.returncode == 0


def fail_recovery(monkeypatch, *, timeout=True):
    """Inject loss at the streaming runner, not the retired capture seam."""
    def bounded(cmd, **kwargs):
        assert 'ls-remote' in cmd
        if timeout:
            raise subprocess.TimeoutExpired(cmd, 60)
        return BoundedResult(128, b'', b'fatal: unreachable')
    monkeypatch.setattr(agent_room.gitstore, 'run_bounded', bounded)


# ===== #12. delivery uncertainty when reconciliation is unavailable ========

def test_accepted_push_with_lost_ack_and_failed_reconciliation_is_unknown(
        tmp_path, bare_remote, monkeypatch):
    """The exact reproduction from CircleForge #12."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run
    state = {"pushed": False}

    def run(cmd, **kwargs):
        if "push" in cmd and not state["pushed"]:
            state["pushed"] = True
            accepted = real_run(cmd, **kwargs)        # the remote really takes it
            assert accepted.returncode == 0
            raise subprocess.TimeoutExpired(cmd, 60)  # ...and the ack is lost
        if "ls-remote" in cmd or "fetch" in cmd:
            raise subprocess.TimeoutExpired(cmd, 60)  # reconciliation also fails
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    fail_recovery(monkeypatch)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "landed"})
    monkeypatch.undo()

    attempted = exc.value.commit
    assert remote_contains(bare_remote, attempted), "remote really does hold it"
    assert not (exc.value.pushed is False and exc.value.pushed_known is True), \
        "delivery was never disproven, so it must not be reported as failed"
    assert exc.value.pushed is None and exc.value.pushed_known is False
    assert isinstance(exc.value.cause, PushAmbiguous)


def test_cli_exposes_the_same_unknown_delivery_state(tmp_path, bare_remote,
                                                     monkeypatch, capsys):
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)

    real_run = subprocess.run
    state = {"pushed": False}

    def run(cmd, **kwargs):
        if "push" in cmd and not state["pushed"]:
            state["pushed"] = True
            real_run(cmd, **kwargs)
            raise subprocess.TimeoutExpired(cmd, 60)
        if "ls-remote" in cmd or "fetch" in cmd:
            raise subprocess.TimeoutExpired(cmd, 60)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    fail_recovery(monkeypatch)
    code = main(["--repo", str(repo), "--participant", "claude-code",
                 "--remote", str(bare_remote),
                 "post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "x"}'])
    payload = json.loads(capsys.readouterr().out)

    assert code != 0
    assert payload["pushed"] is None and payload["pushed_known"] is False


def test_retry_exhaustion_without_reconciliation_is_unknown(
        tmp_path, bare_remote, monkeypatch):
    """Exhausting retries is not itself proof that nothing was delivered."""
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 2
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run

    def run(cmd, **kwargs):
        if "push" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "fatal: broken pipe")
        if "ls-remote" in cmd:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: unreachable")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    fail_recovery(monkeypatch, timeout=False)
    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert exc.value.pushed is None and exc.value.pushed_known is False


# -- retained controls ------------------------------------------------------

def test_control_exact_reconciliation_proves_delivered(tmp_path, bare_remote,
                                                       monkeypatch):
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    room = AgentRoom(store, "claude-code", None)

    real_run = subprocess.run
    state = {"pushed": False}

    def run(cmd, **kwargs):
        if "push" in cmd and not state["pushed"]:
            state["pushed"] = True
            real_run(cmd, **kwargs)
            raise subprocess.TimeoutExpired(cmd, 60)
        return real_run(cmd, **kwargs)     # reconciliation works

    monkeypatch.setattr(agent_room.gitstore.subprocess, "run", run)
    result = room.post(thread_id="t1", type="observation", body={"text": "x"})
    assert result["pushed"] is True and result["pushed_known"] is True


def test_control_genuine_rejection_proves_not_delivered(tmp_path, bare_remote):
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
    assert not remote_contains(bare_remote, exc.value.commit)


def test_control_retrying_push_does_not_duplicate_the_message(tmp_path, bare_remote):
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    store = GitMessageStore.initialise(tmp_path / "a", branch="agent-room")
    configure_identity(store.workdir)
    store.remote = str(bare_remote)
    store.push_retries = 1
    room = AgentRoom(store, "claude-code", None)

    with pytest.raises(DeliveryError) as exc:
        room.post(thread_id="t1", type="observation", body={"text": "once"})
    first = exc.value.message_id

    hook.unlink()
    assert store.push()["pushed"] is True
    messages = list(store.iter_messages())
    assert len(messages) == 1 and messages[0]["message_id"] == first


# ===== #13. reads must authenticate commit -> tree -> blob ================

def forge_tree_entry(store, thread, victim_rel, forged_text):
    """Replace a tree object under its old OID so it selects a different blob."""
    tree_path = f".agent-room/messages/{thread}"
    tree_oid = git(store.workdir, "rev-parse", f"HEAD:{tree_path}").strip()
    old_blob = git(store.workdir, "rev-parse", f"HEAD:{victim_rel}").strip()

    # Store a genuinely valid replacement blob.
    new_blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"], cwd=store.workdir,
        input=forged_text.encode("utf-8"), capture_output=True,
    ).stdout.decode().strip()

    raw = subprocess.run(["git", "cat-file", "tree", tree_oid], cwd=store.workdir,
                         capture_output=True).stdout
    forged = raw.replace(bytes.fromhex(old_blob), bytes.fromhex(new_blob))
    assert forged != raw, "expected the victim blob id inside the tree"

    body = b"tree %d\0" % len(forged) + forged
    path = loose_object_path(store, tree_oid)
    path.chmod(0o644)
    path.write_bytes(zlib.compress(body))
    return tree_oid, new_blob


def _forged_envelope(store, posted, text):
    envelope = json.loads((store.workdir / posted["path"]).read_text(encoding="utf-8"))
    envelope["body"] = {"text": text}
    del envelope["envelope_sha256"]
    return canonical.canonical_text(canonical.seal(envelope))


def test_cold_read_fails_on_a_forged_tree(store, room):
    """The exact reproduction: corrupt tree selects a valid, resealed blob."""
    victim = room.post(thread_id="t1", type="observation", body={"text": "original"})
    room.post(thread_id="t1", type="observation", body={"text": "sibling"})
    forged = _forged_envelope(store, victim, "forged by a corrupt tree")
    forge_tree_entry(store, "t1", victim["path"], forged)

    fsck = subprocess.run(["git", "fsck", "--strict"], cwd=store.workdir,
                          capture_output=True, text=True)
    assert fsck.returncode != 0, "git fsck --strict must see the object mismatch"

    cold = GitMessageStore(store.workdir, branch="agent-room")
    with pytest.raises(AppendOnlyViolation):
        cold.read("t1", victim["message_id"])


def test_warm_cache_read_fails_on_a_forged_tree(store, room):
    """A warm integrity cache must not mask later object mutation."""
    victim = room.post(thread_id="t1", type="observation", body={"text": "original"})
    room.post(thread_id="t1", type="observation", body={"text": "sibling"})

    assert store.read("t1", victim["message_id"])["body"]["text"] == "original"
    assert store.verify_store() == 2          # warms both caches

    forged = _forged_envelope(store, victim, "forged by a corrupt tree")
    forge_tree_entry(store, "t1", victim["path"], forged)

    with pytest.raises(AppendOnlyViolation):
        store.read("t1", victim["message_id"])
    with pytest.raises(AppendOnlyViolation):
        store.verify_store()


def test_warm_read_rejects_forged_tree_with_unchanged_object_metadata(store, room):
    """Object paths, sizes and mtimes cannot authenticate the selected blob."""
    victim = room.post(thread_id="t1", type="observation", body={"text": "original"})
    tip = git(store.workdir, "rev-parse", store.ref).strip()
    tree_oid = git(store.workdir, "rev-parse", f"{tip}:.agent-room/messages/t1").strip()
    old_blob = git(store.workdir, "rev-parse", f"{tip}:{victim['path']}").strip()
    tree = subprocess.run(
        ["git", "cat-file", "tree", tree_oid], cwd=store.workdir,
        capture_output=True, check=True,
    ).stdout
    forged_text = _forged_envelope(store, victim, "forged with restored metadata")
    # Prepare the valid replacement blob before warming the integrity path:
    # the attack must not add an object file that would invalidate the old cache.
    new_blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"], cwd=store.workdir,
        input=forged_text.encode("utf-8"), capture_output=True, check=True,
    ).stdout.decode().strip()
    forged_tree = tree.replace(bytes.fromhex(old_blob), bytes.fromhex(new_blob))
    assert forged_tree != tree and len(forged_tree) == len(tree)

    # Stored DEFLATE blocks give equal-length encodings for equal-length trees.
    # Re-encoding the genuine tree preserves its OID and passes the warm read.
    header = b"tree %d\0" % len(tree)
    original = zlib.compress(header + tree, level=0)
    replacement = zlib.compress(header + forged_tree, level=0)
    assert len(replacement) == len(original)
    target = loose_object_path(store, tree_oid)
    target.chmod(0o644)
    target.write_bytes(original)
    assert store.read("t1", victim["message_id"])["body"]["text"] == "original"
    assert store.verify_store() == 1

    objects = store._git_common_dir() / "objects"

    def object_metadata():
        return {
            str(path.relative_to(objects)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in objects.rglob("*") if path.is_file()
        }

    before = object_metadata()
    original_stat = target.stat()
    target.write_bytes(replacement)
    os.utime(target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    assert target.read_bytes() != original
    assert object_metadata() == before
    assert git(store.workdir, "rev-parse", store.ref).strip() == tip
    assert git(store.workdir, "show", f"{tip}:{victim['path']}") == forged_text
    fsck = subprocess.run(["git", "fsck", "--strict"], cwd=store.workdir,
                          capture_output=True, text=True)
    assert fsck.returncode != 0, "the forged tree must fail Git object integrity"

    with pytest.raises(AppendOnlyViolation, match="git fsck --strict"):
        store.read("t1", victim["message_id"])


@pytest.mark.parametrize("warm", [False, True])
def test_verify_rejects_forged_tree_that_hides_message_namespace(store, room, warm):
    """Integrity must precede discovery, even when no paths would be loaded."""
    room.post(thread_id="t1", type="observation", body={"text": "original"})
    if warm:
        assert store.verify_store() == 1
    reader = store if warm else GitMessageStore(store.workdir, branch="agent-room")
    tree_oid = git(store.workdir, "rev-parse", "HEAD^{tree}").strip()
    tree = subprocess.run(
        ["git", "cat-file", "tree", tree_oid], cwd=store.workdir,
        capture_output=True, check=True,
    ).stdout
    forged_tree = tree.replace(b".agent-room\0", b".agent-roon\0")
    assert forged_tree != tree
    target = loose_object_path(store, tree_oid)
    target.chmod(0o644)
    target.write_bytes(zlib.compress(b"tree %d\0" % len(forged_tree) + forged_tree))

    with pytest.raises(AppendOnlyViolation, match="git fsck --strict"):
        reader.verify_store()


def test_forged_tree_also_fails_thread_and_iteration(store, room):
    victim = room.post(thread_id="t1", type="observation", body={"text": "original"})
    room.post(thread_id="t1", type="observation", body={"text": "sibling"})
    forge_tree_entry(store, "t1", victim["path"],
                     _forged_envelope(store, victim, "forged"))

    with pytest.raises(AppendOnlyViolation):
        store.thread_messages("t1")
    with pytest.raises(AppendOnlyViolation):
        list(store.iter_messages())


def test_control_normal_reads_and_valid_trees_are_unaffected(store, room):
    a = room.post(thread_id="t1", type="observation", body={"text": "a"})
    b = room.post(thread_id="t2", type="observation", body={"text": "b"})
    assert store.read("t1", a["message_id"])["body"]["text"] == "a"
    assert store.read("t2", b["message_id"])["body"]["text"] == "b"
    assert store.verify_store() == 2
    assert store.read("t1", a["message_id"])["body"]["text"] == "a"   # warm


# ===== #14. branch must be a literal branch name ==========================

@pytest.mark.parametrize("expression", [
    "agent-room~1", "agent-room^", "agent-room@{1}", "agent-room^{}",
    "agent-room..main", "agent-room:path", "agent-room?", "agent-room*",
    "-agent-room", "agent room", "agent-room\n", "",
])
def test_revision_expressions_are_rejected_as_branches(store, expression):
    with pytest.raises(InvalidBranchName):
        GitMessageStore(store.workdir, branch=expression)


@pytest.mark.parametrize("name", ["agent-room", "agent.room-1", "room/x", "a1"])
def test_ordinary_branch_names_are_accepted(store, name):
    assert GitMessageStore(store.workdir, branch=name).ref == f"refs/heads/{name}"


def test_an_expression_cannot_verify_an_earlier_clean_history(store, room):
    """The regression: ~1 previously verified a shorter, cleaner history."""
    room.post(thread_id="t1", type="observation", body={"text": "one"})
    room.post(thread_id="t1", type="observation", body={"text": "two"})
    assert store.verify_store() == 2

    with pytest.raises(InvalidBranchName):
        GitMessageStore(store.workdir, branch="agent-room~1").verify_store()


def test_existence_uses_exact_ref_semantics(store, room):
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    tip = git(store.workdir, "rev-parse", "HEAD").strip()
    git(store.workdir, "tag", "ghost", tip)
    with pytest.raises(AgentRoomError):
        GitMessageStore(store.workdir, branch="ghost").verify_store()


# ===== #15. parsing and cursor-state error contract =======================

def test_committed_invalid_utf8_artifact_fails_controlled(store, room):
    mid = uuid7()
    rel = store.message_path("t1", mid)
    target = store.workdir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b'{"a": "\xff\xfe invalid utf-8"}')
    store._git("add", "--", rel)
    store._commit("invalid utf-8", rel)

    with pytest.raises(SchemaError, match="UTF-8"):
        store.verify_store()


def test_cli_reports_invalid_utf8_without_a_traceback(store, capsys):
    mid = uuid7()
    rel = store.message_path("t1", mid)
    target = store.workdir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b'{"a": "\xff\xfe"}')
    store._git("add", "--", rel)
    store._commit("invalid utf-8", rel)

    code = main(["--repo", str(store.workdir), "--participant", "claude-code", "verify"])
    err = capsys.readouterr().err
    assert code == 2 and "SchemaError" in err
    assert "Traceback" not in err and "UnicodeDecodeError" not in err


@pytest.mark.parametrize("value", [None, [], {}, 7, 1.5, True, object()])
def test_strict_loads_rejects_unsupported_input_types(value):
    with pytest.raises(SchemaError):
        canonical.strict_loads(value)


@pytest.mark.parametrize("payload", [
    pytest.param(b"{not json", id="malformed"),
    pytest.param(b"[]", id="non-object-root"),
    pytest.param(b"null", id="null-root"),
    pytest.param(b'{"schema_version": 1, "participant": "claude-code", '
                 b'"acknowledged": []}', id="acknowledged-array"),
    pytest.param(b'{"schema_version": 1, "participant": "claude-code", '
                 b'"acknowledged": {"m": 7}}', id="acknowledged-entry-scalar"),
    pytest.param(b'{"schema_version": 99, "participant": "claude-code", '
                 b'"acknowledged": {}}', id="wrong-schema-version"),
    pytest.param(b'{"schema_version": 1, "participant": "someone-else", '
                 b'"acknowledged": {}}', id="wrong-participant"),
    pytest.param(b'{"schema_version": 1, "participant": "claude-code", '
                 b'"acknowledged": {}}\xff', id="invalid-utf8"),
])
def test_malformed_cursor_state_fails_controlled(tmp_path, payload):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "cursor-claude-code.json").write_bytes(payload)
    with pytest.raises(CursorStateError):
        ParticipantCursor(state_dir, "claude-code")


def test_cursor_recovery_path_is_deleting_the_file(tmp_path, store, room):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    path = state_dir / "cursor-openai-research.json"
    path.write_text("{corrupt", encoding="utf-8")

    with pytest.raises(CursorStateError, match="Delete the file"):
        ParticipantCursor(state_dir, "openai-research")

    path.unlink()
    cursor = ParticipantCursor(state_dir, "openai-research")
    assert cursor.acknowledged_ids() == set()


def test_valid_cursor_still_round_trips(tmp_path, store, room):
    state_dir = tmp_path / "state"
    claude = AgentRoom(store, "claude-code", ParticipantCursor(state_dir, "claude-code"))
    openai = AgentRoom(store, "openai-research",
                       ParticipantCursor(state_dir, "openai-research"))
    posted = claude.post(thread_id="t1", type="observation", body={"text": "x"})
    openai.acknowledge(posted["message_id"])

    reopened = ParticipantCursor(state_dir, "openai-research")
    assert reopened.is_acknowledged(posted["message_id"])


# ===== #16. IPv4-looking hosts ============================================

@pytest.mark.parametrize("host", [
    "256.1.2.3", "999.999.999.999", "1.2.3.4.5", "1.2.3", "01.02.03.04",
    "192.168.0.256", "1..2.3",
])
def test_ipv4_shaped_hosts_that_are_not_ipv4_are_refused(room, host):
    with pytest.raises(SchemaError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[{"kind": "external", "url": f"https://{host}/x"}])


@pytest.mark.parametrize("url", [
    "https://192.0.2.1/x",
    "http://198.51.100.42:8080/a",
    "https://[2001:db8::1]/x",
    "https://example.test/x",
    "https://xn--bcher-kva.example/x",
])
def test_valid_hosts_are_still_accepted(room, url):
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": url}])


def test_no_dns_resolution_is_performed(room, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("URL validation must not resolve DNS")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    room.post(thread_id="t1", type="evidence", body={"text": "e"},
              evidence=[{"kind": "external", "url": "https://example.test/x"}])
