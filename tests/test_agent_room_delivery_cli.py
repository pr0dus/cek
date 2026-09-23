"""CLI delivery recovery and malformed identifier handling.

A CLI-only participant must be able to recover from the one failure mode that
is genuinely ambiguous — the message is committed locally but never reached the
remote — without reposting it under a fresh UUID and duplicating it in
permanent history. And no malformed input may escape as a raw Python error,
because the CLI's error handling only contracts to catch Agent Room errors.
"""

import json

import pytest

import agent_room
from agent_room import GitMessageStore
from agent_room.cli import EXIT_PARTIAL_DELIVERY, main
from agent_room.errors import ClaimStateError, SchemaError
from tests.conftest_agent_room import configure_identity

FULL_SHA = "40ffdf4617283f4accb3493a8a710c5025c5d3bc"
REPO_EVIDENCE = {"kind": "repo", "repo": "pr0dus/concept-evolution-kernel", "commit": FULL_SHA, "path": "x.py"}


# -- public API --------------------------------------------------------------

def test_delivery_error_is_publicly_exported():
    """Participants are expected to catch it, so it must be importable."""
    assert "DeliveryError" in agent_room.__all__
    assert agent_room.DeliveryError is agent_room.errors.DeliveryError


# -- 2. CLI partial-delivery recovery, end to end ---------------------------

@pytest.fixture
def cli_remote(tmp_path, bare_remote, capsys):
    """A CLI bound to a remote that is initially rejecting all pushes."""
    hook = bare_remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    repo = tmp_path / "room"
    store = GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)

    def run(*args, expect=0):
        argv = ["--repo", str(repo), "--participant", "claude-code",
                "--remote", str(bare_remote), "--state-dir", str(tmp_path / "state"), *args]
        code = main(argv)
        out = capsys.readouterr().out
        assert code == expect, f"exit {code} for {args}: {out}"
        return json.loads(out) if out.strip() else None

    return run, bare_remote, store


def test_cli_post_then_push_recovers_without_reposting(cli_remote):
    run, remote, store = cli_remote

    # 1. Post against the rejecting remote — structured partial delivery.
    result = run("post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "held"}', expect=EXIT_PARTIAL_DELIVERY)

    assert result["locally_committed"] is True
    assert result["pushed"] is False
    for field in ("message_id", "commit", "path", "error"):
        assert result[field], f"{field} missing from partial-delivery result"
    message_id = result["message_id"]

    # 2. The message is already durable locally.
    assert len(list(store.iter_messages())) == 1

    # 3. Remove the rejection and retry delivery via the CLI.
    (remote / "hooks" / "pre-receive").unlink()
    pushed = run("push")
    assert pushed["pushed"] is True

    # 4. Exactly one message, still the original id — no repost happened.
    messages = list(store.iter_messages())
    assert len(messages) == 1
    assert messages[0]["message_id"] == message_id
    assert run("verify") == {"verified": 1}


def test_cli_partial_delivery_exit_code_is_non_zero(cli_remote):
    run, _, _ = cli_remote
    assert EXIT_PARTIAL_DELIVERY != 0
    run("post", "--thread-id", "t1", "--type", "observation",
        "--body", '{"text": "x"}', expect=EXIT_PARTIAL_DELIVERY)


def test_cli_push_is_a_one_shot_command(cli_remote):
    """It returns a result and exits; it does not wait or loop."""
    run, remote, _ = cli_remote
    (remote / "hooks" / "pre-receive").unlink()
    run("post", "--thread-id", "t1", "--type", "observation", "--body", '{"text": "a"}')
    pushed = run("push")
    assert pushed["pushed"] is True and pushed["pushed_known"] is True
    assert pushed["attempts"] == 1


def test_cli_push_without_remote_says_so(tmp_path, capsys):
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)
    assert main(["--repo", str(repo), "--participant", "claude-code", "push"]) == 0
    assert json.loads(capsys.readouterr().out)["pushed"] is False


# -- 3. malformed identifiers stay inside the schema contract ---------------

@pytest.mark.parametrize("bad_id", [
    pytest.param([], id="array"),
    pytest.param({}, id="object"),
    pytest.param("", id="empty-string"),
    pytest.param("   ", id="blank-string"),
    pytest.param(7, id="number"),
])
def test_malformed_evidence_id_is_a_schema_error(room, bad_id):
    with pytest.raises(SchemaError, match="non-empty string"):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, id=bad_id)])


@pytest.mark.parametrize("bad_entry", [
    pytest.param([], id="array"),
    pytest.param({}, id="object"),
    pytest.param("", id="empty-string"),
    pytest.param("  ", id="blank-string"),
    pytest.param(None, id="null"),
    pytest.param(3, id="number"),
])
def test_malformed_evidence_basis_entry_is_a_claim_error(room, bad_entry):
    with pytest.raises(ClaimStateError, match="non-empty string"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            evidence=[dict(REPO_EVIDENCE, id="e1")],
            claim={"status": "supported", "scope": "s",
                   "revision_condition": "r", "evidence_basis": [bad_entry]},
        )


def test_duplicate_evidence_basis_entries_are_rejected(room):
    with pytest.raises(ClaimStateError, match="duplicated"):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            evidence=[dict(REPO_EVIDENCE, id="e1")],
            claim={"status": "supported", "scope": "s",
                   "revision_condition": "r", "evidence_basis": ["e1", "e1"]},
        )


@pytest.mark.parametrize("bad", [[], {}, "", 7])
def test_malformed_ids_never_escape_as_typeerror(room, bad):
    """The CLI only contracts to catch Agent Room errors."""
    from agent_room.errors import AgentRoomError

    with pytest.raises(AgentRoomError):
        room.post(thread_id="t1", type="evidence", body={"text": "e"},
                  evidence=[dict(REPO_EVIDENCE, id=bad)])
    with pytest.raises(AgentRoomError):
        room.post(
            thread_id="t1", type="claim", body={"text": "c"},
            claim={"status": "supported", "scope": "s",
                   "revision_condition": "r", "evidence_basis": [bad]},
        )


def test_cli_reports_malformed_identifiers_cleanly(tmp_path, capsys):
    repo = tmp_path / "room"
    GitMessageStore.initialise(repo, branch="agent-room")
    configure_identity(repo)
    code = main([
        "--repo", str(repo), "--participant", "claude-code",
        "post", "--thread-id", "t1", "--type", "evidence", "--body", '{"text":"e"}',
        "--evidence", '[{"id": [], "kind": "repo", "commit": "' + FULL_SHA + '", "path": "x.py"}]',
    ])
    assert code == 2
    assert "SchemaError" in capsys.readouterr().err


def test_well_formed_identifiers_still_work(room):
    posted = room.post(
        thread_id="t1", type="claim", body={"text": "c"},
        evidence=[dict(REPO_EVIDENCE, id="e1")],
        claim={"status": "supported", "scope": f"at commit {FULL_SHA}",
               "revision_condition": "a counterexample", "evidence_basis": ["e1"]},
    )
    assert posted["status"] == "created"
