"""CLI surface.

The CLI is one-shot by construction: each command runs, prints JSON and exits.
There is no daemon, no poller and no scheduling here, and these tests check the
operations Issue #2 requires are actually reachable from the command line.
"""

import json

import pytest

from agent_room.cli import main
from tests.conftest_agent_room import configure_identity


@pytest.fixture
def cli(tmp_path, capsys):
    repo = tmp_path / "room"
    state = tmp_path / "state"

    def run(*args, participant="claude-code", expect=0):
        argv = ["--repo", str(repo), "--participant", participant,
                "--state-dir", str(state), *args]
        code = main(argv)
        out = capsys.readouterr().out
        assert code == expect, f"exit {code} for {args}: {out}"
        return json.loads(out) if code == 0 and out.strip() else None

    assert main(["--repo", str(repo), "--participant", "claude-code", "init"]) == 0
    capsys.readouterr()
    configure_identity(repo)
    return run


def test_post_get_and_thread(cli):
    posted = cli("post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "hello"}')
    assert posted["status"] == "created"

    got = cli("get", "--thread-id", "t1", "--message-id", posted["message_id"])
    assert got["body"]["text"] == "hello"
    assert len(got["envelope_sha256"]) == 64

    assert len(cli("thread", "--thread-id", "t1")) == 1


def test_reply_links_to_parent(cli):
    root = cli("post", "--thread-id", "t1", "--type", "question", "--body", '{"text": "?"}')
    child = cli("reply", "--parent-id", root["message_id"], "--type", "answer",
                "--body", '{"text": "!"}')
    assert child["thread_id"] == "t1"

    tree = cli("thread", "--thread-id", "t1", "--tree")
    assert tree[1]["parent_id"] == root["message_id"]


def test_inbox_and_ack(cli):
    posted = cli("post", "--thread-id", "t1", "--type", "observation",
                 "--body", '{"text": "broadcast"}')
    assert len(cli("inbox", participant="openai-research")) == 1
    cli("ack", "--message-id", posted["message_id"], participant="openai-research")
    assert cli("inbox", participant="openai-research") == []
    assert len(cli("inbox", "--all", participant="openai-research")) == 1


def test_queries(cli):
    cli("post", "--thread-id", "t1", "--type", "observation", "--body", '{"text": "a"}',
        "--project", '{"repo": "pr0dus/cek"}')
    cli("post", "--thread-id", "t2", "--type", "observation", "--body", '{"text": "b"}',
        "--project", '{"repo": "pr0dus/concept-evolution-kernel"}')

    assert len(cli("query", "--project-repo", "pr0dus/cek")) == 1
    assert len(cli("query", "--thread-id", "t2")) == 1
    assert len(cli("query", "--participant-name", "claude-code")) == 2
    assert cli("threads") == ["t1", "t2"]


def test_verify_walks_every_digest(cli):
    cli("post", "--thread-id", "t1", "--type", "observation", "--body", '{"text": "a"}')
    cli("post", "--thread-id", "t1", "--type", "observation", "--body", '{"text": "b"}')
    assert cli("verify") == {"verified": 2}


@pytest.mark.parametrize("mtype", ["approval", "rejection"])
def test_cli_refuses_approval_and_rejection(cli, mtype):
    """No agent-facing path to asserting human authority."""
    cli("post", "--thread-id", "t1", "--type", mtype, "--body", '{"text": "approved"}',
        expect=2)


def test_cli_rejects_malformed_input(cli):
    cli("post", "--thread-id", "t1", "--type", "nonsense", "--body", '{"text": "x"}', expect=2)
    cli("post", "--thread-id", "t1", "--type", "observation", "--body", "not-json", expect=2)


def test_cli_supported_claim_rules_apply(cli):
    cli("post", "--thread-id", "t1", "--type", "claim", "--body", '{"text": "c"}',
        "--claim", '{"status": "supported", "evidence_basis": ["e1"]}', expect=2)

    ok = cli("post", "--thread-id", "t1", "--type", "claim", "--body", '{"text": "c"}',
             "--evidence", '[{"id":"e1","kind":"repo","commit":"40ffdf4617283f4accb3493a8a710c5025c5d3bc","path":"x.py"}]',
             "--claim", '{"status":"supported","scope":"at 40ffdf4617283f4accb3493a8a710c5025c5d3bc",'
                        '"revision_condition":"a counterexample","evidence_basis":["e1"]}')
    assert ok["status"] == "created"
