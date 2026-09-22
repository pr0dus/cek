"""Unread / acknowledged state.

Acknowledgement is participant-local bookkeeping. It must survive a restart,
it must never touch the shared message log, and it must not be mistaken for
agreement — a participant can acknowledge a claim it intends to challenge.
"""

from agent_room import AgentRoom, ParticipantCursor


def _two_participants(store, tmp_path):
    claude = AgentRoom(store, "claude-code", ParticipantCursor(tmp_path / "claude", "claude-code"))
    openai = AgentRoom(store, "openai-research", ParticipantCursor(tmp_path / "openai", "openai-research"))
    return claude, openai


def test_unread_then_acknowledged(store, tmp_path):
    claude, openai = _two_participants(store, tmp_path)
    posted = claude.post(
        thread_id="t1", type="question", body={"text": "?"},
        recipient={"agent": "openai-research"},
    )

    assert [m["message_id"] for m in openai.inbox()] == [posted["message_id"]]
    assert not openai.is_acknowledged(posted["message_id"])

    openai.acknowledge(posted["message_id"])

    assert openai.inbox() == []
    assert openai.is_acknowledged(posted["message_id"])


def test_acknowledgement_is_per_participant(store, tmp_path):
    """One participant reading something does not mark it read for the other."""
    claude, openai = _two_participants(store, tmp_path)
    posted = claude.post(thread_id="t1", type="observation", body={"text": "broadcast"})

    openai.acknowledge(posted["message_id"])
    assert openai.inbox() == []

    third = AgentRoom(store, "human", ParticipantCursor(tmp_path / "human", "human"))
    assert [m["message_id"] for m in third.inbox()] == [posted["message_id"]]


def test_own_messages_are_not_in_your_inbox(store, tmp_path):
    claude, _ = _two_participants(store, tmp_path)
    claude.post(thread_id="t1", type="observation", body={"text": "mine"})
    assert claude.inbox() == []


def test_directed_message_is_not_in_a_third_partys_inbox(store, tmp_path):
    claude, openai = _two_participants(store, tmp_path)
    claude.post(thread_id="t1", type="question", body={"text": "?"},
                recipient={"agent": "openai-research"})

    bystander = AgentRoom(store, "other", ParticipantCursor(tmp_path / "other", "other"))
    assert bystander.inbox() == []
    assert len(openai.inbox()) == 1


def test_ack_state_survives_restart_with_the_same_state_dir(store, tmp_path):
    """A new process pointed at the same cursor directory sees prior acks."""
    claude, openai = _two_participants(store, tmp_path)
    first = claude.post(thread_id="t1", type="observation", body={"text": "one"})
    second = claude.post(thread_id="t1", type="observation", body={"text": "two"})
    openai.acknowledge(first["message_id"])

    restarted = AgentRoom(
        store, "openai-research",
        ParticipantCursor(tmp_path / "openai", "openai-research"),
    )
    assert restarted.is_acknowledged(first["message_id"])
    assert [m["message_id"] for m in restarted.inbox()] == [second["message_id"]]


def test_cursor_loss_reverts_to_unread_without_losing_messages(store, tmp_path):
    """Cursor state is rebuildable: losing it costs re-reading, nothing more."""
    claude, openai = _two_participants(store, tmp_path)
    posted = claude.post(thread_id="t1", type="observation", body={"text": "one"})
    openai.acknowledge(posted["message_id"])

    (tmp_path / "openai" / "cursor-openai-research.json").unlink()

    fresh = AgentRoom(store, "openai-research",
                      ParticipantCursor(tmp_path / "openai", "openai-research"))
    assert len(fresh.inbox()) == 1
    assert len(list(store.iter_messages())) == 1


def test_inbox_all_includes_acknowledged(store, tmp_path):
    claude, openai = _two_participants(store, tmp_path)
    posted = claude.post(thread_id="t1", type="observation", body={"text": "one"})
    openai.acknowledge(posted["message_id"])

    assert openai.inbox(unread_only=True) == []
    assert len(openai.inbox(unread_only=False)) == 1


def test_acknowledgement_is_not_agreement(store, tmp_path):
    """Acking a claim leaves its epistemic state exactly where it was."""
    claude, openai = _two_participants(store, tmp_path)
    posted = claude.post(
        thread_id="t1", type="claim", body={"text": "a claim"},
        claim={"status": "proposed"},
    )
    openai.acknowledge(posted["message_id"])

    assert openai.get("t1", posted["message_id"])["claim"]["status"] == "proposed"
    # and the reader remains free to challenge what it has read
    openai.reply(posted["message_id"], type="challenge", body={"text": "disputed"})
    assert len(openai.thread("t1")) == 2
