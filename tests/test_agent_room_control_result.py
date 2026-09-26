import os

import pytest

from agent_room import canonical
from agent_room import control_result as cr
from agent_room import doorbell_protocol as dp
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7


def _result(request_id=None):
    request_id = request_id or uuid7()
    return {
        "control_schema_version": 1,
        "request_id": request_id,
        "operation": "status",
        "request_sha256": "a" * 64,
        "status": "ok",
        "completed_at": "2026-09-26T07:00:00Z",
        "room_tip": "b" * 40,
        "detail": {"ok": True},
    }


def test_service_result_copy_is_write_once(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    result = _result()
    cr.record_produced(state, result)
    cr.record_produced(state, result)
    changed = dict(result)
    changed["status"] = "failed"
    with pytest.raises(AgentRoomError):
        cr.record_produced(state, changed)


def test_control_result_wake_is_bound_to_signed_report_identity():
    request_id = uuid7()
    report = {
        "message_id": request_id,
        "timestamp": "2026-09-26T07:00:00Z",
        "sender": {"agent": "openai-research"},
        "recipient": {"agent": "openai-research"},
        "type": "observation",
        "body": {
            "format": dp.CONTROL_RESULT_FORMAT,
            "request_id": request_id,
            "result_sha256": "c" * 64,
            "status": "ok",
            "operation": "supervisor_export",
        },
        canonical.DIGEST_FIELD: "d" * 64,
    }
    event = dp.from_control_result("e" * 40, report)
    assert event["role"] == "openai-research"
    assert event["event_kind"] == "control_result"
    assert event["report_id"] == request_id
    assert dp.validate_event(event) == event


def test_control_result_rejects_mismatched_request_identity():
    request_id = uuid7()
    report = {
        "message_id": uuid7(),
        "timestamp": "2026-09-26T07:00:00Z",
        "sender": {"agent": "openai-research"},
        "recipient": {"agent": "openai-research"},
        "type": "observation",
        "body": {
            "format": dp.CONTROL_RESULT_FORMAT,
            "request_id": request_id,
            "result_sha256": "c" * 64,
            "status": "ok",
            "operation": "status",
        },
        canonical.DIGEST_FIELD: "d" * 64,
    }
    with pytest.raises(AgentRoomError):
        dp.from_control_result("e" * 40, report)
