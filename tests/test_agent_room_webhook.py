import hashlib
import hmac
import json

import pytest

from agent_room import webhook_receiver as wh


SECRET = b"x" * 48


def body(repo=wh.EXPECTED_REPOSITORY, ref=wh.EXPECTED_REF):
    return json.dumps({"repository": {"full_name": repo}, "ref": ref},
                      separators=(",", ":")).encode()


def headers(raw, *, event="push", secret=SECRET):
    sig = hmac.new(secret, raw, hashlib.sha256).hexdigest()
    return {"X-GitHub-Event": event, "X-Hub-Signature-256": "sha256=" + sig}


def test_accepts_only_exact_signed_control_push():
    raw = body()
    doc = wh.validate_delivery(headers(raw), raw, SECRET)
    assert doc["repository"]["full_name"] == wh.EXPECTED_REPOSITORY
    assert doc["ref"] == wh.EXPECTED_REF


@pytest.mark.parametrize("mutation", ["signature", "event", "repo", "ref"])
def test_rejects_wrong_binding(mutation):
    raw = body(repo="other/repo" if mutation == "repo" else wh.EXPECTED_REPOSITORY,
               ref="refs/heads/main" if mutation == "ref" else wh.EXPECTED_REF)
    h = headers(raw, event="issues" if mutation == "event" else "push")
    if mutation == "signature":
        h["X-Hub-Signature-256"] = "sha256=" + "0" * 64
    with pytest.raises(wh.WebhookRefused):
        wh.validate_delivery(h, raw, SECRET)


def test_rejects_oversize_before_json_parse():
    raw = b"{" + b"x" * wh.MAX_BODY_BYTES + b"}"
    with pytest.raises(wh.WebhookRefused):
        wh.validate_delivery(headers(raw), raw, SECRET)


def test_rejects_duplicate_json_keys():
    raw = (b'{"repository":{"full_name":"pr0dus/agent-room-transport"},'
           b'"ref":"refs/heads/agent-room-control",'
           b'"ref":"refs/heads/main"}')
    with pytest.raises(wh.WebhookRefused):
        wh.validate_delivery(headers(raw), raw, SECRET)


def test_wake_runner_coalesces_when_pending(monkeypatch):
    runner = object.__new__(wh.WakeRunner)
    import queue
    runner.queue = queue.Queue(maxsize=1)
    assert runner.wake() == "accepted"
    assert runner.wake() == "coalesced"


def test_accepts_signed_ping_without_control_wake():
    raw = json.dumps({"repository": {"full_name": wh.EXPECTED_REPOSITORY}},
                     separators=(",", ":")).encode()
    doc = wh.validate_ping(headers(raw, event="ping"), raw, SECRET)
    assert doc["repository"]["full_name"] == wh.EXPECTED_REPOSITORY
