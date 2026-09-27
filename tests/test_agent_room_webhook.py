import hashlib
import hmac
import json
import io
from types import SimpleNamespace

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


class Connection:
    """Deterministic HTTP peer; no listening service or external network."""
    def __init__(self, raw, *, chunk=8192):
        self.input = io.BytesIO(raw)
        self.output = bytearray()
        self.timeouts = []
        self.chunk = chunk
        self.received = 0

    def makefile(self, *a):
        return io.BytesIO()

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def recv_into(self, buffer, size):
        data = self.input.read(min(size, self.chunk))
        buffer[:len(data)] = data
        self.received += len(data)
        return len(data)

    def sendall(self, data):
        self.output.extend(data)


def request(raw=None, *, extra=(), length=None, event='push'):
    raw = body() if raw is None else raw
    fields = [f'Content-Length: {len(raw) if length is None else length}',
              *(f'{key}: {value}' for key, value in headers(raw, event=event).items()), *extra]
    return ('POST ' + wh.WEBHOOK_PATH + ' HTTP/1.1\r\n' + '\r\n'.join(fields)
            + '\r\n\r\n').encode() + raw


def deliver(raw, connection=None):
    calls = []
    server = SimpleNamespace(secret=SECRET,
                             runner=SimpleNamespace(wake=lambda: calls.append(True) or 'accepted'))
    peer = connection or Connection(raw)
    wh._Handler(peer, ('fake-peer', 1), server)
    return bytes(peer.output), calls, peer


def test_http_valid_control_wake_exactly_once_and_no_keepalive():
    response, calls, _ = deliver(request(extra=['Connection: keep-alive']) + request())
    assert response.startswith(b'HTTP/1.1 202')
    assert b'Connection: close' in response
    assert len(calls) == 1
    assert response.count(b'HTTP/1.1') == 1


def test_http_ping_does_not_wake():
    response, calls, _ = deliver(request(event='ping'))
    assert response.startswith(b'HTTP/1.1 200')
    assert not calls


@pytest.mark.parametrize('extra', [
    ['Content-Length: 1'], ['Transfer-Encoding: chunked'],
    ['X-GitHub-Event: push'], ['X-Hub-Signature-256: sha256=' + '0' * 64],
    ['Expect: 100-continue'],
])
def test_ambiguous_framing_or_expectation_never_wakes(extra):
    response, calls, _ = deliver(request(extra=extra))
    assert response.startswith((b'HTTP/1.1 400', b'HTTP/1.1 417'))
    assert not calls


@pytest.mark.parametrize('length', ['-1', '+1', '1, 1', 'x', '00000000001', '65537'])
def test_http_bad_or_oversized_length_never_wakes(length):
    response, calls, peer = deliver(request(length=length))
    assert response.startswith((b'HTTP/1.1 400', b'HTTP/1.1 413'))
    assert not calls
    assert peer.received <= wh.MAX_REQUEST_BYTES


def test_short_body_never_wakes():
    response, calls, _ = deliver(request()[:-1])
    assert response.startswith(b'HTTP/1.1 400')
    assert not calls


@pytest.mark.parametrize('ref', ['refs/heads/agent-room', 'agent-room-control',
                                'refs/tags/agent-room-control', 'refs/heads/main'])
def test_unimplemented_room_routing_and_wrong_refs_stay_closed(ref):
    response, calls, _ = deliver(request(body(ref=ref)))
    assert response.startswith(b'HTTP/1.1 403')
    assert not calls


def test_wrong_signature_never_wakes():
    raw = request().replace(b'"repository"', b'"repositorY"')
    response, calls, _ = deliver(raw)
    assert response.startswith(b'HTTP/1.1 403')
    assert not calls


def test_total_header_byte_budget():
    raw = request(extra=['X-Padding: ' + 'x' * 2000] * 50)
    response, calls, peer = deliver(raw)
    assert not calls
    assert peer.received == wh.MAX_REQUEST_BYTES


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_slow_drip_cannot_extend_absolute_deadline(monkeypatch, phase):
    now = [0.0]
    monkeypatch.setattr(wh.time, 'monotonic', lambda: now[0])
    raw = request()
    body_offset = raw.index(b'\r\n\r\n') + 4

    class Slow(Connection):
        def recv_into(self, buffer, size):
            count = super().recv_into(buffer, size)
            if phase == 'headers' or self.received > body_offset:
                now[0] += 1
            return count

    peer = Slow(raw, chunk=1)
    response, calls, _ = deliver(raw, peer)
    assert not calls
    assert now[0] <= wh.REQUEST_TIMEOUT_SECONDS
    assert peer.timeouts[-1] <= 1


def test_wake_arrival_while_active_is_retained():
    import queue
    runner = object.__new__(wh.WakeRunner)
    runner.queue = queue.Queue(maxsize=1)
    runner.wake()
    runner.queue.get_nowait()  # the worker begins its active pass
    assert runner.wake() == 'accepted'
    assert runner.wake() == 'coalesced'
    runner.queue.task_done()
    assert runner.queue.qsize() == 1  # next event-driven pass is still queued
