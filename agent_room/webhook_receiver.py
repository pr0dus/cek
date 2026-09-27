"""Event-driven wake receiver for the narrow Agent Room supervisor transport.

The GitHub payload is never interpreted as a command.  A valid push to the
one fixed control branch merely wakes one bounded TransportWorker lifecycle.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import canonical, custody
from .transport import TransportConfig, TransportWorker
from .transport_worker import DEFAULT_CONFIG
from .control_result import DEFAULT_DOORBELL_CONFIG, drain as drain_control_results
from .doorbell import configuration as doorbell_configuration
from .errors import AgentRoomError

LISTEN_HOST = "192.168.2.47"
LISTEN_PORT = 8787
WEBHOOK_PATH = "/github/control-wake"
SECRET_PATH = "/etc/agent-room/webhook.secret"
EXPECTED_REPOSITORY = "pr0dus/agent-room-transport"
EXPECTED_REF = "refs/heads/agent-room-control"
MAX_BODY_BYTES = 64 * 1024
# One request per connection, with a total deadline (not a resettable idle
# timeout). Even a peer sending one byte just before each timeout is bounded.
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_REQUEST_BYTES = MAX_BODY_BYTES + 16 * 1024


class WebhookRefused(ValueError):
    """The request is not the one fixed wake signal accepted here."""


def _require(condition, reason):
    if not condition:
        raise WebhookRefused(reason)


def load_secret(path: str = SECRET_PATH) -> bytes:
    custody.root_file(path)
    raw = Path(path).read_text(encoding="ascii").strip()
    _require(32 <= len(raw) <= 256, "invalid webhook secret length")
    _require(all(33 <= ord(ch) <= 126 for ch in raw), "invalid webhook secret")
    return raw.encode("ascii")


def verify_signature(signature: str | None, body: bytes, secret: bytes) -> None:
    _require(isinstance(signature, str) and signature.startswith("sha256="),
             "missing webhook signature")
    supplied = signature[7:]
    _require(len(supplied) == 64 and all(ch in "0123456789abcdef" for ch in supplied),
             "malformed webhook signature")
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(supplied, expected), "webhook signature mismatch")


def _signed_document(headers, body: bytes, secret: bytes) -> dict:
    _require(isinstance(body, (bytes, bytearray)), "webhook body type")
    _require(len(body) <= MAX_BODY_BYTES, "webhook body too large")
    verify_signature(headers.get("X-Hub-Signature-256"), bytes(body), secret)
    try:
        document = canonical.strict_loads(bytes(body).decode("utf-8"))
    except (UnicodeError, ValueError, AgentRoomError) as exc:
        raise WebhookRefused("invalid webhook JSON") from exc
    _require(isinstance(document, dict), "webhook root must be an object")
    repository = document.get("repository")
    _require(isinstance(repository, dict)
             and repository.get("full_name") == EXPECTED_REPOSITORY,
             "wrong webhook repository")
    return document


def validate_delivery(headers, body: bytes, secret: bytes) -> dict:
    _require(headers.get("X-GitHub-Event") == "push", "wrong GitHub event")
    document = _signed_document(headers, body, secret)
    _require(document.get("ref") == EXPECTED_REF, "wrong webhook ref")
    return document


def validate_ping(headers, body: bytes, secret: bytes) -> dict:
    _require(headers.get("X-GitHub-Event") == "ping", "wrong GitHub event")
    return _signed_document(headers, body, secret)


class WakeRunner:
    """Coalesce concurrent pushes while guaranteeing a later reconciliation pass."""

    def __init__(self, config: TransportConfig, doorbell_config: dict):
        self.config = config
        self.doorbell_config = doorbell_configuration(doorbell_config)
        self.queue = queue.Queue(maxsize=1)
        self.thread = threading.Thread(target=self._loop,
                                       name="agent-room-control-wake",
                                       daemon=True)
        self.thread.start()
        # One reconciliation pass at service start closes the only crash
        # window after an HTTP 202: the durable control branch is the queue.
        self.wake()

    def wake(self) -> str:
        try:
            self.queue.put_nowait(object())
            return "accepted"
        except queue.Full:
            return "coalesced"

    def _loop(self) -> None:
        while True:
            self.queue.get()
            try:
                summary = TransportWorker(self.config).run()
                status = summary.get("lifecycle", {}).get("status")
                if status != "ok":
                    raise RuntimeError("narrow transport lifecycle did not settle")
                wakes = drain_control_results(self.config, self.doorbell_config)
                print(json.dumps({"event": "control-wake-complete",
                                  "status": status,
                                  "processed": summary.get("processed"),
                                  "remaining": summary.get("remaining"),
                                  "result_wakes": len(wakes)},
                                 sort_keys=True), flush=True)
                if (summary.get("remaining") or 0) > 0:
                    self.wake()
            except Exception as exc:  # noqa: BLE001 - journal gets type only
                print(json.dumps({"event": "control-wake-failed",
                                  "error_type": type(exc).__name__},
                                 sort_keys=True), flush=True)
                # The control branch is durable. A systemd restart performs a
                # startup reconciliation pass; never silently drop a 202 wake.
                os._exit(1)
            finally:
                self.queue.task_done()


class _DeadlineReader(io.RawIOBase):
    def __init__(self, connection, deadline):
        super().__init__()
        self.connection = connection
        self.deadline = deadline
        self.remaining = MAX_REQUEST_BYTES

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining_time = self.deadline - time.monotonic()
        if remaining_time <= 0:
            raise TimeoutError('webhook request deadline')
        if self.remaining <= 0:
            raise WebhookRefused('webhook request byte limit')
        self.connection.settimeout(remaining_time)
        count = self.connection.recv_into(buffer, min(len(buffer), self.remaining))
        self.remaining -= count
        return count


class _Handler(BaseHTTPRequestHandler):
    server_version = "AgentRoomWebhook/1"
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection, self.deadline))

    def handle(self):
        # Deliberately no keep-alive loop. HTTPServer is serial, so the
        # connection/thread bound is one, with a small fixed accept backlog.
        try:
            self.handle_one_request()
        except (OSError, WebhookRefused):
            self.close_connection = True

    def handle_expect_100(self):
        self._reply(417, {'status': 'expectation_failed'})
        return False

    def log_message(self, fmt, *args):  # no payload/header logging
        return

    def _reply(self, status: int, document: dict) -> None:
        self.close_connection = True
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return
        self.connection.settimeout(remaining)
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(405, {"status": "method_not_allowed"})

    def do_POST(self):
        if self.path != WEBHOOK_PATH:
            self._reply(404, {"status": "not_found"})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get_all('Transfer-Encoding')
                or len(lengths) != 1
                or not lengths[0].isascii()
                or not lengths[0].isdigit()
                or len(lengths[0]) > 6
                or any(len(self.headers.get_all(name, [])) != 1 for name in
                       ('X-GitHub-Event', 'X-Hub-Signature-256'))):
            self._reply(400, {"status": "bad_request"})
            return
        length = int(lengths[0])
        if length < 0 or length > MAX_BODY_BYTES:
            self._reply(413, {"status": "too_large"})
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._reply(400, {"status": "bad_request"})
            return
        try:
            event = self.headers.get("X-GitHub-Event")
            if event == "ping":
                validate_ping(self.headers, body, self.server.secret)
                self._reply(200, {"status": "pong"})
                return
            validate_delivery(self.headers, body, self.server.secret)
        except WebhookRefused:
            self._reply(403, {"status": "refused"})
            return
        state = self.server.runner.wake()
        self._reply(202, {"status": state})


class AgentRoomWebhookServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self, address, handler, *, secret: bytes, runner: WakeRunner):
        self.secret = secret
        self.runner = runner
        super().__init__(address, handler)


def main() -> int:
    item = custody.guard("openai-research")
    custody.root_file(DEFAULT_CONFIG)
    config = TransportConfig.load(DEFAULT_CONFIG)
    custody.check_transport(config, item)
    custody.root_file(DEFAULT_DOORBELL_CONFIG)
    doorbell_config = canonical.strict_loads(
        Path(DEFAULT_DOORBELL_CONFIG).read_text(encoding="utf-8"))
    doorbell_configuration(doorbell_config)
    custody.install_environment("openai-research", item)
    secret = load_secret()
    runner = WakeRunner(config, doorbell_config)
    server = AgentRoomWebhookServer((LISTEN_HOST, LISTEN_PORT), _Handler,
                                    secret=secret, runner=runner)
    print(json.dumps({"event": "agent-room-webhook-listening",
                      "host": LISTEN_HOST, "port": LISTEN_PORT,
                      "path": WEBHOOK_PATH}), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
