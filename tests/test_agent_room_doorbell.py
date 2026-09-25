"""Focused public fixtures: no models, live roles, secrets or GitHub requests."""
import copy
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from agent_room import AgentRoom, ParticipantCursor, canonical
from agent_room.checkpoint import TrustCheckpoint, policy_digest
from agent_room.claude_participant import ClaudeParticipant
from agent_room.codex_participant import CodexParticipant
from agent_room.doorbell import Doorbell, GitHubPR, MAX_HTTP_BYTES, MAX_PAGES
from agent_room.doorbell_protocol import (
    DoorbellError, FIELDS, KINDS, PREFIX, ROLES, decode, encode,
    event_identity, from_report, terminal_kind, verify_notice,
)
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7
from tests.conftest_agent_room import git

CONFIG = dict(repository='example/room', pull_number=1, pull_node_id='PR_test1',
              actor_ids={'claude-code': 23, 'codex': 24})
SECRET = 'sensitive-content-must-never-leave-signed-room'


class FakeGitHub:
    def __init__(self):
        self.posts, self.comments, self.finds = [], [], []
        self.mode = 'success'
        self.targets = 0

    def check_target(self):
        self.targets += 1

    def post(self, event):
        self.posts.append(encode(event))
        if self.mode == 'before-acceptance':
            raise DoorbellError('network failure')
        self.comments.append(encode(event))
        if self.mode == 'lost-ack':
            raise DoorbellError('acknowledgement lost after real acceptance')
        return len(self.comments)

    def find(self, event):
        self.finds.append(encode(event))
        return self.comments.index(encode(event)) + 1 if encode(event) in self.comments else None


@pytest.fixture
def rig(signed_store, trust_material, bare_remote, tmp_path):
    store = signed_store
    git(store.workdir, 'remote', 'add', 'origin', str(bare_remote))
    git(store.workdir, 'push', '-q', 'origin', 'HEAD:refs/heads/agent-room')
    store.remote = 'origin'
    cp = TrustCheckpoint.bootstrap(store, expected_genesis=store.room_id(),
        expected_trust_policy_sha256=policy_digest(store.trust), path=tmp_path / 'checkpoint.json')
    api = FakeGitHub()
    doors, rooms = {}, {}
    for role in ROLES:
        rooms[role] = AgentRoom(store, role, ParticipantCursor(tmp_path / ('cursor-' + role), role),
                               signer=trust_material['signers'][role])
        doors[role] = Doorbell(store, cp, tmp_path / ('doorbell-' + role), CONFIG, role, api)
        doors[role].ledger.initialise()
    return SimpleNamespace(store=store, cp=cp, api=api, rooms=rooms, doors=doors,
                           material=trust_material, tmp=tmp_path)


def report(rig, role='codex', kind='end_report', **extra):
    posted = rig.rooms[role].post(thread_id=SECRET, type='observation',
        body={'text': SECRET, 'format': PREFIX + kind},
        recipient={'agent': 'openai-research'}, **extra)
    return rig.store.resolve_message(posted['message_id'])


def event():
    value = dict(protocol='agent-room-doorbell', schema_version=1, room_id='a' * 40,
                 report_id=uuid7(), role='codex', event_kind='end_report',
                 timestamp='2026-09-25T12:00:00Z', envelope_sha256='b' * 64)
    value['event_id'] = event_identity(value['room_id'], value['report_id'], value['envelope_sha256'])
    return value


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('kind', KINDS)
def test_signed_terminal_only_metadata_emitted_and_supervisor_reopens(rig, role, kind):
    original = report(rig, role, kind)
    result = rig.doors[role].drain()
    assert result['status'] == 'delivered'
    raw = rig.api.posts[0]
    assert SECRET not in raw and len(raw.encode()) <= 1024
    assert set(json.loads(raw)) == FIELDS
    assert verify_notice(raw, rig.store, rig.cp) == original
    assert len(rig.api.posts) == 1


def test_routine_no_github_and_unknown_terminal_fail_closed(rig):
    rig.rooms['codex'].post(thread_id='t1', type='observation', body={'text': 'task complete!'},
                           recipient={'agent': 'openai-research'})
    assert rig.doors['codex'].drain()['status'] == 'idle'
    assert rig.api.targets == 0
    report(rig, kind='run-shell')
    with pytest.raises(DoorbellError):
        rig.doors['codex'].drain()
    assert rig.api.posts == []


@pytest.mark.parametrize('role,adapter', [('codex', CodexParticipant), ('claude-code', ClaudeParticipant)])
@pytest.mark.parametrize('terminal', [False, True])
def test_terminal_routed_to_supervisor_without_changing_routine_reply(rig, role, adapter, terminal):
    coordinator = AgentRoom(rig.store, 'coordinator', ParticipantCursor(rig.tmp / 'coordinator', 'coordinator'),
                            signer=rig.material['signers']['coordinator'])
    posted = coordinator.post(thread_id='t1', type='question', body={'text': 'bounded task'},
                              recipient={'agent': role}, reply_requested=True)
    body = {'text': SECRET}
    if terminal:
        body['format'] = PREFIX + 'verification_complete'
    def invoke(prompt):
        assert PREFIX in prompt
        return json.dumps({'type': 'answer', 'body': body})
    result = adapter(rig.rooms[role], invoke).run_turn()
    assert result['status'] == 'responded'
    reply = list(rig.store.iter_messages())[-1]
    assert reply['parent_id'] == posted['message_id']
    assert reply['recipient'] == {'agent': 'openai-research' if terminal else 'coordinator'}
    assert rig.doors[role].drain()['status'] == ('delivered' if terminal else 'idle')


def test_decision_request_marker_is_notification_not_approval():
    assert terminal_kind({'type': 'decision_request', 'human_approval_required': True}) == 'human_required'
    with pytest.raises(DoorbellError):
        terminal_kind({'type': 'decision_request', 'human_approval_required': False})


@pytest.mark.parametrize('field,value', [('report_id', 'missing'), ('room_id', 'c' * 40),
    ('envelope_sha256', 'd' * 64), ('role', 'claude-code'), ('event_kind', 'blocked')])
def test_supervisor_rejects_missing_or_mismatched_actual_report(rig, field, value):
    original = report(rig)
    notice = from_report(rig.store.room_id(), original)
    notice[field] = uuid7() if value == 'missing' else value
    notice['event_id'] = event_identity(notice['room_id'], notice['report_id'], notice['envelope_sha256'])
    with pytest.raises(AgentRoomError):
        verify_notice(encode(notice), rig.store, rig.cp)


def test_unsigned_store_cannot_supply_supervisor_evidence(rig):
    notice = encode(from_report(rig.store.room_id(), report(rig)))
    rig.store.trust = None
    with pytest.raises(DoorbellError):
        verify_notice(notice, rig.store, rig.cp)


def test_verified_report_uses_existing_supervisor_export_import(rig):
    from agent_room.supervisor import SupervisorBoundary
    original = report(rig)
    notice = encode(from_report(rig.store.room_id(), original))
    verified = verify_notice(notice, rig.store, rig.cp)
    room = AgentRoom(rig.store, 'openai-research', ParticipantCursor(rig.tmp / 'supervisor', 'openai-research'),
                     signer=rig.material['signers']['openai-research'])
    boundary = SupervisorBoundary(room)
    packet = boundary.export(verified['message_id'])
    assert packet['target_message_id'] == original['message_id']
    assert SECRET in json.dumps(packet)
    # The full private packet remains off GitHub; only the notice is posted.
    rig.doors['codex'].drain()
    assert SECRET not in rig.api.posts[0]
    result = boundary.import_response({
        'packet_schema_version': packet['packet_schema_version'],
        'target_message_id': packet['target_message_id'],
        'context_sha256': packet['context_sha256'],
        'response': {'type': 'answer', 'body': {'text': 'Evidence reviewed; bounded follow-up only.'}},
    })
    assert result['status'] == 'responded'
    assert rig.doors['codex'].drain()['status'] == 'idle'
    assert len(rig.api.posts) == 1  # supervisor response cannot feed back a notification loop


def test_remote_delivery_unproven_never_notifies(rig, monkeypatch):
    report(rig)
    monkeypatch.setattr(rig.store, '_reconcile_push', lambda tip: (None, False, None))
    with pytest.raises(DoorbellError):
        rig.doors['codex'].drain()
    assert rig.api.posts == []


def test_restart_concurrency_and_multiple_delivery_calls_are_idempotent(rig):
    report(rig)
    door = rig.doors['codex']
    second = Doorbell(rig.store, rig.cp, door.ledger.root, CONFIG, 'codex', rig.api)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda d: d.drain()['status'], [door, second]))
    assert sorted(results) == ['delivered', 'idle']
    assert second.drain()['status'] == 'idle'
    assert len(rig.api.posts) == 1


@pytest.mark.parametrize('mode', ['before-acceptance', 'lost-ack'])
def test_ambiguous_post_get_only_never_reposts(rig, mode):
    report(rig)
    rig.api.mode = mode
    door = rig.doors['codex']
    assert door.drain()['status'] == 'uncertain'
    for _ in range(3):
        result = door.drain()
    assert result['status'] == ('idle' if mode == 'lost-ack' else 'uncertain')
    assert len(rig.api.posts) == 1
    assert len(rig.api.comments) == (1 if mode == 'lost-ack' else 0)


def test_crash_after_durable_intent_cannot_cause_new_post(rig, monkeypatch):
    report(rig)
    def crash(event):
        raise SystemExit('simulated crash before POST')
    monkeypatch.setattr(rig.api, 'post', crash)
    with pytest.raises(SystemExit):
        rig.doors['codex'].drain()
    monkeypatch.setattr(rig.api, 'post', lambda event: pytest.fail('must not repost'))
    assert rig.doors['codex'].drain()['status'] == 'uncertain'


def test_crash_after_github_receipt_before_local_receipt_reconciles(rig, monkeypatch):
    report(rig)
    ledger = rig.doors['codex'].ledger
    save = ledger.save
    def crash(doc):
        if any(e['state'] == 'delivered' for e in doc['events'].values()):
            raise SystemExit('crash after real comment')
        return save(doc)
    monkeypatch.setattr(ledger, 'save', crash)
    with pytest.raises(SystemExit):
        rig.doors['codex'].drain()
    monkeypatch.setattr(ledger, 'save', save)
    assert rig.doors['codex'].drain()['status'] == 'delivered'
    assert len(rig.api.posts) == 1


@pytest.mark.parametrize('raw', ['null', '{}', '{', '[]', '{"version":1,"version":1}', 'true'])
def test_corrupt_ledger_never_treated_as_first_run(rig, raw):
    ledger = rig.doors['codex'].ledger
    (ledger.root / 'ledger.json').write_text(raw)
    with pytest.raises(AgentRoomError):
        rig.doors['codex'].drain()
    assert rig.api.posts == []


def test_explicit_enrollment_cannot_reset_existing_ledger(rig):
    with pytest.raises(AgentRoomError):
        rig.doors['codex'].ledger.initialise()


def test_ledger_identity_rejects_boolean_and_role_substitution(rig):
    ledger = rig.doors['codex'].ledger
    doc = ledger.load()
    doc['identity']['config']['pull_number'] = True
    with pytest.raises(DoorbellError):
        ledger.save(doc)
    doc = ledger.load()
    doc['identity']['role'] = 'claude-code'
    with pytest.raises(DoorbellError):
        ledger.save(doc)


def test_one_pass_and_ledger_capacity_bounded(rig, monkeypatch):
    import agent_room.doorbell as module
    for _ in range(3):
        report(rig)
    monkeypatch.setattr(module, 'MAX_EVENTS_PER_PASS', 2)
    assert rig.doors['codex'].drain()['remaining'] == 1
    assert len(rig.api.posts) == 2
    monkeypatch.setattr(module, 'MAX_RECORDS', 2)
    with pytest.raises(DoorbellError):
        rig.doors['codex'].drain()
    assert len(rig.api.posts) == 2


@pytest.mark.parametrize('raw', ['null', '[]', 'true', '0', '"text"', '\ud800',
                                '{"protocol":1,"protocol":2}', 'x' * 1025])
def test_malformed_notice_controlled_error(raw):
    with pytest.raises(AgentRoomError):
        decode(raw)


@pytest.mark.parametrize('field,value', [('schema_version', True), ('role', ['codex']),
    ('event_kind', 'shell'), ('timestamp', 'not-a-date'), ('envelope_sha256', SECRET),
    ('event_id', 'a' * 64), ('body', SECRET), ('command', 'echo secret')])
def test_notice_strict_allowlist(field, value):
    notice = event()
    notice[field] = value
    with pytest.raises(AgentRoomError):
        encode(notice)


def client():
    return GitHubPR(CONFIG, 'codex', 'test_token_NOT_A_CREDENTIAL')


def comment(notice):
    return dict(id=99, user={'id': 24}, body=encode(notice),
                issue_url='https://api.github.com/repos/example/room/issues/1')


@pytest.mark.parametrize('field,value', [('user', {'id': 99}), ('id', True),
    ('body', '{}'), ('issue_url', 'https://attacker.invalid/issues/1')])
def test_response_comment_binds_actor_target_and_exact_body(monkeypatch, field, value):
    github, notice = client(), event()
    response = comment(notice)
    response[field] = value
    monkeypatch.setattr(github, '_request', lambda *a: response)
    with pytest.raises(DoorbellError):
        github.post(notice)


def test_pr_must_be_exact_open_target(monkeypatch):
    github = client()
    valid = dict(state='open', node_id=CONFIG['pull_node_id'], number=1,
                 base={'repo': {'full_name': CONFIG['repository']}})
    monkeypatch.setattr(github, '_request', lambda *a: valid)
    github.check_target()
    for key, bad in [('state', 'closed'), ('node_id', 'different'), ('number', 2), ('base', {})]:
        changed = dict(valid, **{key: bad})
        monkeypatch.setattr(github, '_request', lambda *a: changed)
        with pytest.raises(DoorbellError):
            github.check_target()


def test_reconciliation_duplicate_and_pagination_bounds(monkeypatch):
    github, notice = client(), event()
    monkeypatch.setattr(github, '_request', lambda *a: [comment(notice), comment(notice)])
    with pytest.raises(DoorbellError):
        github.find(notice)
    calls = []
    def page(*args):
        calls.append(args)
        return [{'body': 'irrelevant'}] * 100
    monkeypatch.setattr(github, '_request', page)
    with pytest.raises(DoorbellError, match='bound'):
        github.find(notice)
    assert len(calls) == MAX_PAGES


@pytest.mark.parametrize('status,length', [(302, None), (401, None), (200, str(MAX_HTTP_BYTES + 1)),
                                         (200, None)])
def test_http_fixed_endpoint_bounded_response_no_secret_errors(monkeypatch, status, length):
    import agent_room.doorbell as module
    reads, requests = [], []
    class Response:
        def getheader(self, name):
            return length
        def read(self, count):
            reads.append(count)
            return b'x' * count
    response = Response()
    response.status = status
    class Connection:
        def __init__(self, host, timeout):
            assert host == 'api.github.com' and timeout == 10
        def request(self, *args, **kwargs):
            requests.append((args, kwargs))
        def getresponse(self):
            return response
        def close(self):
            pass
    monkeypatch.setattr(module.http.client, 'HTTPSConnection', Connection)
    with pytest.raises(DoorbellError) as exc:
        client().check_target()
    assert 'test_token' not in str(exc.value)
    assert all(count == MAX_HTTP_BYTES + 1 for count in reads)
    assert requests[0][0][:2] == ('GET', '/repos/example/room/pulls/1')


def test_http_post_payload_contains_only_notice(monkeypatch):
    github, notice = client(), event()
    calls = []
    def request(method, suffix, payload):
        calls.append((method, suffix, payload))
        return comment(notice)
    monkeypatch.setattr(github, '_request', request)
    assert github.post(notice) == 99
    assert calls == [('POST', '/issues/1/comments', {'body': encode(notice)})]


def test_worker_recovers_only_no_model_on_uncertainty(monkeypatch):
    from agent_room import doorbell_worker as worker
    fake = SimpleNamespace(ledger=SimpleNamespace(load=lambda: {}),
                           drain=lambda: {'status': 'uncertain', 'events': []})
    monkeypatch.setattr(worker, 'prepare', lambda role: fake)
    monkeypatch.setattr(worker.role_worker, 'run', lambda role: pytest.fail('model must not run'))
    assert worker.run('codex')['model_invoked'] is False
    assert worker.run('codex', 'recover')['model_invoked'] is False


def test_worker_post_turn_failure_preserves_result_never_reinvokes(monkeypatch):
    from agent_room import doorbell_worker as worker
    calls, drains = [], []
    def drain():
        drains.append(1)
        if len(drains) > 1:
            raise DoorbellError('notification failure')
        return {'status': 'idle', 'events': []}
    fake = SimpleNamespace(ledger=SimpleNamespace(load=lambda: {}), drain=drain)
    monkeypatch.setattr(worker, 'prepare', lambda role: fake)
    monkeypatch.setattr(worker.role_worker, 'run', lambda role: calls.append(role) or {'message_id': 'retained'})
    result = worker.run('codex')
    assert result['participant_result'] == {'message_id': 'retained'}
    assert result['notification']['status'] == 'unresolved'
    assert calls == ['codex']
