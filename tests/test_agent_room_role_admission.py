"""Issue 16 prerequisite slice; no automatic wake or crash-retry claim.

All Git remotes and signing keys are disposable; clients are fakes.
"""
import json
from pathlib import Path

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical, custody
from agent_room import role_worker as worker
from agent_room.checkpoint import TrustCheckpoint, policy_digest
from agent_room.codex_participant import CodexParticipant
from agent_room.errors import AgentRoomError
from tests.conftest_agent_room import configure_identity, git


def config(role='codex', enabled=True):
    result = dict(key_id=f'{role}-1', room_branch='agent-room',
                  room_remote='origin', enabled=enabled, owner_home=True)
    if role == 'codex':
        result['model'] = 'gpt-6-astra'
    return result


@pytest.mark.parametrize('role', ['codex', 'claude-code'])
@pytest.mark.parametrize('field,value', [
    ('enabled', 'false'), ('enabled', 1), ('enabled', None),
    ('room_branch', 'main'), ('room_remote', '/tmp/evil'),
    ('key_id', ''), ('key_id', []),
    ('argv', ['--dangerously-bypass-approvals-and-sandbox']),
    ('unit', 'evil.service'), ('client', '/tmp/evil'),
    ('workspace', '/tmp/evil'), ('sandbox', 'danger-full-access'),
    ('environment', {'CODEX_MODEL': 'evil'}),
])
def test_config_injection_refused_before_room_or_client(monkeypatch, role, field, value):
    document = config(role)
    document[field] = value
    monkeypatch.setattr(custody, 'guard', lambda r: custody.layout(r))
    monkeypatch.setattr(custody, 'root_json', lambda p: document)
    monkeypatch.setattr(worker, 'room_for', lambda *a: pytest.fail('room constructed'))
    with pytest.raises(custody.CustodyError):
        worker.run(role)


@pytest.mark.parametrize('model', [None, '', 'gpt-6', 'gpt-6-astra --sandbox danger-full-access',
                                   ['gpt-6-astra'], {'name': 'gpt-6-astra'}])
def test_astra_pin_is_exact(model):
    with pytest.raises(custody.CustodyError):
        worker.validate_configuration('codex', dict(config(), model=model))


@pytest.mark.parametrize('role', ['codex', 'claude-code'])
def test_disabled_stops_before_environment_signer_sync_or_client(monkeypatch, role):
    paths = []
    monkeypatch.setattr(custody, 'guard', lambda r: custody.layout(r))
    monkeypatch.setattr(custody, 'root_json', lambda p: paths.append(p) or config(role, False))
    monkeypatch.setattr(custody, 'install_environment', lambda *a: pytest.fail('environment'))
    monkeypatch.setattr(worker, 'room_for', lambda *a: pytest.fail('room'))
    assert worker.run(role) == dict(status='disabled', participant=role, invoked_model=False)
    assert paths == [f'/etc/agent-room/{role}.json']


def test_legacy_config_is_not_implicitly_enabled():
    document = config()
    del document['enabled']
    with pytest.raises(custody.CustodyError):
        worker.validate_configuration('codex', document)


def test_client_settings_are_fixed_despite_environment(monkeypatch):
    from agent_room import codex_participant
    monkeypatch.setenv('CODEX_MODEL', 'evil')
    monkeypatch.setenv('OPENAI_MODEL', 'evil')
    monkeypatch.setenv('CODEX_HOME', '/tmp/evil')
    monkeypatch.setattr(custody, 'guard', lambda r: custody.layout(r))
    monkeypatch.setattr(custody, 'root_json', lambda p: config())
    monkeypatch.setattr(custody, 'root_file', Path)
    monkeypatch.setattr(custody, 'install_environment', lambda *a: None)
    monkeypatch.setattr(worker, 'room_for', lambda *a: 'fake room')

    class Adapter:
        def __init__(self, room, invoker, *, turn_timeout):
            command = invoker.command('/fixed/schema', '/fixed/output')
            assert command[0] == custody.CLIENTS['codex']
            assert command[command.index('--model') + 1] == 'gpt-6-astra'
            assert command[command.index('--sandbox') + 1] == 'danger-full-access'
            assert '--ignore-user-config' in command
            assert command[command.index('-C') + 1] == '/home/pr0'
            assert 'evil' not in ' '.join(command)
            assert turn_timeout == 0

    monkeypatch.setattr(codex_participant, 'CodexParticipant', Adapter)
    monkeypatch.setattr(worker, 'run_verified_turn', lambda *a: {'checked': True})
    assert worker.run('codex') == {'checked': True}


@pytest.fixture
def role_net(signed_store, trust_material, bare_remote, tmp_path):
    source = signed_store
    git(source.workdir, 'remote', 'add', 'origin', str(bare_remote))
    git(source.workdir, 'push', '-q', 'origin', 'agent-room')
    checkout = tmp_path / 'role-room'
    git(tmp_path, 'clone', '-q', '--branch', 'agent-room', str(bare_remote), str(checkout))
    configure_identity(checkout)
    store = GitMessageStore(checkout, branch='agent-room', remote='origin', trust=source.trust)
    checkpoint = tmp_path / 'checkpoint.json'
    TrustCheckpoint.bootstrap(store, expected_genesis=store.room_id(),
                              expected_trust_policy_sha256=policy_digest(store.trust),
                              path=checkpoint)
    room = AgentRoom(store, 'codex', ParticipantCursor(tmp_path / 'cursor', 'codex'),
                     signer=trust_material['signers']['codex'])
    writer = AgentRoom(source, 'openai-research', signer=trust_material['signers']['openai-research'])
    from agent_room.tasks import Journal
    state = tmp_path / 'worker-state'
    Journal(state / 'tasks').save(dict(version=1, room_id=store.room_id(), records={}), enroll=True)
    return room, writer, {'checkpoint': str(checkpoint), 'state': str(state)}, bare_remote


def send(writer):
    from agent_room.tasks import FORMAT
    from agent_room.ids import uuid7
    task = dict(task_id=uuid7(), recipient='codex', instruction='review this')
    message = writer.post(thread_id='task-' + task['task_id'], type='question',
                          recipient={'agent': 'codex'}, reply_requested=True,
                          body={'format': FORMAT, 'text': canonical.canonical_text(task)})
    git(writer.store.workdir, 'push', '-q', 'origin', 'agent-room')
    return message


def test_remote_only_work_synced_before_fake_invocation(role_net):
    room, writer, item, _ = role_net
    target = send(writer)
    assert room.find(target['message_id']) is None
    calls = []

    def invoke(prompt):
        calls.append(prompt)
        assert room.find(target['message_id']) is not None
        checkpoint = TrustCheckpoint.load(item['checkpoint'])
        assert checkpoint.document['last_accepted_tip'] == writer.store.current_tip()
        return json.dumps({'type': 'observation', 'body': {'text': 'reviewed'}})

    worker.run_verified_turn(CodexParticipant(room, invoke, turn_timeout=0), item)
    assert len(calls) == 1
    assert target['message_id'] in calls[0]


def test_no_work_is_clean_idle_after_sync(role_net):
    room, _, item, _ = role_net
    adapter = CodexParticipant(room, lambda p: pytest.fail('client called'), turn_timeout=0)
    assert worker.run_verified_turn(adapter, item) == dict(status='idle',
                 turns=[dict(status='idle', invoked_model=False)], invoked_model=False)


@pytest.mark.parametrize('failure', ['rollback', 'wrong-ref', 'dirty', 'missing-checkpoint',
                                    'corrupt-checkpoint', 'local-unpublished', 'missing-ref'])
def test_sync_refusal_never_invokes(role_net, failure):
    room, writer, item, origin = role_net
    genesis = room.store.current_tip()
    send(writer)
    worker.sync_role_room(room, item)
    checkpoint_before = Path(item['checkpoint']).read_bytes()
    if failure == 'rollback':
        git(origin, 'update-ref', 'refs/heads/agent-room', genesis)
    elif failure == 'wrong-ref':
        git(room.store.workdir, 'checkout', '-q', '-b', 'other')
    elif failure == 'dirty':
        (room.store.workdir / 'untracked').write_text('not a clean role clone')
    elif failure == 'missing-checkpoint':
        Path(item['checkpoint']).unlink()
    elif failure == 'corrupt-checkpoint':
        Path(item['checkpoint']).write_text('{}')
    elif failure == 'local-unpublished':
        room.store.remote = None  # retain an undelivered local commit
        room.post(thread_id='local', type='question', body={'text': 'retain me'})
    else:
        git(origin, 'update-ref', '-d', 'refs/heads/agent-room')
    tip_before = room.store.current_tip()
    adapter = CodexParticipant(room, lambda p: pytest.fail('client called'), turn_timeout=0)
    with pytest.raises(AgentRoomError):
        worker.run_verified_turn(adapter, item)
    assert room.store.current_tip() == tip_before
    if failure not in ('missing-checkpoint', 'corrupt-checkpoint'):
        assert Path(item['checkpoint']).read_bytes() == checkpoint_before


def test_concurrent_role_admission_refuses_without_wait_or_invocation(role_net, monkeypatch):
    from agent_room.participant import TurnLockTimeout
    room, _, item, _ = role_net
    first = CodexParticipant(room, lambda p: pytest.fail('client called'), turn_timeout=0)
    second = CodexParticipant(room, lambda p: pytest.fail('client called'), turn_timeout=0)
    monkeypatch.setattr(worker, 'sync_role_room', lambda *a: pytest.fail('sync without lock'))
    with first.turn_lock(), pytest.raises(TurnLockTimeout):
        worker.run_verified_turn(second, item)


@pytest.mark.parametrize('attack', ['signature', 'oversize'])
def test_untrusted_remote_candidate_not_installed_or_invoked(role_net, attack):
    room, writer, item, _ = role_net
    tip = room.store.current_tip()
    checkpoint = Path(item['checkpoint']).read_bytes()
    message = writer.post(thread_id='hostile', type='question',
                          recipient={'agent': 'codex'}, body={'text': 'original'})
    relative = writer.store.message_path(message['thread_id'], message['message_id'])
    path = writer.store.workdir / relative
    if attack == 'signature':
        document = json.loads(path.read_text())
        document['body']['text'] = 'forged after signature'
        path.write_text(canonical.canonical_text(canonical.seal(document)))
    else:
        path.write_bytes(b'x' * (270 * 1024))
    git(writer.store.workdir, 'add', relative)
    git(writer.store.workdir, 'commit', '--amend', '-qm', 'untrusted candidate')
    git(writer.store.workdir, 'push', '-q', 'origin', 'agent-room')
    adapter = CodexParticipant(room, lambda p: pytest.fail('client called'), turn_timeout=0)
    with pytest.raises(AgentRoomError):
        worker.run_verified_turn(adapter, item)
    assert room.store.current_tip() == tip
    assert Path(item['checkpoint']).read_bytes() == checkpoint


def test_remote_movement_during_verification_refused(role_net, monkeypatch):
    room, writer, item, _ = role_net
    send(writer)
    before = room.store.current_tip()
    original = worker.RoomRemote.required_remote_tip
    observations = []

    def moved(remote):
        observed = original(remote)
        observations.append(observed)
        # First observation precedes fetch. The final pre-install recheck
        # must bind to that verified candidate, not accept new event metadata.
        return observed if len(observations) == 1 else 'f' * 40

    monkeypatch.setattr(worker.RoomRemote, 'required_remote_tip', moved)
    with pytest.raises(AgentRoomError, match='tip changed'):
        worker.run_verified_turn(CodexParticipant(room, lambda p: pytest.fail('client called'),
                                                  turn_timeout=0), item)
    assert room.store.current_tip() == before


def test_committed_reply_push_failure_recovers_without_second_model(role_net, monkeypatch):
    from agent_room.tasks import Journal
    room, writer, item, _ = role_net
    target = send(writer)
    calls = []
    adapter = CodexParticipant(room, lambda p: calls.append(p) or json.dumps({
        'type': 'observation', 'body': {'text': 'one actual model result'}}), turn_timeout=0)
    original = room.store._push_locked
    monkeypatch.setattr(room.store, '_push_locked', lambda: (_ for _ in ()).throw(
        AgentRoomError('lost push acknowledgement')))
    with pytest.raises(AgentRoomError):
        worker.run_verified_turn(adapter, item)
    assert len(calls) == 1
    record = next(iter(Journal(Path(item['state'])/'tasks').load()['records'].values()))
    assert record['phase'] == 'output'
    assert room.find(record['response_id'])['parent_id'] == target['message_id']
    monkeypatch.setattr(room.store, '_push_locked', original)
    assert worker.run_verified_turn(adapter, item)['invoked_model'] is False
    assert len(calls) == 1
    assert next(iter(Journal(Path(item['state'])/'tasks').load()['records'].values()))['phase'] == 'settled'
