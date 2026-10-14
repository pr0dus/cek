import json
from pathlib import Path

import pytest

from agent_room import AgentRoom, ParticipantCursor, canonical
from agent_room.codex_participant import CodexParticipant, CodexInvoker
from agent_room.claude_participant import ClaudeInvoker
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7
from agent_room.tasks import Journal, validate, extract, execute, FORMAT
from agent_room.transport import TransportWorker, validate_request
from tests.test_agent_room_transport_s3 import env, request_document
from tests.test_agent_room_transport_remote_s3 import net


def task():
    return dict(task_id=uuid7(), recipient='codex', instruction='Return a bounded observation.')


def enrolled(env):
    journal = Journal(Path(env['config'].state_dir) / 'tasks')
    journal.save(dict(version=1, room_id=env['room'].room_id(), records={}), enroll=True)
    return journal


def submit(env, params=None):
    return TransportWorker(env['config'])._op_task_submit(env['room'], params or task())


def adapter(env, invoke):
    room = AgentRoom(env['room'], 'codex', ParticipantCursor(env['tmp']/'codex', 'codex'),
                     signer=env['signers']['codex'])
    journal = Journal(env['tmp']/'attempts')
    journal.save(dict(version=1, room_id=room.store.room_id(), records={}), enroll=True)
    return CodexParticipant(room, invoke), journal


def test_fresh_task_submission_is_signed_idempotent_and_content_bound(env):
    enrolled(env)
    params = task()
    first = submit(env, params)
    second = submit(env, params)
    assert first == second
    message = env['room'].resolve_message(first['message_id'])
    assert message['sender']['agent'] == 'openai-research' and 'auth' in message
    assert extract(message, 'codex') == params
    with pytest.raises(AgentRoomError):
        submit(env, dict(params, instruction='Different task'))


def test_one_attempt_and_restart_no_duplicate(env):
    enrolled(env); submit(env)
    calls = []
    a, j = adapter(env, lambda p: calls.append(p) or json.dumps({
        'type':'observation', 'body':{'text':'done','format':'agent-room-terminal-v1/end_report'}}))
    assert execute(a,j)['invoked_model']
    assert execute(a,Journal(j.root))['status'] == 'idle'
    assert len(calls) == 1


def test_crash_inside_model_is_uncertain_never_replayed(env):
    enrolled(env); submit(env)
    calls = []
    def crash(prompt):
        calls.append(prompt)
        raise RuntimeError('lost response')
    a,j = adapter(env,crash)
    with pytest.raises(RuntimeError): execute(a,j)
    assert execute(a,Journal(j.root))['status'] == 'uncertain'
    assert len(calls) == 1


def test_output_survives_publication_failure_without_model_repeat(env, monkeypatch):
    enrolled(env); submit(env)
    calls = []
    a,j = adapter(env,lambda p: calls.append(p) or json.dumps({'type':'observation','body':{'text':'done'}}))
    original = a.room.reply
    monkeypatch.setattr(a.room,'reply',lambda *a,**k: (_ for _ in ()).throw(AgentRoomError('publication failed')))
    with pytest.raises(AgentRoomError): execute(a,j)
    monkeypatch.setattr(a.room,'reply',original)
    assert execute(a,Journal(j.root))['status'] == 'responded'
    assert len(calls) == 1


@pytest.mark.parametrize('value', [None, [], {}, True, 0, '', {'task_id':'fake'}])
def test_wrong_task_shapes_fail_closed(value):
    with pytest.raises(AgentRoomError): validate(value)


@pytest.mark.parametrize('field', ['argv','unit','model','shell','sandbox','auth','workspace','approval'])
def test_no_infrastructure_or_authority_override(field):
    with pytest.raises(AgentRoomError):
        validate_request(request_document('task_submit', dict(task(), **{field:'evil'})))


@pytest.mark.parametrize('role', ['human','release-recorder','openai-research','broadcast'])
def test_no_consequential_or_broadcast_task(role):
    with pytest.raises(AgentRoomError): validate(dict(task(), recipient=role))


@pytest.mark.parametrize('raw', ['null','{}','[]','{"version":1}', '{', ''])
def test_corrupt_journal_is_not_empty(env,raw):
    j=enrolled(env); (j.root/'tasks.json').write_text(raw)
    with pytest.raises(AgentRoomError): j.load()


def test_missing_journal_refuses_and_double_enrollment_refuses(env):
    j=Journal(env['tmp']/'absent')
    with pytest.raises(AgentRoomError): j.load()
    j=enrolled(env)
    with pytest.raises(AgentRoomError): j.save(j.load(),enroll=True)


def test_default_clients_remain_restricted_owner_home_is_explicit():
    assert '--restricted' in ClaudeInvoker().command()
    assert CodexInvoker().command('/s','/o')[3:5] == ['--sandbox','read-only']
    c=CodexInvoker(cwd='/home/pr0',owner_home=True).command('/s','/o')
    assert c[c.index('--sandbox')+1]=='danger-full-access'
    assert '--ignore-user-config' in c and '--ignore-rules' not in c
    assert 'approval_policy="on-request"' in c
    cl=ClaudeInvoker(cwd='/home/pr0',owner_home=True).command()
    assert '--safe-mode' in cl and '--restricted' not in cl
    assert 'bypassPermissions' not in cl and cl[cl.index('--permission-mode')+1]=='manual'
    for cls in (ClaudeInvoker,CodexInvoker):
        with pytest.raises(AgentRoomError): cls(cwd='/tmp',owner_home=True)


def test_non_supervisor_and_broadcast_history_is_not_enrolled(env):
    a,j=adapter(env,lambda p: pytest.fail('old traffic invoked model'))
    assert execute(a,j)['status']=='idle'
    assert j.load()['records']=={}


def test_instruction_invalid_unicode_is_controlled():
    with pytest.raises(AgentRoomError): validate(dict(task(), instruction='\ud800'))


def test_submission_recovery_same_identity_after_push_failure(env, monkeypatch):
    enrolled(env)
    w = TransportWorker(env['config'])
    params = task()
    original = w._accept_after_delivery
    monkeypatch.setattr(w, '_accept_after_delivery', lambda *a: (_ for _ in ()).throw(
        AgentRoomError('checkpoint publication interrupted')))
    with pytest.raises(AgentRoomError): w._op_task_submit(env['room'], params)
    j=Journal(Path(env['config'].state_dir)/'tasks')
    record=j.load()['records'][params['task_id']]
    assert record['phase']=='output'
    monkeypatch.setattr(w, '_accept_after_delivery', original)
    w.reconcile_tasks()
    assert j.load()['records'][params['task_id']]['phase']=='settled'
    assert sum(m['message_id']==record['message_id'] for m in env['room'].iter_messages())==1


def test_real_remote_submission_and_same_id_recovery(net):
    enrolled(net)
    w=TransportWorker(net['config'])
    params=task()
    first=w._op_task_submit(net['room'],params)
    remote=w._room_remote()
    assert remote.required_remote_tip()==net['room'].current_tip()
    assert w._op_task_submit(net['room'],params)==first
    assert sum(m['message_id']==first['message_id'] for m in net['room'].iter_messages())==1


def test_real_remote_task_movement_is_reconciled_with_same_envelope(net,monkeypatch):
    from agent_room.remote_sync import RoomRemote
    from tests.conftest_agent_room import git
    enrolled(net)
    w=TransportWorker(net['config'])
    params=task()
    original=RoomRemote.push_with_lease
    moved=[]
    def concurrent(remote,expected):
        if not moved:
            net['other'].post(thread_id='concurrent',type='observation',body={'text':'unrelated'})
            git(net['other_room'].workdir,'push','-q','origin','agent-room')
            moved.append(True)
        return original(remote,expected)
    monkeypatch.setattr(RoomRemote,'push_with_lease',concurrent)
    with pytest.raises(AgentRoomError): w._op_task_submit(net['room'],params)
    journal=Journal(Path(net['config'].state_dir)/'tasks')
    before=journal.load()['records'][params['task_id']]
    assert before['phase']=='output'
    w.recover_room(); w.sync_room(); w.reconcile_tasks()
    after=journal.load()['records'][params['task_id']]
    assert after['phase']=='settled' and after['payload']==before['payload']
    assert w._room_remote().required_remote_tip()==net['room'].current_tip()
