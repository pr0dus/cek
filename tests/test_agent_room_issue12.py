"""Restoration regressions; disposable stores, no client/network/model calls."""
import hashlib
import json

import pytest
from agent_room import canonical
from agent_room.control_store import ControlStore, ControlNamespaceViolation, ControlAppendOnlyViolation
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7
from agent_room import control_store, task_admission
from agent_room.tasks import execute
from agent_room.transport import TransportWorker, TransportRefused
from tests.test_agent_room_tasks17 import enrolled, submit, adapter, task
from tests.test_agent_room_transport_s3 import env, request_document


def annotation(tmp_path, monkeypatch):
    store = ControlStore.initialise(tmp_path/'control')
    file = store.workdir/control_store.HISTORICAL_ANNOTATION
    file.parent.mkdir(parents=True)
    file.write_text('{"verified":true,"inert_test":true}\n')
    store._git('add', '--', control_store.HISTORICAL_ANNOTATION)
    add = store._commit('synthetic historical annotation')
    blob = store._git('rev-parse', 'HEAD:'+control_store.HISTORICAL_ANNOTATION).stdout.decode().strip()
    monkeypatch.setattr(control_store, 'HISTORICAL_ADD', add)
    monkeypatch.setattr(control_store, 'HISTORICAL_BLOB', blob)
    return store, file


def test_exact_annotation_inert_and_not_a_request_result(tmp_path, monkeypatch):
    s,_=annotation(tmp_path,monkeypatch)
    assert s.verify_history()['tracked']==0
    assert s.requests()==[] and s.assert_namespace_closed()=={'genesis':1,'request':0,'result':0}


@pytest.mark.parametrize('change', ['bytes', 'executable', 'other_path', 'delete', 'false_add'])
def test_annotation_exception_remains_closed(tmp_path,monkeypatch,change):
    s,f=annotation(tmp_path,monkeypatch)
    if change=='bytes': f.write_text('{}')
    elif change=='executable': f.chmod(0o755)
    elif change=='other_path': (f.parent/'other.json').write_text('{}')
    elif change=='delete': f.unlink()
    else: monkeypatch.setattr(control_store,'HISTORICAL_ADD','0'*40)
    if change!='false_add':
        s._git('add','-A'); s._commit('invalid mutation')
    with pytest.raises((ControlNamespaceViolation,ControlAppendOnlyViolation)):s.verify_history()


def admission(params,requests=None):
    return task_admission.validate(dict(version=1,requests=requests or {},tasks={params['task_id']:hashlib.sha256(canonical.canonical_bytes(params)).hexdigest()}))


def test_old_task_held_new_task_exact_and_restart_at_most_once(env):
    enrolled(env)
    old=task();new=task();submit(env,old);submit(env,new)
    calls=[]
    a,j=adapter(env,lambda p:calls.append(p) or json.dumps({'type':'observation','body':{'text':'done'}}))
    a.task_admission=admission(new)
    assert execute(a,j)['task_id']==new['task_id']
    assert execute(a,j)['status']=='idle'
    assert len(calls)==1 and len(j.load()['records'])==1
    assert not task_admission.task_allowed(a.task_admission,dict(new,instruction='changed'))


def test_transport_old_submission_held_without_journal_or_wake(env):
    j=enrolled(env);w=TransportWorker(env['config']);w.task_admission=admission(task())
    with pytest.raises(TransportRefused):w._op_task_submit(env['room'],task())
    assert j.load()['records']=={}


def test_admission_request_bytes_bound_and_wrong_schema_denied():
    params=task(); rid=uuid7(); policy=admission(params,{rid:'1'*64})
    assert task_admission.request_allowed(policy,rid,'1'*64)
    assert not task_admission.request_allowed(policy,rid,'2'*64)
    assert not task_admission.request_allowed(policy,uuid7(),'1'*64)
    for bad in ({},dict(policy,argv=['evil']),dict(policy,version=True),dict(policy,requests={'bad':'1'*64})):
        with pytest.raises(AgentRoomError):task_admission.validate(bad)


def test_held_historical_unsettled_submission_is_not_reconciled(env,monkeypatch):
    j=enrolled(env);params=task();w=TransportWorker(env['config'])
    monkeypatch.setattr(w,'_accept_after_delivery',lambda *a:(_ for _ in ()).throw(AgentRoomError('lost publication')))
    with pytest.raises(AgentRoomError):w._op_task_submit(env['room'],params)
    before=j.load(); assert before['records'][params['task_id']]['phase']=='output'
    w.task_admission=admission(task())
    w.reconcile_tasks()
    assert j.load()==before


def test_unlisted_malformed_request_held_while_enrolled_status_advances(env):
    w=TransportWorker(env['config']);s=ControlStore(env['config'].control_workdir)
    old=uuid7();path=s.workdir/('.agent-room-control/requests/'+old+'.json')
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text('not JSON')
    s._git('add','--',str(path.relative_to(s.workdir)));s._commit('malformed old request')
    new=request_document('status',{}); s.submit_request(new)
    entry=next(e for e in s.requests() if e['request_id']==new['request_id'])
    _,sha=s.read_request(entry);w.task_admission=admission(task(),{new['request_id']:sha})
    result=w.run()
    assert result['processed']==1 and result['held_request_ids']==[old]
    assert old not in w._ledger().document['requests']


def test_admitted_uncertain_intent_not_replayed_and_hold_preserves_it(env):
    enrolled(env);params=task();submit(env,params);calls=[]
    def crash(prompt):calls.append(prompt);raise RuntimeError('lost model response')
    a,j=adapter(env,crash);a.task_admission=admission(params)
    with pytest.raises(RuntimeError):execute(a,j)
    before=j.load()
    assert execute(a,j)['status']=='uncertain' and len(calls)==1
    a.task_admission=admission(task())
    assert execute(a,j)['status']=='idle' and j.load()==before and len(calls)==1


@pytest.mark.parametrize('structured', [None, [], 'text', {'type':'observation','body':{'text':'review'}}])
def test_claude_schema_channel_not_plain_result(monkeypatch,structured):
    from types import SimpleNamespace
    from agent_room import claude_participant as cp
    raw=json.dumps({'is_error':False,'result':'','structured_output':structured}).encode()
    monkeypatch.setattr(cp,'run_bounded',lambda *a,**k:SimpleNamespace(timed_out=False,output_limited=False,returncode=0,stderr=b'',stdout=raw))
    if isinstance(structured,dict):assert json.loads(cp.ClaudeInvoker()('prompt'))==structured
    else:
        with pytest.raises(AgentRoomError):cp.ClaudeInvoker()('prompt')


def test_claude_schema_channel_cannot_mask_client_error(monkeypatch):
    from types import SimpleNamespace
    from agent_room import claude_participant as cp
    raw=json.dumps({'is_error':True,'result':'auth failed','structured_output':{'type':'observation','body':{'text':'forged success'}}}).encode()
    monkeypatch.setattr(cp,'run_bounded',lambda *a,**k:SimpleNamespace(timed_out=False,output_limited=False,returncode=0,stderr=b'',stdout=raw))
    with pytest.raises(AgentRoomError):cp.ClaudeInvoker()('prompt')
