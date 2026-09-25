"""C3 correction regressions: real processes/Git; hooks only schedule or crash."""
import json
import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from agent_room import canonical, release
from agent_room.errors import AgentRoomError
from agent_room.remote_sync import Anchor, SyncError
from agent_room.transport import TransportWorker
from agent_room.transport_state import private_lock, WORKER_LOCK
from agent_room.control_store import ControlStore
from tests.conftest_agent_room import git
from tests.test_agent_room_transport_remote_s3 import net, request_document, submit_remote
from tests.test_agent_room_release_c2 import case, reserve, decision, remote_messages


def run_process(config, output, entered=None, pause=None, resume=None,
                boundary='anchor', crash_point=None):
    # Fresh process isolates all hooks; no verification or data is stubbed.
    original_write = Anchor._write
    original_start = TransportWorker._start_clock
    original_replace = os.replace
    paused = False

    def start(worker):
        if entered is not None:
            entered.set()
        return original_start(worker)

    def write(anchor, previous):
        nonlocal paused
        kind = 'control-anchor' if boundary == 'anchor' else 'processed-ledger'
        if not paused and pause is not None and anchor.kind == kind:
            paused = True
            pause.set()
            assert resume.wait(20)
        return original_write(anchor, previous)

    def replace(src, dest, *args, **kwargs):
        if crash_point and str(dest).endswith('control-anchor.json'):
            if crash_point == 'before':
                pause.set()
                time.sleep(30)  # killed by parent, not while owning an Event semaphore
            result = original_replace(src, dest, *args, **kwargs)
            if crash_point == 'after':
                pause.set()
                time.sleep(30)
            return result
        return original_replace(src, dest, *args, **kwargs)

    Anchor._write = write if not crash_point else original_write
    TransportWorker._start_clock = start
    os.replace = replace
    try:
        Path(output).write_text(json.dumps(TransportWorker(config).run()))
    finally:
        Anchor._write = original_write
        TransportWorker._start_clock = original_start
        os.replace = original_replace


def finish(process):
    process.join(20)
    assert process.exitcode == 0


@pytest.mark.parametrize('boundary', ['anchor', 'ledger'])
def test_TWO_REAL_TRANSPORT_PROCESSES_no_regression_or_lost_completion(net, tmp_path, boundary):
    worker = TransportWorker(net['config'])
    assert worker.run()['lifecycle']['status'] == 'ok'
    h0 = worker._control_anchor().get('last_accepted_tip')
    r1 = submit_remote(net, request_document('status'))
    context = mp.get_context('spawn')
    pause, resume, entered = context.Event(), context.Event(), context.Event()
    p1 = context.Process(target=run_process, args=(net['config'], tmp_path/'p1.json'),
                         kwargs=dict(pause=pause, resume=resume, boundary=boundary))
    p2 = context.Process(target=run_process, args=(net['config'], tmp_path/'p2.json'),
                         kwargs=dict(entered=entered))
    p1.start()
    try:
        assert pause.wait(10)
        r2 = submit_remote(net, request_document('supervisor_export'))
        p2.start()
        assert not entered.wait(0.25), 'second process entered lifecycle while first owns lock'
        resume.set()
        finish(p1)
        finish(p2)
        assert json.loads((tmp_path/'p1.json').read_text())['lifecycle']['status'] == 'ok'
        assert json.loads((tmp_path/'p2.json').read_text())['lifecycle']['status'] == 'ok'
        assert set(worker._ledger().get('requests')) == {r1, r2}
        assert worker.run()['processed'] == 0
        accepted = worker._control_anchor().get('last_accepted_tip')
        assert accepted != h0
        git(net['writer_control'].workdir, 'push', '--force', '-q', 'origin',
            f'{h0}:refs/heads/agent-room-control')
        refusal = worker.run()
        assert refusal['lifecycle']['status'] == 'failed'
        assert worker._control_anchor().get('last_accepted_tip') == accepted
        assert ControlStore(net['config'].control_workdir).current_tip() != h0
    finally:
        resume.set()
        for p in (p1, p2):
            if p.pid:
                p.join(2)
                if p.is_alive():
                    p.terminate()
                    p.join(2)


@pytest.mark.parametrize('point', ['before', 'after'])
def test_CONTROL_ANCHOR_CRASH(net, tmp_path, point):
    worker = TransportWorker(net['config'])
    assert worker.run()['lifecycle']['status'] == 'ok'
    old = worker._control_anchor().get('last_accepted_tip')
    rid = submit_remote(net, request_document())
    new = net['writer_control'].current_tip()
    context = mp.get_context('spawn')
    pause, resume = context.Event(), context.Event()
    process = context.Process(target=run_process, args=(net['config'], tmp_path/'killed.json'),
                              kwargs=dict(pause=pause, resume=resume, crash_point=point))
    process.start()
    try:
        assert pause.wait(10)
        process.kill()
        process.join(5)
        assert process.exitcode == -9
        assert worker._control_anchor().get('last_accepted_tip') == (old if point == 'before' else new)
        after = worker.run()
        assert after['lifecycle']['status'] == 'ok'
        assert set(worker._ledger().get('requests')) == {rid}
        assert worker.run()['processed'] == 0
    finally:
        resume.set()
        if process.is_alive():
            process.kill()
            process.join(5)


def hold_lock(path, reached, resume):
    with private_lock(path, WORKER_LOCK):
        reached.set()
        assert resume.wait(15)


def test_lock_busy_no_state_read_and_recovers_after_exception(net, monkeypatch):
    context = mp.get_context('spawn')
    reached, resume = context.Event(), context.Event()
    holder = context.Process(target=hold_lock, args=(net['config'].state_dir, reached, resume))
    holder.start()
    try:
        assert reached.wait(5)
        # Reading state before the lock would fail this test immediately.
        monkeypatch.setattr(TransportWorker, '_ledger', lambda self: pytest.fail('read before lock'))
        report = TransportWorker(net['config']).run()
        assert report['lifecycle']['error_type'] == 'WorkerBusy'
        assert report['processed'] == 0
        assert not (Path(net['config'].state_dir)/'processed.json').exists()
    finally:
        resume.set()
        finish(holder)
    with pytest.raises(RuntimeError):
        with private_lock(net['config'].state_dir, WORKER_LOCK):
            raise RuntimeError('injected exception')
    with private_lock(net['config'].state_dir, WORKER_LOCK):
        pass


@pytest.mark.parametrize('tamper', ['root-symlink', 'ancestor-symlink', 'lock-symlink',
                                  'lock-hardlink', 'root-permissions', 'lock-permissions'])
def test_lock_path_substitution_fails_closed(net, tmp_path, tamper):
    root = Path(net['config'].state_dir)
    root.mkdir(mode=0o700, exist_ok=True)
    lock = root/WORKER_LOCK
    if tamper == 'root-symlink':
        target = tmp_path/'elsewhere'
        target.mkdir(mode=0o700)
        root.rmdir()
        root.symlink_to(target, target_is_directory=True)
    elif tamper == 'ancestor-symlink':
        from dataclasses import replace
        alias = tmp_path/'alias'
        alias.symlink_to(tmp_path, target_is_directory=True)
        net['config'] = replace(net['config'], state_dir=str(alias/'state'))
    elif tamper == 'root-permissions':
        root.chmod(0o755)
    else:
        target = tmp_path/'outside'
        target.write_text('unchanged')
        target.chmod(0o600)
        if tamper == 'lock-symlink':
            lock.symlink_to(target)
        elif tamper == 'lock-hardlink':
            os.link(target, lock)
        else:
            lock.write_text('')
            lock.chmod(0o644)
    report = TransportWorker(net['config']).run()
    assert report['lifecycle']['status'] == 'failed'
    assert report['processed'] == 0


def test_CONTROL_ANCHOR_STALE_WRITER_rechecks_disk_and_pin(net):
    worker = TransportWorker(net['config'])
    worker.sync_control()
    stale = worker._control_anchor()
    old = stale.get('last_accepted_tip')
    submit_remote(net, request_document())
    worker.sync_control()
    new = worker._control_anchor().get('last_accepted_tip')
    assert new != old
    git(net['config'].control_workdir, 'update-ref', 'refs/heads/stale-candidate', old)
    previous = ControlStore(net['config'].control_workdir, 'stale-candidate')
    # Local mode does not exempt monotonicity; no room/source authority mocked.
    with pytest.raises(SyncError, match='regress'):
        stale.advance_control(previous, None, net['config'].control_genesis)
    assert worker._control_anchor().get('last_accepted_tip') == new
    with pytest.raises(SyncError, match='genesis'):
        stale.advance_control(net['control'], None, '0'*40)
    with pytest.raises(SyncError, match='monotonic'):
        stale.set(last_accepted_tip=old)
    before = worker._control_anchor().path.read_bytes()
    worker._control_anchor().advance_control(net['control'], worker._control_remote(), net['config'].control_genesis)
    assert worker._control_anchor().path.read_bytes() == before


@pytest.mark.parametrize('field', ['pending_results', 'uncertain_imports', 'requests'])
def test_stale_state_cannot_erase_new_item(tmp_path, field):
    path = tmp_path/'state'/'processed.json'
    first = Anchor(path, 'processed-ledger')
    first.set(**{field: {'a': {'state': 'pending'}}})
    stale = Anchor(path, 'processed-ledger')
    latest = Anchor(path, 'processed-ledger')
    latest.set(**{field: {'a': {'state': 'pending'}, 'b': {'state': 'pending'}}})
    with private_lock(path.parent, WORKER_LOCK):
        with pytest.raises(SyncError, match='stale'):
            stale.set(**{field: {}})
    assert set(Anchor(path, 'processed-ledger').get(field)) == {'a', 'b'}
    fresh = Anchor(path, 'processed-ledger')
    if field == 'requests':
        with pytest.raises(SyncError, match='completed'):
            fresh.set(requests={})
    else:
        # Clear precisely a (representing its proven delivery), retaining b.
        fresh.set(**{field: {'b': {'state': 'pending'}}})
        assert set(Anchor(path, 'processed-ledger').get(field)) == {'b'}


@pytest.mark.parametrize('change', ['request-delete', 'result-delete', 'result-modify', 'addition'])
def test_merge_topology_always_refused(net, change):
    rid = submit_remote(net, request_document())
    worker = TransportWorker(net['config'])
    assert worker.run()['lifecycle']['status'] == 'ok'
    writer = net['writer_control']
    git(writer.workdir, 'pull', '-q', '--ff-only', 'origin', 'agent-room-control')
    parent = writer.current_tip()
    root = writer.genesis()
    side = git(writer.workdir, 'commit-tree', root+'^{tree}', '-p', root, '-m', 'side').strip()
    req = f'.agent-room-control/requests/{rid}.json'
    res = f'.agent-room-control/results/{rid}.json'
    if change.endswith('delete'):
        git(writer.workdir, 'rm', req if change == 'request-delete' else res)
    elif change == 'result-modify':
        (writer.workdir/res).write_text('{}')
        git(writer.workdir, 'add', res)
    else:
        doc = request_document()
        path = writer.workdir/f'.agent-room-control/requests/{doc["request_id"]}.json'
        path.write_text(json.dumps(doc))
        git(writer.workdir, 'add', str(path))
    tree = git(writer.workdir, 'write-tree').strip()
    merge = git(writer.workdir, 'commit-tree', tree, '-p', parent, '-p', side, '-m', change).strip()
    git(writer.workdir, 'update-ref', writer.ref, merge)
    git(writer.workdir, 'push', '-q', 'origin', 'agent-room-control')
    local_before = net['control'].current_tip()
    report = worker.run()
    assert report['lifecycle']['status'] == 'failed'
    assert 'linear' in report['lifecycle']['error']
    assert net['control'].current_tip() == local_before


def test_LINEAR_APPEND_CONTROL(net):
    rid = submit_remote(net, request_document())
    assert TransportWorker(net['config']).run()['lifecycle']['status'] == 'ok'
    assert net['control'].verify_history()['tracked'] == 2
    assert net['control'].has_result(rid)


@pytest.mark.parametrize('terminal', ['failed', 'executed'])
def test_terminal_preserves_reservation_decision(case, terminal):
    reserve(case)
    git(case.author.workdir, 'pull', '--ff-only', '-q', 'origin', 'agent-room')
    decision(case, 'reject', 'later-B')
    release.reconcile(case.store, case.request, status=terminal, result={},
                      signer=case.signers['release-recorder'], workdir=case.target,
                      checkpoint_path=case.checkpoint, state_path=case.state)
    records = [m['receipt'] for m in remote_messages(case) if m['type'] == 'execution_receipt']
    assert [r['decision_id'] for r in records] == ['initial-approval']*2
    case.store.verify_store()
    with pytest.raises(release.ReleaseBlocked):
        reserve(case)


def test_raw_signed_terminal_cannot_change_authorization(case):
    reserve(case)
    git(case.author.workdir, 'pull', '--ff-only', '-q', 'origin', 'agent-room')
    decision(case, 'reject', 'later-B')
    store = case.author
    env = release._receipt_envelope(store, store.resolve_message(case.request),
              status='failed', result={}, decision_id='later-B', signer=case.signers['release-recorder'])
    path = store.message_path(env['thread_id'], env['message_id'])
    target = store.workdir/path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(canonical.canonical_text(env))
    git(store.workdir, 'add', path)
    git(store.workdir, 'commit', '-qm', 'signed but misattributed terminal')
    with pytest.raises(AgentRoomError, match='provenance'):
        store.verify_store()
