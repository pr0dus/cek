"""S3-G1/G2/G3: exact delivery knowledge, not process exit, closes a request."""
import json
import hashlib
from pathlib import Path

import pytest

from agent_room import canonical
from agent_room.checkpoint import TrustCheckpoint
from agent_room.remote_sync import AmbiguousDelivery, RoomRemote, ControlRemote, SyncError
from agent_room import remote_sync
from agent_room.transport import TransportConfig, TransportWorker
from tests.conftest_agent_room import git
from tests.test_agent_room_transport_remote_s3 import (
    net, bound_response, remote_supervisor_messages, remote_tip,
    request_document, submit_remote, push_other, run,
)


def uncertain_start(net, monkeypatch, *, accepted=False):
    document = request_document('supervisor_import', {'response': bound_response(net)})
    rid = submit_remote(net, document)
    real = RoomRemote.push_with_lease
    calls = []

    def lose_ack(self, expected):
        calls.append((self.local_tip(), expected))
        if accepted:
            real(self, expected)
        raise AmbiguousDelivery('fault: remote acceptance cannot be inspected')

    with monkeypatch.context() as patch:
        patch.setattr(RoomRemote, 'push_with_lease', lose_ack)
        summary = run(net)
    worker = TransportWorker(net['config'])
    ledger = worker._ledger()
    assert rid not in ledger.get('requests', {}), 'unknown must not be terminal'
    assert rid not in ledger.get('pending_results', {}), 'no final ok result'
    entry = ledger.get('uncertain_imports', {})[rid]
    assert entry['state'] == 'uncertain_delivery'
    assert entry['request_id'] == rid
    assert entry['request_sha256'] == hashlib.sha256(canonical.canonical_text(document).encode()).hexdigest()
    assert entry['target_message_id'] == document['params']['response']['target_message_id']
    assert entry['context_sha256'] == document['params']['response']['context_sha256']
    assert (entry['local_tip'], entry['expected_remote_head']) == calls[0]
    assert summary['results'][0]['status'] == 'uncertain_delivery'
    return rid, entry


def final_ok(net, rid):
    worker = TransportWorker(net['config'])
    ledger = worker._ledger()
    assert ledger.get('requests', {})[rid]['status'] == 'ok'
    assert rid not in ledger.get('uncertain_imports', {})
    assert rid not in ledger.get('pending_results', {})
    assert len(remote_supervisor_messages(net)) == 1
    assert TrustCheckpoint.load(net['config'].checkpoint_path).document['last_accepted_tip'] == remote_tip(net)


def forbid_signature(*args, **kwargs):
    pytest.fail('reconciliation must reuse the existing signed response')


def test_ROOM_PUSH_UNKNOWN_THEN_PROVEN_ABSENT(net, monkeypatch):
    rid, entry = uncertain_start(net, monkeypatch)
    assert remote_supervisor_messages(net) == []
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    assert run(net)['lifecycle']['status'] == 'ok'
    final_ok(net, rid)
    assert remote_tip(net) == entry['local_tip'], 'same signed commit, same lease'


def test_ROOM_PUSH_UNKNOWN_THEN_PROVEN_PRESENT(net, monkeypatch):
    rid, entry = uncertain_start(net, monkeypatch, accepted=True)
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', forbid_signature)
    assert run(net)['lifecycle']['status'] == 'ok'
    final_ok(net, rid)
    assert remote_tip(net) == entry['local_tip']


def test_ROOM_PUSH_UNKNOWN_THEN_CONTEXT_CHANGED(net, monkeypatch):
    rid, _ = uncertain_start(net, monkeypatch)
    net['other'].post(thread_id='t1', type='observation', body={'text': 'new reviewed context'})
    push_other(net)
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    assert run(net)['lifecycle']['status'] == 'ok'
    ledger = TransportWorker(net['config'])._ledger()
    assert ledger.get('requests', {})[rid]['status'] == 'refused'
    assert rid not in ledger.get('uncertain_imports', {})
    assert remote_supervisor_messages(net) == []


def test_ROOM_PUSH_UNKNOWN_REMOTE_STILL_UNREADABLE(net, monkeypatch):
    rid, entry = uncertain_start(net, monkeypatch)
    submit_remote(net, request_document('status'))
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)

    def unreadable(*args):
        raise SyncError('fault: cannot inspect remote')

    monkeypatch.setattr(RoomRemote, 'fetch_candidate', unreadable)
    for _ in range(2):
        summary = run(net)
        assert summary['lifecycle']['status'] == 'failed'
        assert summary['processed'] == 0
        ledger = TransportWorker(net['config'])._ledger()
        assert ledger.get('uncertain_imports', {})[rid] == entry
        assert not ledger.get('requests')
        assert not ledger.get('pending_results')
    assert net['room'].current_tip() == entry['local_tip']


def test_ROOM_REMOTE_REF_DELETED(net):
    rid = submit_remote(net, request_document('status'))
    before = net['room'].current_tip()
    checkpoint = Path(net['config'].checkpoint_path).read_bytes()
    git(net['origin_room'], 'update-ref', '-d', 'refs/heads/agent-room')
    summary = run(net)
    assert summary['lifecycle']['status'] == 'failed'
    assert 'remote ref missing' in summary['lifecycle']['error']
    assert summary['processed'] == 0
    assert net['room'].current_tip() == before
    assert Path(net['config'].checkpoint_path).read_bytes() == checkpoint
    assert rid not in TransportWorker(net['config'])._ledger().get('requests', {})


def test_CONTROL_REMOTE_REF_DELETED(net):
    worker = TransportWorker(net['config'])
    worker.sync_control()
    anchor = worker._control_anchor().path.read_bytes()
    rid = request_document()['request_id']
    worker._record(rid, 'status', '0' * 64, 'ok', {})
    worker.materialise_pending(net['control'])
    local_only = net['control'].current_tip()
    ledger = worker._ledger().path.read_bytes()
    assert local_only != worker._control_anchor().get('last_accepted_tip')
    git(net['origin_control'], 'update-ref', '-d', 'refs/heads/agent-room-control')
    summary = run(net)
    assert summary['lifecycle']['status'] == 'failed'
    assert 'remote ref missing' in summary['lifecycle']['error']
    assert summary['processed'] == 0
    assert worker._control_anchor().path.read_bytes() == anchor
    assert worker._ledger().path.read_bytes() == ledger
    assert net['control'].current_tip() == local_only


def test_shipped_example_loads_with_real_placeholders(net, tmp_path):
    example = json.loads((Path(__file__).resolve().parents[1] / 'deploy/transport.json.example').read_text())
    assert set(example) <= set(TransportConfig.__dataclass_fields__)
    for key in example:
        example[key] = getattr(net['config'], key)
    path = tmp_path / 'example.json'
    path.write_text(json.dumps(example))
    assert TransportConfig.load(path) == net['config']


def test_unknown_unrelated_traffic_allows_only_proven_absent_reconstruction(net, monkeypatch):
    rid, old = uncertain_start(net, monkeypatch)
    net['other'].post(thread_id='t2', type='observation', body={'text': 'unrelated'})
    push_other(net)
    assert run(net)['lifecycle']['status'] == 'ok'
    final_ok(net, rid)
    message = remote_supervisor_messages(net)[0]
    assert message['message_id'] != old['response_message_id']
    assert message['parent_id'] == old['target_message_id']
    assert net['room'].resolve_message(old['response_message_id']) is None


def test_uncertain_import_stops_new_work_in_same_pass(net, monkeypatch):
    first = submit_remote(net, request_document('supervisor_import', {'response': bound_response(net)}))
    second = submit_remote(net, request_document('status'))

    def unknown(*args):
        raise AmbiguousDelivery('unknown')

    monkeypatch.setattr(RoomRemote, 'push_with_lease', unknown)
    summary = run(net)
    assert summary['lifecycle']['status'] == 'uncertain_delivery'
    assert len(summary['results']) == 1
    ledger = TransportWorker(net['config'])._ledger()
    assert first in ledger.get('uncertain_imports', {})
    assert second not in ledger.get('requests', {})


def test_uncertain_record_is_durable_before_first_push(net, monkeypatch):
    rid = submit_remote(net, request_document('supervisor_import', {'response': bound_response(net)}))
    real = RoomRemote.push_with_lease

    def inspect(self, expected):
        ledger = TransportWorker(net['config'])._ledger()
        entry = ledger.get('uncertain_imports', {})[rid]
        assert entry['expected_remote_head'] == expected
        assert entry['local_tip'] == self.local_tip()
        assert rid not in ledger.get('requests', {})
        return real(self, expected)

    monkeypatch.setattr(RoomRemote, 'push_with_lease', inspect)
    assert run(net)['results'][0]['status'] == 'ok'
    final_ok(net, rid)


def test_post_acceptance_inspection_error_does_not_finalize(net, monkeypatch):
    rid = submit_remote(net, request_document('supervisor_import', {'response': bound_response(net)}))

    def unreadable(*args):
        raise SyncError('post-push inspection unavailable')

    with monkeypatch.context() as patch:
        patch.setattr(TransportWorker, '_accept_after_delivery', unreadable)
        assert run(net)['results'][0]['status'] == 'uncertain_delivery'
    assert rid not in TransportWorker(net['config'])._ledger().get('requests', {})
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    run(net)
    final_ok(net, rid)


@pytest.mark.parametrize('which', ['room', 'control'])
def test_network_or_auth_failure_never_means_branch_absent(net, monkeypatch, which):
    real = remote_sync.run_git
    workdir = Path(getattr(net['config'], which + '_workdir'))
    from types import SimpleNamespace

    def failure(path, *args, **kwargs):
        if Path(path) == workdir and args[0] in ('ls-remote', 'fetch'):
            return SimpleNamespace(returncode=128, stdout=b'', stderr=b'not found: authorization denied')
        return real(path, *args, **kwargs)

    monkeypatch.setattr(remote_sync, 'run_git', failure)
    worker = TransportWorker(net['config'])
    remote = worker._room_remote() if which == 'room' else worker._control_remote()
    with pytest.raises(SyncError, match='cannot inspect'):
        remote.fetch_candidate(remote.branch + '-candidate')
    summary = run(net)
    assert summary['lifecycle']['status'] == 'failed'
    assert 'remote ref missing' not in summary['lifecycle']['error']
    assert summary['processed'] == 0


@pytest.mark.parametrize('which', ['room', 'control'])
def test_delete_ref_between_precheck_and_push_cannot_recreate(net, monkeypatch, which):
    real = remote_sync.run_git
    workdir = Path(getattr(net['config'], which + '_workdir'))
    origin = net['origin_' + which]
    branch = getattr(net['config'], which + '_branch')
    fired = []

    def delete_before_actual_push(path, *args, **kwargs):
        if Path(path) == workdir and args[0] == 'push' and not fired:
            fired.append(True)
            git(origin, 'update-ref', '-d', 'refs/heads/' + branch)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(remote_sync, 'run_git', delete_before_actual_push)
    submit_remote(net, request_document('supervisor_import', {'response': bound_response(net)}))
    if which == 'control':
        with pytest.raises(SyncError, match='remote ref missing'):
            run(net)
    else:
        run(net)
    assert fired
    assert not git(origin, 'for-each-ref', '--format=%(refname)', 'refs/heads/' + branch).strip()
    ledger = TransportWorker(net['config'])._ledger()
    assert ledger.get('uncertain_imports') if which == 'room' else ledger.get('pending_results')


def test_repeated_false_moved_signal_has_bounded_reconciliation(net, monkeypatch):
    from agent_room.remote_sync import RemoteRefMoved, MAX_DELIVERY_ATTEMPTS
    submit_remote(net, request_document('supervisor_import', {'response': bound_response(net)}))
    calls = []

    def moved(*args):
        calls.append(True)
        raise RemoteRefMoved('no stable observation this pass')

    monkeypatch.setattr(RoomRemote, 'push_with_lease', moved)
    summary = run(net)
    assert len(calls) == MAX_DELIVERY_ATTEMPTS
    assert summary['results'][0]['status'] == 'uncertain_delivery'
    assert not TransportWorker(net['config'])._ledger().get('requests')


def test_uncertain_request_cannot_be_processed_as_new(net, monkeypatch):
    rid, saved = uncertain_start(net, monkeypatch)
    worker = TransportWorker(net['config'])
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    entry = next(e for e in net['control'].requests() if e['request_id'] == rid)
    assert worker._process(net['control'], entry)['status'] == 'uncertain_delivery'
    assert worker._ledger().get('uncertain_imports')[rid] == saved


def test_crash_after_absent_remote_install_recovers_without_stale_response(net, monkeypatch):
    rid, _ = uncertain_start(net, monkeypatch)
    net['other'].post(thread_id='t1', type='observation', body={'text': 'changed context'})
    push_other(net)
    real = TrustCheckpoint.accept

    def crash_after_reset(self, store, *args, **kwargs):
        if store.current_tip() == remote_tip(net):
            raise RuntimeError('crash after installation, before checkpoint')
        return real(self, store, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(TrustCheckpoint, 'accept', crash_after_reset)
        with pytest.raises(RuntimeError, match='before checkpoint'):
            run(net)
    monkeypatch.setattr(TransportWorker, '_boundary', forbid_signature)
    summary = run(net)
    assert summary['lifecycle']['status'] == 'ok'
    assert TransportWorker(net['config'])._ledger().get('requests')[rid]['status'] == 'refused'
    assert remote_supervisor_messages(net) == []
