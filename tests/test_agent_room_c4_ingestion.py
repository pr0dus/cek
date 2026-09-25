"""Real bounded disposable Git remotes, never host disk-fill experiments."""
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path

import pytest

from agent_room import git_ingestion as ingestion
from agent_room.errors import AgentRoomError
from agent_room.transport import TransportWorker, validate_request
from tests.conftest_agent_room import git
from tests.test_agent_room_transport_remote_s3 import net, request_document, submit_remote, push_other


def odb(net, which='control'):
    return Path(getattr(net['config'], which+'_workdir'))/'.git/objects'


def snapshot(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob('*') if p.is_file()}


def publish(net, payload, *, valid_path=True):
    writer = net['writer_control']
    name = '.agent-room-control/requests/'+request_document()['request_id']+'.json' if valid_path else 'unexpected.txt'
    path = writer.workdir/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    git(writer.workdir, 'add', '--', name)
    git(writer.workdir, 'commit', '-qm', 'public ingestion test')
    oid = git(writer.workdir, 'rev-parse', f'HEAD:{name}').strip()
    git(writer.workdir, 'push', '-q', 'origin', writer.branch)
    return oid


def assert_rejected_without_install(net, before, local, object_id=None):
    worker = TransportWorker(net['config'])
    report = worker.run()
    assert report['lifecycle']['status'] == 'failed', report
    assert net['control'].current_tip() == local
    assert snapshot(odb(net)) == before
    assert not (odb(net).parent/'agent-room-quarantine/attempt').exists()
    if object_id:
        proc = net['control']._git('cat-file', '-e', object_id, check=False)
        assert proc.returncode != 0
    return report


@pytest.mark.parametrize('size,random', [(12*1024*1024, False), (12*1024*1024, True),
                                       (ingestion.PACK_BYTES + 1024*1024, True), (270*1024, False)])
def test_oversized_blob_never_persisted(net, size, random):
    before, local = snapshot(odb(net)), net['control'].current_tip()
    payload = os.urandom(size) if random else b'x'*size
    oid = publish(net, payload)
    result = assert_rejected_without_install(net, before, local, oid)
    assert any(word in result['lifecycle']['error'] for word in ('budget', 'limit', 'fetch refused'))


def test_aggregate_small_objects_uncompressed_limit(net):
    writer = net['writer_control']
    # Each object is below both the 256 KiB protocol limit and 1 MiB object
    # limit; aggregate expansion, not an individual oversized blob, refuses.
    count = ingestion.GRAPH_BYTES // (240*1024) + 2
    for i in range(count):
        doc = request_document()
        doc['params'] = {'public_padding': str(i) + 'x'*(240*1024)}
        path = writer.workdir/f'.agent-room-control/requests/{doc["request_id"]}.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc))
    git(writer.workdir, 'add', '.agent-room-control/requests')
    git(writer.workdir, 'commit', '-qm', 'bounded aggregate candidate')
    git(writer.workdir, 'push', '-q', 'origin', writer.branch)
    result = assert_rejected_without_install(net, snapshot(odb(net)), net['control'].current_tip())
    assert 'uncompressed object budget' in result['lifecycle']['error']


def test_repeated_unique_rejected_candidates_cannot_accumulate(net):
    before, local = snapshot(odb(net)), net['control'].current_tip()
    for i in range(12):
        oid = publish(net, os.urandom(16384), valid_path=False)
        assert_rejected_without_install(net, before, local, oid)


def test_small_valid_room_and_control_are_verified_and_promoted(net):
    rid = submit_remote(net, request_document())
    net['other'].post(thread_id='t1', type='observation', body={'text': 'bounded valid candidate'})
    push_other(net)
    tip = net['other_room'].current_tip()
    worker = TransportWorker(net['config'])
    result = worker.run()
    assert result['lifecycle']['status'] == 'ok' and result['processed'] == 1, result
    assert rid in worker._ledger().document['requests']
    assert net['room'].current_tip() == tip
    assert net['checkpoint'].load(net['config'].checkpoint_path).document['last_accepted_tip'] == tip
    for which in ('room', 'control'):
        assert not (odb(net, which).parent/'agent-room-quarantine/attempt').exists()
        assert ingestion.storage(odb(net, which)) <= ingestion.PERSISTENT_BYTES


def crash_run(config, boundary):
    original_command, original_promote, original_replace = ingestion.command, ingestion._promote, os.replace
    def command(path, *args, **kwargs):
        output = original_command(path, *args, **kwargs)
        if boundary == 'after-fetch' and args[0] == 'fetch':
            os._exit(71)
        return output
    def promote(*args):
        if boundary == 'after-verify':
            os._exit(71)
        return original_promote(*args)
    def replace(src, dst, *args, **kwargs):
        result = original_replace(src, dst, *args, **kwargs)
        if boundary == 'pack-before-index' and str(dst).endswith('.pack'):
            os._exit(71)
        return result
    ingestion.command, ingestion._promote, os.replace = command, promote, replace
    TransportWorker(config).run()


@pytest.mark.parametrize('boundary', ['after-fetch', 'after-verify', 'pack-before-index'])
def test_quarantine_crash_recovers_without_partial_authority(net, boundary):
    rid = submit_remote(net, request_document())
    local = net['control'].current_tip()
    process = mp.get_context('spawn').Process(target=crash_run, args=(net['config'], boundary))
    process.start()
    process.join(15)
    try:
        assert process.exitcode == 71
        assert net['control'].current_tip() == local
        root = Path(net['config'].state_dir)
        assert not (root/'control-anchor.json').exists()
        assert not (root/'processed.json').exists()
        assert (odb(net).parent/'agent-room-quarantine/attempt').exists()
        worker = TransportWorker(net['config'])
        report = worker.run()
        assert report['lifecycle']['status'] == 'ok', report
        assert set(worker._ledger().document['requests']) == {rid}
        assert worker.run()['processed'] == 0
        assert not (odb(net).parent/'agent-room-quarantine/attempt').exists()
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)


def test_existing_oversized_store_requires_explicit_maintenance(net):
    path = odb(net)/'pack/public-oversized-fixture'
    path.parent.mkdir(exist_ok=True)
    with path.open('wb') as handle:
        handle.truncate(ingestion.PERSISTENT_BYTES + 1)  # sparse, not disk filling
    local = net['control'].current_tip()
    report = TransportWorker(net['config']).run()
    assert report['lifecycle']['status'] == 'failed'
    assert 'explicit maintenance' in report['lifecycle']['error']
    assert path.stat().st_size == ingestion.PERSISTENT_BYTES + 1
    assert net['control'].current_tip() == local


@pytest.mark.parametrize('field', ['PACK_BYTES', 'OBJECT_COUNT', 'PERSISTENT_BYTES', 'quarantine_path'])
def test_budget_not_request_selectable(field):
    doc = request_document()
    doc['params'][field] = 2**63
    with pytest.raises(AgentRoomError):
        validate_request(doc)


@pytest.mark.parametrize('field', ['OBJECT_COUNT', 'PERSISTENT_BYTES'])
def test_independent_count_and_promotion_caps(net, monkeypatch, field):
    rid = submit_remote(net, request_document())
    before, local = snapshot(odb(net)), net['control'].current_tip()
    # Trusted-code reduced ceilings make exact boundary tests cheap. No request
    # can supply these constants; separate tests use production ceilings.
    limit = 2 if field == 'OBJECT_COUNT' else ingestion.storage(odb(net)) + 1
    monkeypatch.setattr(ingestion, field, limit)
    report = assert_rejected_without_install(net, before, local)
    assert 'budget' in report['lifecycle']['error']
    assert rid not in TransportWorker(net['config'])._ledger().document['requests']


@pytest.mark.parametrize('kind', ['ancestor-writable', 'root-symlink', 'attempt-symlink', 'objects-symlink'])
def test_quarantine_path_cannot_escape(net, tmp_path, kind):
    repo = odb(net).parent
    external = tmp_path/'external'
    external.mkdir(mode=0o700)
    marker = external/'untouched'
    marker.write_bytes(b'keep')
    root = repo/'agent-room-quarantine'
    if kind == 'ancestor-writable':
        repo.chmod(0o777)
    elif kind == 'root-symlink':
        root.symlink_to(external, target_is_directory=True)
    elif kind == 'attempt-symlink':
        root.mkdir(mode=0o700)
        (root/'attempt').symlink_to(external, target_is_directory=True)
    else:
        # No trusted objects are removed; relocate the disposable fixture's ODB.
        odb(net).rename(external/'objects')
        odb(net).symlink_to(external/'objects', target_is_directory=True)
    report = TransportWorker(net['config']).run()
    assert report['lifecycle']['status'] == 'failed'
    assert marker.read_bytes() == b'keep'


def test_unsigned_room_rejection_does_not_pollute(net):
    before = snapshot(odb(net, 'room'))
    local = net['room'].current_tip()
    path = net['other_room'].workdir/'README.agent-room.md'
    path.write_text('unauthorized remote tree content')
    git(net['other_room'].workdir, 'add', str(path))
    git(net['other_room'].workdir, 'commit', '-qm', 'corrupt room candidate')
    push_other(net)
    report = TransportWorker(net['config']).run()
    assert report['lifecycle']['status'] == 'failed'
    assert snapshot(odb(net, 'room')) == before
    assert net['room'].current_tip() == local
