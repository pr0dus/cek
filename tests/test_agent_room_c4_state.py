"""C4: real persisted corruption must not become first-run state."""
import copy
import json
from pathlib import Path

import pytest

from agent_room import canonical
from agent_room.errors import AgentRoomError
from agent_room.ids import uuid7
from agent_room.remote_sync import Anchor
from agent_room.transport import TransportWorker
from agent_room.checkpoint import TrustCheckpoint
from agent_room.cursor import ParticipantCursor
from tests.conftest_agent_room import git
from tests.test_agent_room_transport_remote_s3 import net, request_document, submit_remote

MISSING = object()
BAD = [None, [], {}, True, 0, '', 'HEAD~1', 'a'*39, 'a'*41]


def entry(field, rid):
    at = '2026-09-25T00:00:00Z'
    completed = dict(operation='status', status='ok', at=at, room_tip='a'*40)
    if field == 'requests':
        return completed
    if field == 'pending_results':
        return dict(state='produced', at=at, document=dict(control_schema_version=1,
            request_id=rid, operation='status', status='ok', completed_at=at,
            request_sha256='b'*64, room_tip='a'*40, detail={}))
    mid, response_id = uuid7(), uuid7()
    return dict(state='uncertain_delivery', request_id=rid, request_sha256='b'*64,
                params={'response': {'target_message_id': mid, 'context_sha256': 'b'*64}},
                target_message_id=mid, response_message_id=response_id,
                context_sha256='b'*64, response_sha256='c'*64, local_tip='a'*40,
                expected_remote_head='b'*40, attempts=1, import_ignored=None,
                **{'import': {'response_message_id': response_id}})


@pytest.mark.parametrize('value', BAD + [MISSING])
def test_control_corruption_blocks_rollback(net, value):
    worker = TransportWorker(net['config'])
    submit_remote(net, request_document())
    assert worker.run()['lifecycle']['status'] == 'ok'
    anchor = worker._control_anchor()
    local = net['control'].current_tip()
    document = copy.deepcopy(anchor.document)
    if value is MISSING:
        del document['last_accepted_tip']
    else:
        document['last_accepted_tip'] = value
    anchor.path.write_text(canonical.canonical_text(document))
    corrupted = anchor.path.read_bytes()
    git(net['writer_control'].workdir, 'push', '--force', '-q', 'origin',
        f'{net["config"].control_genesis}:refs/heads/agent-room-control')
    report = worker.run()
    assert report['lifecycle']['status'] == 'failed' and report['processed'] == 0
    assert anchor.path.read_bytes() == corrupted
    assert net['control'].current_tip() == local


@pytest.mark.parametrize('field', ['requests', 'pending_results', 'uncertain_imports'])
@pytest.mark.parametrize('value', [None, [], False, '', 0, MISSING])
def test_ledger_required_maps_fail_before_replay(net, field, value):
    worker = TransportWorker(net['config'])
    rid = submit_remote(net, request_document())
    assert worker.run()['processed'] == 1
    ledger = worker._ledger()
    document = copy.deepcopy(ledger.document)
    if value is MISSING:
        del document[field]
    else:
        document[field] = value
    ledger.path.write_text(canonical.canonical_text(document))
    before = ledger.path.read_bytes()
    report = worker.run()
    assert report['lifecycle']['status'] == 'failed' and report['processed'] == 0
    assert ledger.path.read_bytes() == before
    assert rid in ledger.document['requests']


@pytest.mark.parametrize('field', ['requests', 'pending_results', 'uncertain_imports'])
@pytest.mark.parametrize('value', [None, [], False, {}, {'state': 'pending'}])
def test_nested_state_refused(tmp_path, field, value):
    anchor = Anchor(tmp_path/'state'/'processed.json', 'processed-ledger')
    anchor.set()
    doc = copy.deepcopy(anchor.document)
    doc[field][uuid7()] = value
    anchor.path.write_text(canonical.canonical_text(doc))
    with pytest.raises(AgentRoomError):
        Anchor(anchor.path, 'processed-ledger')


@pytest.mark.parametrize('raw', [b'', b'{', b'null', b'[]', b'{"kind":"processed-ledger"}',
                               b'{"kind":"release-reservation-v1","created_at":"2026-09-25T00:00:00Z"}'])
def test_partial_existing_never_bootstraps(tmp_path, raw):
    path = tmp_path/'state'/'processed.json'
    anchor = Anchor(path, 'processed-ledger')
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(AgentRoomError):
        Anchor(path, 'processed-ledger')
    assert path.read_bytes() == raw


def test_true_absence_initializes(net):
    worker = TransportWorker(net['config'])
    assert not (Path(net['config'].state_dir)/'processed.json').exists()
    assert worker.run()['lifecycle']['status'] == 'ok'
    assert worker._ledger().document['requests'] == {}
    assert worker._control_anchor().document['last_accepted_tip']


@pytest.mark.parametrize('field', ['trust_generation', 'trust_policy_sha256',
                                  'last_accepted_tip', 'genesis', 'accepted_at'])
@pytest.mark.parametrize('value', [None, [], True, MISSING])
def test_checkpoint_does_not_drop_rollback_authority(net, field, value):
    document = copy.deepcopy(net['checkpoint'].document)
    if value is MISSING:
        del document[field]
    else:
        document[field] = value
    with pytest.raises(AgentRoomError):
        TrustCheckpoint(document)


@pytest.mark.parametrize('value', [None, [], False, MISSING])
def test_cursor_ack_map_not_reset(tmp_path, value):
    cursor = ParticipantCursor(tmp_path/'cursor', 'claude-code')
    cursor.acknowledge(uuid7(), at='2026-09-25T00:00:00Z')
    state = json.loads(cursor.path.read_bytes())
    if value is MISSING:
        del state['acknowledged']
    else:
        state['acknowledged'] = value
    cursor.path.write_text(json.dumps(state))
    with pytest.raises(AgentRoomError):
        cursor.acknowledged_ids()


@pytest.mark.parametrize('field,value', [('revision', True), ('revision', None), ('revision', -1),
                                      ('created_at', []), ('updated_at', {}),
                                      ('created_at', '2026-02-30T00:00:00Z')])
def test_state_common_fields_are_not_optional(tmp_path, field, value):
    state = Anchor(tmp_path/'private'/'state.json', 'processed-ledger')
    state.set()
    doc = copy.deepcopy(state.document)
    doc[field] = value
    state.path.write_text(canonical.canonical_text(doc))
    with pytest.raises(AgentRoomError):
        Anchor(state.path, 'processed-ledger')


@pytest.mark.parametrize('field', ['identity', 'pending', 'revision'])
def test_existing_release_state_cannot_rebootstrap(tmp_path, field):
    state = Anchor(tmp_path/'private'/'release.json', 'release-reservation-v1')
    state.set(identity=dict(room='a'*40, branch='agent-room', remote='origin',
                           checkout='/fixture', target='/target', checkpoint='/checkpoint'), pending=None)
    doc = copy.deepcopy(state.document)
    del doc[field]
    state.path.write_text(canonical.canonical_text(doc))
    with pytest.raises(AgentRoomError):
        Anchor(state.path, 'release-reservation-v1')
