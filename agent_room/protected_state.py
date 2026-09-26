"""Semantic schemas for service-owned continuity/replay state (C4).

These validators never initialize or migrate. Only the persistence layer's
ENOENT path may create initial state. An existing partial document is corrupt.
"""
import datetime as dt
import re

from .errors import AgentRoomError
from .ids import is_uuid7

OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')


class ProtectedStateError(AgentRoomError):
    pass


def require(condition, label):
    if not condition:
        raise ProtectedStateError('invalid protected state: ' + label)


def oid(value):
    return isinstance(value, str) and OID.fullmatch(value) is not None


def digest(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def text(value):
    return isinstance(value, str) and bool(value.strip())


def timestamp(value):
    require(isinstance(value, str), 'timestamp type')
    try:
        parsed = dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
        require(parsed.strftime('%Y-%m-%dT%H:%M:%SZ') == value, 'canonical timestamp')
    except ValueError as exc:
        raise ProtectedStateError('invalid protected state timestamp') from exc


def common(document, kind):
    require(isinstance(document, dict) and document.get('kind') == kind, kind)
    require(type(document.get('revision')) is int and document['revision'] >= 0, 'revision')
    timestamp(document.get('created_at'))
    timestamp(document.get('updated_at'))


def control_anchor(document):
    common(document, 'control-anchor')
    for key in ('genesis', 'last_accepted_tip'):
        require(oid(document.get(key)), key)


def completed(entry):
    require(isinstance(entry, dict), 'completed request')
    require(text(entry.get('operation')), 'operation')
    require(entry.get('status') in ('ok', 'refused', 'failed'), 'status')
    timestamp(entry.get('at'))
    require('room_tip' in entry and (entry['room_tip'] is None or oid(entry['room_tip'])), 'room_tip')
    if 'result_sha256' in entry:
        require(digest(entry['result_sha256']), 'result_sha256')


def pending(entry, request_id):
    require(isinstance(entry, dict), 'pending result')
    require(entry.get('state') in ('produced', 'materialised', 'conflict', 'deferred',
                                  'unknown', 'pending'), 'pending state')
    timestamp(entry.get('at'))
    require('detail' not in entry or isinstance(entry['detail'], str), 'pending detail')
    result = entry.get('document')
    require(isinstance(result, dict), 'result document')
    require(type(result.get('control_schema_version')) is int and result['control_schema_version'] == 1,
            'result version')
    require(result.get('request_id') == request_id, 'result request binding')
    completed(dict(operation=result.get('operation'), status=result.get('status'),
                   at=result.get('completed_at'), room_tip=result.get('room_tip')))
    require('room_tip' in result, 'result room_tip')
    require(result.get('request_sha256') == '' or digest(result.get('request_sha256')), 'request digest')
    require(isinstance(result.get('detail'), dict), 'result detail')


def uncertain(entry, request_id):
    require(isinstance(entry, dict) and entry.get('state') == 'uncertain_delivery', 'uncertain import')
    require(entry.get('request_id') == request_id, 'uncertain request binding')
    for key in ('request_sha256', 'context_sha256', 'response_sha256'):
        require(digest(entry.get(key)), key)
    for key in ('target_message_id', 'response_message_id'):
        require(is_uuid7(entry.get(key)), key)
    for key in ('local_tip', 'expected_remote_head'):
        require(oid(entry.get(key)), key)
    require(type(entry.get('attempts')) is int and 1 <= entry['attempts'] <= 3, 'attempts')
    params, imported = entry.get('params'), entry.get('import')
    require(isinstance(params, dict) and isinstance(params.get('response'), dict), 'response params')
    response = params['response']
    require(response.get('target_message_id') == entry['target_message_id'] and
            response.get('context_sha256') == entry['context_sha256'], 'response binding')
    require(isinstance(imported, dict) and imported.get('response_message_id') == entry['response_message_id'],
            'import binding')


def processed_ledger(document):
    common(document, 'processed-ledger')
    for key, validate in (('requests', lambda value, _: completed(value)),
                          ('pending_results', pending), ('uncertain_imports', uncertain)):
        require(isinstance(document.get(key), dict), key)
        for request_id, entry in document[key].items():
            require(is_uuid7(request_id), key + ' request id')
            validate(entry, request_id)
    require(not (document['requests'].keys() & document['uncertain_imports'].keys()),
            'completed request also uncertain')
    require(document['pending_results'].keys() <= document['requests'].keys(), 'orphan result')
    for key, value in document['pending_results'].items():
        result, record = value['document'], document['requests'][key]
        require(all(result[a] == record[b] for a, b in (
            ('operation', 'operation'), ('status', 'status'), ('completed_at', 'at'),
            ('room_tip', 'room_tip'))), 'result/completion mismatch')
        if record.get('result_sha256') is not None:
            from . import canonical
            import hashlib
            require(hashlib.sha256(canonical.canonical_bytes(result)).hexdigest()
                    == record['result_sha256'], 'result digest mismatch')


def release_journal(document):
    common(document, 'release-reservation-v1')
    identity = document.get('identity')
    require(isinstance(identity, dict) and set(identity) == {
        'room', 'branch', 'remote', 'checkout', 'target', 'checkpoint'}, 'release identity')
    require(oid(identity['room']) and all(text(v) for v in identity.values()), 'release identity values')
    require('pending' in document, 'release pending')
    value = document['pending']
    if value is not None:
        require(isinstance(value, dict) and set(value) == {
            'parent', 'envelope', 'authorisation', 'commit'}, 'reservation intent')
        require(oid(value['parent']) and (value['commit'] is None or oid(value['commit'])), 'reservation OID')
        require(isinstance(value['envelope'], dict) and isinstance(value['authorisation'], dict), 'reservation objects')
        # Exact signed-envelope/authority binding is also checked by C2 before use.
        from . import canonical
        canonical.verify(value['envelope'])
        receipt, authority = value['envelope'].get('receipt'), value['authorisation']
        require(value['envelope'].get('type') == 'execution_receipt' and isinstance(receipt, dict), 'reservation type')
        require(receipt.get('status') == 'uncertain' and authority.get('action_permitted') is False,
                'reservation authority')
        for key in ('request_message_id', 'decision_id', 'action_nonce'):
            require(text(receipt.get(key)) and receipt[key] == authority.get(key), 'reservation binding ' + key)
    if 'last_delivery' in document:
        delivery = document['last_delivery']
        require(isinstance(delivery, dict) and delivery.get('state') in ('absent', 'delivered'), 'delivery')
        require(oid(delivery.get('head')) and is_uuid7(delivery.get('message_id')), 'delivery identity')
        require('commit' in delivery and (delivery['commit'] is None or oid(delivery['commit'])), 'delivery commit')
        if delivery['state'] == 'delivered':
            require(oid(delivery['commit']) and oid(delivery.get('parent')), 'delivered ancestry')


VALIDATORS = {'control-anchor': control_anchor, 'processed-ledger': processed_ledger,
              'release-reservation-v1': release_journal}


def validate(document, kind):
    require(kind in VALIDATORS, 'unknown state kind')
    VALIDATORS[kind](document)
