"""Metadata-only supervisor doorbells. Notifications never carry authority."""
import hashlib

from . import canonical
from .errors import AgentRoomError
from .ids import is_uuid7
from .protected_state import digest, oid, timestamp

PREFIX = 'agent-room-terminal-v1/'
ROLES = ('claude-code', 'codex')
EVENT_ROLES = ROLES + ('openai-research',)
KINDS = ('end_report', 'task_complete', 'implementation_complete',
         'verification_complete', 'blocked', 'unexpected_finding',
         'disagreement', 'human_required')
EVENT_KINDS = KINDS + ('control_result',)
CONTROL_RESULT_FORMAT = 'agent-room-control-result-v1'
FIELDS = {'protocol', 'schema_version', 'event_id', 'room_id', 'report_id',
          'role', 'event_kind', 'timestamp', 'envelope_sha256'}
MAX_EVENT_BYTES = 1024


class DoorbellError(AgentRoomError):
    pass


def require(value, message):
    if not value:
        raise DoorbellError(message)


def terminal_kind(message):
    """Explicit signed metadata, never keywords or a completion inference."""
    if message.get('type') == 'decision_request':
        require(message.get('human_approval_required') is True,
                'decision request lacks human requirement')
        return 'human_required'
    fmt = message.get('body', {}).get('format', '')
    if not isinstance(fmt, str) or not fmt.startswith(PREFIX):
        return None
    kind = fmt[len(PREFIX):]
    require(kind in KINDS, 'unknown terminal marker')
    return kind


def event_identity(room_id, message_id, envelope_digest):
    return hashlib.sha256(canonical.canonical_bytes(
        [room_id, message_id, envelope_digest])).hexdigest()


def validate_event(event):
    require(isinstance(event, dict) and set(event) == FIELDS, 'doorbell fields')
    require(event['protocol'] == 'agent-room-doorbell', 'doorbell protocol')
    require(type(event['schema_version']) is int and event['schema_version'] == 1,
            'doorbell version')
    require(oid(event['room_id']) and is_uuid7(event['report_id']), 'doorbell identity')
    require(event['role'] in EVENT_ROLES and event['event_kind'] in EVENT_KINDS, 'doorbell role/kind')
    require(digest(event['envelope_sha256']), 'doorbell digest')
    timestamp(event['timestamp'])
    require(event['event_id'] == event_identity(event['room_id'], event['report_id'],
                                               event['envelope_sha256']), 'doorbell event binding')
    require(len(canonical.canonical_bytes(event)) <= MAX_EVENT_BYTES, 'doorbell size')
    return event


def from_report(room_id, report):
    """Caller must supply a verified committed envelope, not model output."""
    kind = terminal_kind(report)
    if kind is None:
        return None
    require(report['sender']['agent'] in ROLES, 'not a coding participant report')
    require(report.get('recipient') == {'agent': 'openai-research'},
            'terminal report must be addressed to supervisor')
    event = dict(protocol='agent-room-doorbell', schema_version=1,
                 room_id=room_id, report_id=report['message_id'],
                 role=report['sender']['agent'], event_kind=kind,
                 timestamp=report['timestamp'], envelope_sha256=report[canonical.DIGEST_FIELD])
    event['event_id'] = event_identity(room_id, event['report_id'], event['envelope_sha256'])
    return validate_event(event)


def from_control_result(room_id, report):
    """Bind a wake to one authenticated service-produced control result marker."""
    require(isinstance(report, dict) and report.get('type') == 'observation',
            'control result report type')
    require(report.get('sender') == {'agent': 'openai-research'},
            'control result signer role')
    require(report.get('recipient') == {'agent': 'openai-research'},
            'control result recipient')
    body = report.get('body')
    require(isinstance(body, dict) and set(body) == {
        'format', 'request_id', 'result_sha256', 'status', 'operation'
    }, 'control result body fields')
    require(body['format'] == CONTROL_RESULT_FORMAT, 'control result format')
    require(is_uuid7(body['request_id']) and report.get('message_id') == body['request_id'],
            'control result request binding')
    require(digest(body['result_sha256']), 'control result digest')
    require(body['status'] in ('ok', 'refused', 'failed'), 'control result status')
    require(isinstance(body['operation'], str) and 1 <= len(body['operation']) <= 64,
            'control result operation')
    event = dict(protocol='agent-room-doorbell', schema_version=1,
                 room_id=room_id, report_id=report['message_id'],
                 role='openai-research', event_kind='control_result',
                 timestamp=report['timestamp'],
                 envelope_sha256=report[canonical.DIGEST_FIELD])
    event['event_id'] = event_identity(room_id, event['report_id'],
                                       event['envelope_sha256'])
    return validate_event(event)


def encode(event):
    return canonical.canonical_text(validate_event(event))


def decode(raw):
    require(isinstance(raw, str), 'doorbell type')
    try:
        require(len(raw.encode('utf-8')) <= MAX_EVENT_BYTES, 'doorbell size')
    except UnicodeError:
        raise DoorbellError('doorbell encoding') from None
    return validate_event(canonical.strict_loads(raw))


def verify_notice(raw, store, checkpoint):
    """Supervisor must call before treating a notice as a real report."""
    event = decode(raw)
    require(store.trust is not None, 'authenticated store required')
    checkpoint.verify_candidate(store)
    tip = store.current_tip()
    require(store.room_id() == event['room_id'], 'wrong room')
    report = store.resolve_message(event['report_id'])
    expected = (from_control_result(store.room_id(), report)
                if report is not None and event['event_kind'] == 'control_result'
                else from_report(store.room_id(), report) if report is not None else None)
    require(report is not None and expected == event,
            'missing or mismatched authoritative report')
    require(store.current_tip() == tip, 'room changed during report verification')
    return report
