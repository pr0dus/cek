"""Typed supervisor tasks and crash-durable, at-most-one model attempts.

Task text is model input, never shell/argv or infrastructure configuration.
Only signed supervisor questions bearing this closed format are eligible.
"""
import hashlib
import os
from pathlib import Path
import secrets

from . import canonical
from .errors import AgentRoomError
from .ids import is_uuid7
from .transport_state import private_directory, check_file
from .protected_state import digest, oid

FORMAT = 'agent-room-task-v1'
ROLES = ('codex', 'claude-code')
MAX_TASKS = 256


def wake(path):
    """Fixed service-owned wake hint, not a dispatch ticket or command."""
    path = Path(path)
    with private_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW |
                     os.O_NONBLOCK, 0o600, dir_fd=directory)
        check_file(fd)
        os.fsync(fd)
        os.close(fd)
        os.fsync(directory)


def require(condition, reason):
    if not condition:
        raise AgentRoomError('task refused: ' + reason)


def validate(task):
    require(isinstance(task, dict) and set(task) == {
        'task_id', 'recipient', 'instruction'}, 'exact task fields required')
    require(is_uuid7(task['task_id']), 'task ID must be canonical UUIDv7')
    require(isinstance(task['recipient'], str) and task['recipient'] in ROLES,
            'fixed coding recipient required')
    text = task['instruction']
    require(isinstance(text, str) and bool(text.strip()), 'instruction type')
    try:
        length = len(text.encode('utf-8'))
    except UnicodeError:
        raise AgentRoomError('task refused: invalid instruction encoding') from None
    require(length <= 16000,
            'bounded instruction required')
    return task


def extract(message, role):
    if (message.get('sender', {}).get('agent') != 'openai-research'
            or message.get('recipient') != {'agent': role}
            or message.get('type') != 'question'
            or message.get('body', {}).get('format') != FORMAT):
        return None
    task = validate(canonical.strict_loads(message['body']['text']))
    require(task['recipient'] == role and message['thread_id'] == 'task-' + task['task_id'],
            'signed task placement mismatch')
    require(message.get('parent_id') is None and message.get('reply_requested') is True
            and message.get('human_approval_required') is False and 'action' not in message,
            'task cannot carry consequential authority')
    return task


def work_identity(room_id, role, message):
    return hashlib.sha256(canonical.canonical_bytes([
        room_id, role, message['message_id'], message[canonical.DIGEST_FIELD]])).hexdigest()


class Journal:
    """Caller holds the existing role/transport lifecycle lock.

    Explicit enrollment only. Missing/malformed state never means first-run.
    Uses the existing private directory/file guards and atomic fsync discipline.
    """
    def __init__(self, root):
        self.root = Path(root)

    def load(self):
        with private_directory(self.root) as directory:
            try:
                fd = os.open('tasks.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
            except OSError as exc:
                raise AgentRoomError('task journal unavailable; explicit enrollment required') from exc
            with os.fdopen(fd, 'rb') as stream:
                require(check_file(stream.fileno()).st_size <= 8 * 1024 * 1024, 'journal size')
                value = canonical.strict_loads(stream.read(8 * 1024 * 1024 + 1))
        self.validate(value)
        return value

    @staticmethod
    def validate(value):
        require(isinstance(value, dict) and set(value) == {'version', 'room_id', 'records'},
                'journal schema')
        require(type(value['version']) is int and value['version'] == 1, 'journal version')
        require(oid(value['room_id']), 'room binding')
        records = value['records']
        require(isinstance(records, dict) and len(records) <= MAX_TASKS, 'journal capacity')
        for key, record in records.items():
            require(isinstance(key, str) and isinstance(record, dict), 'record shape')
            require(set(record) == {'identity', 'phase', 'message_id', 'response_id', 'payload'},
                    'record fields')
            require(digest(record['identity']),
                    'identity digest')
            require(record['phase'] in ('intent', 'output', 'settled'), 'phase')
            require(is_uuid7(record['message_id']) and is_uuid7(record['response_id']), 'message IDs')
            require(isinstance(record['payload'], dict) or record['payload'] is None, 'payload')
            require((record['phase'] == 'intent' and record['payload'] is None) or
                    (record['phase'] != 'intent' and isinstance(record['payload'], dict)),
                    'phase/payload mismatch')

    def save(self, value, *, enroll=False):
        self.validate(value)
        raw = canonical.canonical_bytes(value)
        require(len(raw) <= 8 * 1024 * 1024, 'journal size')
        with private_directory(self.root) as directory:
            if enroll:
                try:
                    fd = os.open('tasks.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                 os.O_NOFOLLOW, 0o600, dir_fd=directory)
                except OSError as exc:
                    raise AgentRoomError('task journal already enrolled or unavailable') from exc
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.fsync(directory)
                return
            name = '.tasks-' + secrets.token_hex(16)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, 'tasks.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)


def execute(adapter, journal):
    """One verified typed task; intent on disk precedes the sole opaque call."""
    from .ids import uuid7
    store = adapter.room.store
    document = journal.load()
    require(document['room_id'] == store.room_id(), 'journal belongs to another room')
    store.verify_store()
    selected = None
    for message in adapter.room.inbox(unread_only=False):
        task = extract(message, adapter.participant)
        if task is None:
            continue
        key = work_identity(store.room_id(), adapter.participant, message)
        if document['records'].get(key, {}).get('phase') != 'settled':
            selected = (message, task, key)
            break
    if selected is None:
        return {'status': 'idle', 'invoked_model': False}
    target, task, key = selected
    record = document['records'].get(key)
    invoked = False
    if record is None:
        require(len(document['records']) < MAX_TASKS, 'task capacity requires admin maintenance')
        record = {'identity': key, 'phase': 'intent', 'message_id': target['message_id'],
                  'response_id': uuid7(), 'payload': None}
        document['records'][key] = record
        journal.save(document)
        invoked = True
        raw = adapter.invoke(adapter.build_prompt(adapter.room.thread(target['thread_id']), target))
        payload = adapter.parse_response(raw)
        record.update(phase='output', payload=payload)
        journal.save(document)
    require(record['identity'] == key and record['message_id'] == target['message_id'],
            'work identity mismatch')
    if record['phase'] == 'intent':
        return {'status': 'uncertain', 'invoked_model': False, 'work_id': key}
    existing = adapter.room.find(record['response_id'])
    payload = record['payload']
    if existing is None:
        adapter.room.reply(target['message_id'], message_id=record['response_id'],
                           recipient={'agent': 'openai-research'},
                           sender={'via': adapter.MARKER}, **payload)
    else:
        require(existing['parent_id'] == target['message_id'] and
                existing['sender']['agent'] == adapter.participant and
                existing['body'] == payload['body'], 'response binding mismatch')
        if store.remote:
            # A committed reply is not proof of delivery. The existing bounded
            # library reconciles/pushes this same immutable artifact, never a
            # second model call or a fresh logical message.
            store.push()
    adapter.room.acknowledge(target['message_id'])
    record['phase'] = 'settled'
    journal.save(document)
    return {'status': 'responded', 'invoked_model': invoked, 'work_id': key,
            'response_message_id': record['response_id'], 'task_id': task['task_id']}
