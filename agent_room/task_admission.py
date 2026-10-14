"""Root-installed, exact-content admission for a bounded restoration.

Historical work remains held, not consumed or relabeled successful. Missing
production enrollment fails closed. This is not transport/human authority.
"""
import hashlib
from . import canonical, custody
from .errors import AgentRoomError
from .ids import is_uuid7
from .protected_state import digest

CONFIG = '/etc/agent-room/task-admission.json'

def validate(document):
    if (not isinstance(document, dict) or set(document) != {'version', 'requests', 'tasks'}
            or type(document['version']) is not int or document['version'] != 1):
        raise AgentRoomError('invalid task admission schema')
    for name in ('requests', 'tasks'):
        entries = document[name]
        if (not isinstance(entries, dict) or len(entries) > 16
                or any(not is_uuid7(k) or not digest(v) for k, v in entries.items())):
            raise AgentRoomError('invalid bounded admission entries')
    return document

def load():
    return validate(custody.root_json(CONFIG))

def task_allowed(document, task):
    return document['tasks'].get(task['task_id']) == hashlib.sha256(
        canonical.canonical_bytes(task)).hexdigest()

def request_allowed(document, request_id, raw_sha256):
    return document['requests'].get(request_id) == raw_sha256
