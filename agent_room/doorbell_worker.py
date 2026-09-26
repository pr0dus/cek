"""Optional finite role-worker wrapper, not deployed by installing source.

Root-owned units may explicitly select this entry after qualification. No
daemon, polling, shell, supervisor input or human authority is added.
"""
import json
import os
from pathlib import Path
import sys

from . import custody, role_worker
from .checkpoint import TrustCheckpoint
from .doorbell import Doorbell, GitHubPR, configuration
from .doorbell_protocol import ROLES, DoorbellError, require
from .errors import AgentRoomError
from .participant import NoWorkAvailable
from .transport_state import check_file

CONFIG = '/etc/agent-room/doorbell.json'


def prepare(role):
    require(role in ROLES, 'doorbell only supports coding roles')
    item = custody.guard(role)
    config = configuration(custody.root_json(CONFIG))
    worker_config = custody.root_json(f'/etc/agent-room/{role}.json')
    custody.install_environment(role, item)
    room = role_worker.room_for(role, item, worker_config)
    state = Path(item['state']) / 'doorbell'
    if config.get('transport') == 'pr-commit':
        from .doorbell_git import GitCommitPR
        adapter = GitCommitPR(config, role, state)
    else:
        adapter = comment_adapter(config, role, item)
    checkpoint = TrustCheckpoint.load(item['checkpoint'])
    return Doorbell(room.store, checkpoint, state, config, role, adapter)


def comment_adapter(config, role, item):
    """Reviewed dormant fallback; selected only by explicit comment config."""
    credential = Path(item['state_root']) / 'keys' / 'doorbell.token'
    custody.private_path(credential, os.geteuid())
    fd = os.open(credential, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        require(check_file(handle.fileno()).st_size <= 1025, 'doorbell credential size')
        data = handle.read(1026)
        require(len(data) <= 1025, 'doorbell credential size')
    try:
        token = data.decode('ascii').removesuffix('\n')
    except UnicodeError:
        raise DoorbellError('doorbell credential encoding') from None
    return GitHubPR(config, role, token)


def run(role, mode='turn'):
    require(mode in ('turn', 'recover', 'enroll'), 'unknown fixed doorbell mode')
    doorbell = prepare(role)
    if mode == 'enroll':
        doorbell.checkpoint.verify_candidate(doorbell.store)
        if doorbell.config.get('transport') == 'pr-commit':
            from .transport_state import private_lock, WORKER_LOCK
            with private_lock(doorbell.ledger.root, WORKER_LOCK):
                require(not (doorbell.ledger.root / 'ledger.json').exists(), 'ledger already enrolled')
                doorbell.transport.enroll()
        doorbell.ledger.initialise()
        return {'status': 'enrolled', 'model_invoked': False}
    # Missing/corrupt notification state fails BEFORE invoking a participant.
    doorbell.ledger.load()
    if mode == 'recover':
        return {'notification': doorbell.drain(), 'model_invoked': False}
    before = doorbell.drain()
    if before['status'] == 'uncertain' or before.get('remaining', 0):
        return {'notification': before, 'model_invoked': False, 'status': 'recovery_required'}
    try:
        result = role_worker.run(role)
    except NoWorkAvailable:
        return {'status': 'idle', 'model_invoked': False, 'notification': before}
    # Reopen authoritative state, not a report/envelope supplied by the worker.
    try:
        notification = prepare(role).drain()
    except (AgentRoomError, OSError, ValueError):
        notification = {'status': 'unresolved', 'recovery': 'recover mode only; do not repeat the turn'}
    return {'participant_result': result, 'notification': notification}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in (1, 2):
        print('usage: doorbell_worker <fixed-role> [turn|recover|enroll]', file=sys.stderr)
        return 2
    try:
        print(json.dumps(run(*args), sort_keys=True))
    except (AgentRoomError, OSError, ValueError):
        # Error text can contain upstream model/Git data: never relay it here.
        print('doorbell worker refused or unresolved; inspect protected local evidence', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
