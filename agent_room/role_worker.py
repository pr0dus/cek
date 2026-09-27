"""Dedicated production model/coordinator one-shot. No remote command surface.

Role is a literal in a root-owned unit and must match the actual UID. No input
field may choose identity, key, workspace, config or client. This is not a daemon.
"""
import json
import sys
from pathlib import Path

from . import custody
from .auth import Ed25519Signer
from .checkpoint import TrustCheckpoint
from .cursor import ParticipantCursor
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .participant import NoWorkAvailable
from .remote_sync import RoomRemote, SyncError, run_git
from .room import AgentRoom
from .trust import TrustPolicy


CODEX_MODEL = 'gpt-6-astra'


def validate_configuration(role, config):
    if role not in ('codex', 'claude-code', 'coordinator'):
        raise custody.CustodyError('unsupported production role')
    allowed = {'key_id', 'room_branch', 'room_remote'}
    if role == 'coordinator':
        allowed.add('message')
    else:
        allowed.add('enabled')
        allowed.add('owner_home')
        if role == 'codex':
            allowed.add('model')
    if not isinstance(config, dict) or set(config) != allowed:
        raise custody.CustodyError('unexpected production worker fields')
    if (not isinstance(config['key_id'], str) or not config['key_id']
            or len(config['key_id']) > 128):
        raise custody.CustodyError('invalid production signing key identifier')
    if config['room_branch'] != 'agent-room' or config['room_remote'] != 'origin':
        raise custody.CustodyError('production room ref/remote is fixed')
    if role != 'coordinator' and type(config['enabled']) is not bool:
        raise custody.CustodyError('enabled must be a boolean')
    if role != 'coordinator' and config['owner_home'] is not True:
        raise custody.CustodyError('production owner-home policy must be explicit')
    if role == 'codex' and config['model'] != CODEX_MODEL:
        raise custody.CustodyError('production Codex model must be gpt-6-astra')
    return config


def room_for(role, item, config):
    validate_configuration(role, config)
    store = GitMessageStore(item['room'], branch='agent-room', remote='origin',
                            trust=TrustPolicy.load(custody.TRUST_POLICY))
    signer = Ed25519Signer(item['signing_key'], signer=role, key_id=config['key_id'])
    return AgentRoom(store, role, ParticipantCursor(item['state'], role), signer=signer)


def sync_role_room(room, item):
    """Verify the exact authoritative branch in the role's own custody.

    The caller holds the role turn lock. Local unpublished output is never
    reset or discarded here: divergence is a recovery requirement, not licence
    to invoke again using a stale clone.
    """
    store = room.store
    head = run_git(store.workdir, 'symbolic-ref', '--quiet', 'HEAD').stdout.decode().strip()
    if head != 'refs/heads/agent-room':
        raise SyncError('role checkout must be on the fixed room branch')
    if run_git(store.workdir, 'status', '--porcelain').stdout.strip():
        raise SyncError('role room checkout is not clean')
    checkpoint = TrustCheckpoint.load(item['checkpoint'])
    remote = RoomRemote(store.workdir, 'origin', 'agent-room', trust=store.trust,
                        checkpoint_path=item['checkpoint'])
    candidate = remote.fetch_candidate('agent-room-candidate')
    probe = GitMessageStore(store.workdir, branch='agent-room-candidate', trust=store.trust)
    report = checkpoint.verify_candidate(probe)
    if report['candidate_tip'] != candidate or remote.required_remote_tip() != candidate:
        raise SyncError('authoritative room tip changed during role verification')
    # Only journal-bound replies may be recovered from an unpublished local
    # tail. Verify every extra commit/path; unrelated local work stays blocked.
    extra = run_git(store.workdir, 'rev-list', candidate + '..HEAD').stdout.splitlines()
    if extra:
        from .tasks import Journal, require
        document = Journal(Path(item['state']) / 'tasks').load()
        require(document['room_id'] == store.room_id(), 'recovery room mismatch')
        checkpoint.verify_candidate(store)
        allowed = set()
        for record in document['records'].values():
            if record['phase'] not in ('output', 'settled'):
                continue
            message = store.resolve_message(record['response_id'])
            if message is None:
                continue
            require(message['parent_id'] == record['message_id'] and
                    message['sender']['agent'] == room.participant and
                    message['body'] == record['payload']['body'], 'recovery reply binding')
            allowed.add(store.message_path(message['thread_id'], message['message_id']).encode())
        for commit in extra:
            paths = run_git(store.workdir, 'diff-tree', '--no-commit-id',
                            '--name-only', '-z', '-r', commit.decode()).stdout.split(b'\0')
            require(len(paths) == 2 and paths[-1] == b'' and paths[0] in allowed,
                    'unpublished commit is not an exact journal-bound reply')
        store.push()
        candidate = remote.fetch_candidate('agent-room-candidate')
        probe = GitMessageStore(store.workdir, branch='agent-room-candidate', trust=store.trust)
        checkpoint.verify_candidate(probe)
        if remote.required_remote_tip() != candidate:
            raise SyncError('authoritative room tip changed during reply recovery')
    remote.install(candidate)
    if remote.required_remote_tip() != candidate:
        raise SyncError('authoritative room tip changed during role installation')
    return checkpoint.accept(store, candidate_tip=candidate)


def run_verified_turn(adapter, item):
    with adapter.turn_lock():
        sync_role_room(adapter.room, item)
        from .tasks import Journal, execute
        journal = Journal(Path(item['state']) / 'tasks')
        results = []
        for _ in range(8):
            result = execute(adapter, journal)
            results.append(result)
            if result['status'] in ('idle', 'uncertain'):
                break
        if len(results) == 8 and results[-1]['status'] == 'responded':
            from .tasks import wake
            wake(Path(item['state']) / 'task-more')
        # Bind the role checkpoint to the delivered output before doorbell
        # drain. Recovery above handles a crash before this final synchronization.
        sync_role_room(adapter.room, item)
        return {'status': results[-1]['status'], 'turns': results,
                'invoked_model': any(r['invoked_model'] for r in results)}


def run(role):
    if role not in ('claude-code', 'codex', 'coordinator'):
        raise custody.CustodyError('no release or supervisor operation on participant worker')
    item = custody.guard(role)
    config = validate_configuration(role, custody.root_json(f'/etc/agent-room/{role}.json'))
    if role != 'coordinator' and not config['enabled']:
        return {'status': 'disabled', 'participant': role, 'invoked_model': False}
    custody.install_environment(role, item)
    room = room_for(role, item, config)
    if role == 'coordinator':
        # A root-authored routing message only. No client and no impersonation
        # of the existing Coordinator.room_for() development helper.
        message = config['message']
        if (not isinstance(message, dict) or set(message) != {
                'message_id', 'thread_id', 'type', 'recipient', 'project', 'body'}
                or message['type'] != 'handoff'):
            raise custody.CustodyError('coordinator accepts one fixed handoff message only')
        return room.post(**message)
    executable = custody.root_file(item['client'])
    if role == 'claude-code':
        from .claude_participant import ClaudeInvoker, ClaudeParticipant
        adapter = ClaudeParticipant(room, ClaudeInvoker(str(executable), cwd='/home/pr0', owner_home=True),
                                    turn_timeout=0)
    else:
        from .codex_participant import CodexInvoker, CodexParticipant
        adapter = CodexParticipant(room, CodexInvoker(str(executable), cwd='/home/pr0', owner_home=True,
                                                     model=CODEX_MODEL), turn_timeout=0)
    return run_verified_turn(adapter, item)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print('usage: role_worker <fixed-service-role>', file=sys.stderr)
        return 2
    try:
        result = run(argv[0])
    except (AgentRoomError, OSError, ValueError) as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
