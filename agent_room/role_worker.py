"""Dedicated production model/coordinator one-shot. No remote command surface.

Role is a literal in a root-owned unit and must match the actual UID. No input
field may choose identity, key, workspace, config or client. This is not a daemon.
"""
import json
import sys

from . import custody
from .auth import Ed25519Signer
from .cursor import ParticipantCursor
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .room import AgentRoom
from .trust import TrustPolicy


def room_for(role, item, config):
    allowed = {'key_id', 'room_branch', 'room_remote'}
    if role == 'coordinator':
        allowed.add('message')
    if not isinstance(config, dict) or set(config) != allowed:
        raise custody.CustodyError('unexpected production worker fields')
    if config['room_branch'] != 'agent-room' or config['room_remote'] != 'origin':
        raise custody.CustodyError('production room ref/remote is fixed')
    store = GitMessageStore(item['room'], branch='agent-room', remote='origin',
                            trust=TrustPolicy.load(custody.TRUST_POLICY))
    signer = Ed25519Signer(item['signing_key'], signer=role, key_id=config['key_id'])
    return AgentRoom(store, role, ParticipantCursor(item['state'], role), signer=signer)


def run(role):
    if role not in ('claude-code', 'codex', 'coordinator'):
        raise custody.CustodyError('no release or supervisor operation on participant worker')
    item = custody.guard(role)
    config = custody.root_json(f'/etc/agent-room/{role}.json')
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
        adapter = ClaudeParticipant(room, ClaudeInvoker(str(executable), cwd=item['workspace']))
    else:
        from .codex_participant import CodexInvoker, CodexParticipant
        adapter = CodexParticipant(room, CodexInvoker(str(executable), cwd=item['workspace']))
    return adapter.run_turn()


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
