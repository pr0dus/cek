"""Authenticated wake markers for results produced by the narrow control worker.

The control repository is untrusted.  A control-result wake is emitted only
after the service-owned immutable copy of a result is byte-identical to the
verified remote result.  The wake then points at a signed openai-research
observation in the authoritative Agent Room; Git metadata remains only a
doorbell.
"""
import hashlib
import json
import os
from pathlib import Path

from . import canonical, custody
from .auth import Ed25519Signer
from .control_store import ControlStore, RESULTS_DIR, MAX_RESULT_BYTES
from .doorbell import configuration
from .doorbell_git import GitCommitPR
from .doorbell_protocol import from_control_result, require
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .ids import is_uuid7
from .remote_sync import CANDIDATE_SUFFIX, ControlRemote
from .room import AgentRoom
from .trust import TrustPolicy
from .transport_state import private_directory

DEFAULT_TRANSPORT_CONFIG = '/etc/agent-room/transport.json'
DEFAULT_DOORBELL_CONFIG = '/etc/agent-room/doorbell.json'
ROOT_NAME = 'control-results'
MAX_RECORDS = 2048
MAX_PER_PASS = 8


def _root(state_dir):
    return Path(state_dir) / ROOT_NAME


def _read_at(root, subdir, name, *, limit=MAX_RESULT_BYTES):
    with private_directory(Path(root) / subdir) as directory:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as handle:
            raw = handle.read(limit + 1)
    require(len(raw) <= limit, 'control result state too large')
    return raw


def _write_once(root, subdir, name, raw):
    with private_directory(Path(root) / subdir) as directory:
        try:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            existing = _read_at(root, subdir, name, limit=max(len(raw), MAX_RESULT_BYTES))
            require(existing == raw, 'immutable control result state conflict')
            return
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(directory)


def _validate_result(result):
    require(isinstance(result, dict), 'control result object')
    require(is_uuid7(result.get('request_id')), 'control result request id')
    require(result.get('status') in ('ok', 'refused', 'failed'), 'control result status')
    require(isinstance(result.get('operation'), str)
            and 1 <= len(result['operation']) <= 64, 'control result operation')
    require(isinstance(result.get('completed_at'), str), 'control result timestamp')
    require(isinstance(result.get('detail'), dict), 'control result detail')
    raw = canonical.canonical_bytes(result)
    require(len(raw) <= MAX_RESULT_BYTES, 'control result size')
    return raw


def record_produced(state_dir, result):
    """Persist the exact service-produced bytes before the untrusted repo sees them."""
    raw = _validate_result(result)
    request_id = result['request_id']
    _write_once(_root(state_dir), 'produced', request_id + '.json', raw)


def _produced_ids(state_dir):
    root = _root(state_dir)
    with private_directory(root / 'produced') as directory:
        names = sorted(os.listdir(directory))
    require(len(names) <= MAX_RECORDS, 'control result history bound')
    out = []
    for name in names:
        require(name.endswith('.json') and is_uuid7(name[:-5]),
                'unexpected control result state file')
        out.append(name[:-5])
    return out


def _is_delivered(state_dir, request_id):
    return _read_at(_root(state_dir), 'delivered', request_id + '.json',
                    limit=4096) is not None


def _remote_results(config):
    remote = ControlRemote(config.control_workdir, config.control_remote,
                           config.control_branch, genesis=config.control_genesis,
                           anchor_path=Path(config.state_dir) / 'control-anchor.json')
    branch = f"{config.control_branch}{CANDIDATE_SUFFIX}-result-wake"
    remote.fetch_candidate(branch)
    probe = ControlStore(config.control_workdir, branch)
    history = probe._history()
    return probe, history


def _marker_report(config, result, result_sha256):
    trust = TrustPolicy.load(config.trust_policy_path)
    store = GitMessageStore(config.room_workdir, branch=config.room_branch,
                            remote=config.room_remote, trust=trust)
    room = AgentRoom(
        store, 'openai-research',
        signer=Ed25519Signer(config.signing_key_path,
                             signer='openai-research',
                             key_id=config.signing_key_id))
    request_id = result['request_id']
    posted = room.post(
        thread_id='control-result-' + request_id,
        type='observation',
        body={'format': 'agent-room-control-result-v1',
              'request_id': request_id,
              'result_sha256': result_sha256,
              'status': result['status'],
              'operation': result['operation']},
        recipient={'agent': 'openai-research'},
        message_id=request_id,
        timestamp=result['completed_at'])
    report = store.resolve_message(request_id)
    require(report is not None, 'control result marker missing after append')
    delivered, known, _ = store._reconcile_push(posted['commit'])
    require(delivered is True and known is True,
            'control result marker remote delivery unresolved')
    return store, report


def drain(config, doorbell_config, *, limit=MAX_PER_PASS):
    """Emit wakes for remotely delivered service results not yet acknowledged."""
    require(config.control_remote is not None and config.room_remote is not None,
            'control result wake requires production remotes')
    doorbell_config = configuration(doorbell_config)
    probe, history = _remote_results(config)
    transport = GitCommitPR(doorbell_config, 'openai-research',
                            Path(config.state_dir) / 'control-doorbell')
    results = []
    for request_id in [r for r in _produced_ids(config.state_dir)
                       if not _is_delivered(config.state_dir, r)][:limit]:
        expected = _read_at(_root(config.state_dir), 'produced',
                            request_id + '.json')
        path = f"{RESULTS_DIR}/{request_id}.json"
        commit = history.get(path)
        if commit is None:
            continue
        actual = probe._blob(path, commit)
        require(actual == expected,
                'remote control result differs from service-produced bytes')
        result = canonical.strict_loads(expected)
        raw = _validate_result(result)
        result_sha256 = hashlib.sha256(raw).hexdigest()
        store, report = _marker_report(config, result, result_sha256)
        event = from_control_result(store.room_id(), report)
        transport.check_target()
        receipt = transport.post(event)
        require(isinstance(receipt, str) and len(receipt) in (40, 64),
                'control result doorbell delivery unresolved')
        record = canonical.canonical_bytes({
            'request_id': request_id,
            'result_sha256': result_sha256,
            'report_id': report['message_id'],
            'event_id': event['event_id'],
            'commit_oid': receipt,
        })
        _write_once(_root(config.state_dir), 'delivered',
                    request_id + '.json', record)
        results.append({'request_id': request_id,
                        'event_id': event['event_id'],
                        'commit_oid': receipt})
    return results


def enroll(config, doorbell_config):
    transport = GitCommitPR(configuration(doorbell_config), 'openai-research',
                            Path(config.state_dir) / 'control-doorbell')
    transport.enroll()
    return {'status': 'enrolled'}


def _production(action):
    from .transport import TransportConfig
    item = custody.guard('openai-research')
    custody.root_file(DEFAULT_TRANSPORT_CONFIG)
    custody.root_file(DEFAULT_DOORBELL_CONFIG)
    config = TransportConfig.load(DEFAULT_TRANSPORT_CONFIG)
    custody.check_transport(config, item)
    doorbell = canonical.strict_loads(Path(DEFAULT_DOORBELL_CONFIG).read_text())
    custody.install_environment('openai-research', item)
    return enroll(config, doorbell) if action == 'enroll' else drain(config, doorbell)


def main(argv=None):
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in (['enroll'], ['drain']):
        print('usage: python3 -m agent_room.control_result [enroll|drain]',
              file=sys.stderr)
        return 2
    try:
        print(json.dumps(_production(args[0]), sort_keys=True))
    except (AgentRoomError, OSError, ValueError) as exc:
        print(f'{type(exc).__name__}: control result wake refused', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
