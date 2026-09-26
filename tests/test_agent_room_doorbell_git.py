"""Real disposable Git remotes; no live wakes, model calls or credentials."""
import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_room import canonical
from agent_room.doorbell import Doorbell, configuration
from agent_room.doorbell_git import GitCommitPR, ACCEPTED
from agent_room.doorbell_protocol import DoorbellError, encode, from_report, verify_notice
from agent_room.errors import AgentRoomError
from tests.conftest_agent_room import git
from tests.test_agent_room_doorbell import event, rig, report, SECRET

BRANCH = 'supervisor-doorbell-v1'


@pytest.fixture
def channel(tmp_path):
    root = tmp_path / 'channel'
    root.mkdir(mode=0o700)
    remote, source = root / 'remote.git', root / 'source'
    remote.mkdir(); source.mkdir()
    git(remote, 'init', '--bare', '-q')
    git(source, 'init', '-q')
    git(source, 'config', 'user.name', 'fixture')
    git(source, 'config', 'user.email', 'fixture@example.invalid')
    (source / 'README.supervisor-doorbell.md').write_text('metadata-only wake branch\n')
    git(source, 'add', '.')
    git(source, 'commit', '-qm', 'doorbell scaffold')
    seed = git(source, 'rev-parse', 'HEAD').strip()
    git(source, 'remote', 'add', 'origin', str(remote))
    git(source, 'push', '-q', 'origin', f'HEAD:refs/heads/{BRANCH}')
    config = dict(transport='pr-commit', repository='example/room', pull_number=1,
                  pull_node_id='PR_test1', branch=BRANCH, bootstrap_tip=seed)
    def adapter(name='codex', role='codex'):
        a = GitCommitPR(config, role, root / name)
        a.url = str(remote)  # Explicit disposable library fixture, never production config.
        a.enroll()
        return a
    def tip():
        return git(remote, 'rev-parse', f'refs/heads/{BRANCH}').strip()
    return SimpleNamespace(root=root, remote=remote, source=source, config=config,
                           seed=seed, adapter=adapter, tip=tip)


def test_canonical_event_one_commit_no_report_and_stable_retry(channel):
    a, e = channel.adapter(), event()
    receipt = a.post(e)
    assert receipt == channel.tip()
    assert git(channel.remote, 'show', f'{receipt}:wake-{e["event_id"]}.json') == encode(e)
    assert git(channel.remote, 'rev-list', '--count', f'{channel.seed}..{receipt}').strip() == '1'
    assert SECRET not in git(channel.remote, 'show', receipt)
    for _ in range(3):
        assert a.find(e) == receipt
    assert channel.tip() == receipt


def test_signed_report_workflow_and_no_supervisor_loop(channel, rig):
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise()
    signed = report(rig)
    result = door.drain()
    assert result['status'] == 'delivered'
    receipt = result['events'][0]['commit_oid']
    notice = from_report(rig.store.room_id(), signed)
    raw = git(channel.remote, 'show', f'{receipt}:wake-{notice["event_id"]}.json')
    assert verify_notice(raw, rig.store, rig.cp) == signed
    assert SECRET not in raw
    assert door.drain()['status'] == 'idle'
    assert channel.tip() == receipt


@pytest.mark.parametrize('accepted', [False, True])
def test_push_failure_reconciles_present_or_retries_absent_without_duplicates(channel, monkeypatch, accepted):
    import agent_room.doorbell_git as module
    a, e = channel.adapter(), event()
    real = module.command
    pushes = []
    def fault(repo, *args, **kwargs):
        if args[0] == 'push':
            pushes.append(args)
            if accepted:
                real(repo, *args, **kwargs)
            raise AgentRoomError('lost reply')
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(module, 'command', fault)
    result = a.post(e)
    assert (result is not None) == accepted
    monkeypatch.setattr(module, 'command', real)
    final = a.find(e)
    assert final == channel.tip()
    assert git(channel.remote, 'rev-list', '--count', f'{channel.seed}..{final}').strip() == '1'
    assert len(pushes) == 1


@pytest.mark.parametrize('accepted', [False, True])
def test_unknown_remote_retains_intent_restart_reconciles(channel, rig, monkeypatch, accepted):
    import agent_room.doorbell_git as module
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise(); report(rig)
    real = module.command
    blocked = []
    def fault(repo, *args, **kwargs):
        if args[0] == 'push':
            if accepted:
                real(repo, *args, **kwargs)
            blocked.append(True)
            raise AgentRoomError('unknown')
        if blocked and args[0] == 'ls-remote':
            raise AgentRoomError('offline')
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(module, 'command', fault)
    assert door.drain()['status'] == 'uncertain'
    assert list(door.ledger.load()['events'].values())[0]['state'] == 'uncertain'
    monkeypatch.setattr(module, 'command', real)
    restarted = GitCommitPR(channel.config, 'codex', a.root); restarted.url = a.url
    second = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', restarted)
    assert second.drain()['status'] == 'delivered'
    assert second.drain()['status'] == 'idle'
    assert git(channel.remote, 'rev-list', '--count', f'{channel.seed}..{channel.tip()}').strip() == '1'


@pytest.mark.parametrize('same_event', [False, True])
def test_concurrent_role_caches_preserve_both_events_or_deduplicate(channel, same_event):
    a, b = channel.adapter('a'), channel.adapter('b')
    x, y = event(), event()
    if same_event:
        y = copy.deepcopy(x)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(a.post, x), pool.submit(b.post, y)]
        for future in futures:
            try:
                future.result()
            except DoorbellError:
                pass  # A moving observation fails closed; finite recovery follows.
    assert a.find(x)
    assert b.find(y)
    expected = '1' if same_event else '2'
    assert git(channel.remote, 'rev-list', '--count', f'{channel.seed}..{channel.tip()}').strip() == expected


def test_crash_after_intent_before_push_recovery_never_replays_turn(channel, rig, monkeypatch):
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise(); report(rig)
    real = a.post
    monkeypatch.setattr(a, 'post', lambda e: (_ for _ in ()).throw(SystemExit()))
    with pytest.raises(SystemExit):
        door.drain()
    assert channel.tip() == channel.seed
    monkeypatch.setattr(a, 'post', real)
    from agent_room import doorbell_worker as worker
    monkeypatch.setattr(worker, 'prepare', lambda role: door)
    monkeypatch.setattr(worker.role_worker, 'run', lambda role: pytest.fail('model replay'))
    assert worker.run('codex', 'recover')['notification']['status'] == 'delivered'


@pytest.mark.parametrize('attack', ['rollback', 'delete', 'replace'])
def test_ref_disappearance_rollback_replacement_fail_closed(channel, attack):
    a, e = channel.adapter(), event()
    a.post(e)
    before = git(a.repo, 'rev-parse', ACCEPTED)
    ref = f'refs/heads/{BRANCH}'
    if attack == 'delete':
        git(channel.remote, 'update-ref', '-d', ref)
    elif attack == 'rollback':
        git(channel.remote, 'update-ref', ref, channel.seed)
    else:
        git(channel.source, 'commit', '--allow-empty', '-qm', 'unrelated seed descendant')
        git(channel.source, 'push', '-q', '--force', 'origin', f'HEAD:{ref}')
    with pytest.raises(DoorbellError):
        a.find(e)
    assert git(a.repo, 'rev-parse', ACCEPTED) == before
    if attack == 'delete':
        assert not git(channel.remote, 'for-each-ref', '--format=%(refname)', ref).strip()


@pytest.mark.parametrize('attack', ['extra', 'modify', 'delete', 'noncanonical', 'mode', 'symlink', 'misname', 'two', 'oversize', 'merge'])
def test_untrusted_history_refused_before_promotion(channel, attack):
    a, e = channel.adapter(), event()
    receipt = a.post(e)
    git(channel.source, 'fetch', '-q', 'origin', f'refs/heads/{BRANCH}')
    git(channel.source, 'reset', '--hard', '-q', 'FETCH_HEAD')
    old = channel.source / f'wake-{e["event_id"]}.json'
    new = event(); path = channel.source / f'wake-{new["event_id"]}.json'
    if attack == 'extra':
        (channel.source / '.gitattributes').write_text('* filter=bad\n')
    elif attack == 'modify':
        old.write_text('{}')
    elif attack == 'delete':
        old.unlink()
    elif attack == 'noncanonical':
        path.write_text(encode(new) + '\n')
    elif attack == 'mode':
        path.write_text(encode(new)); path.chmod(0o755)
    elif attack == 'symlink':
        path.symlink_to('/etc/passwd')
    elif attack == 'misname':
        path.write_text(encode(e))
    elif attack == 'oversize':
        path.write_text('x' * 1025)
    else:
        path.write_text(encode(new))
        if attack == 'two':
            other = event()
            (channel.source / f'wake-{other["event_id"]}.json').write_text(encode(other))
    git(channel.source, 'add', '-A'); git(channel.source, 'commit', '-qm', 'hostile fixture')
    if attack == 'merge':
        tree = git(channel.source, 'rev-parse', 'HEAD^{tree}').strip()
        merged = git(channel.source, 'commit-tree', tree, '-p', 'HEAD', '-p', channel.seed, '-m', 'merge').strip()
        git(channel.source, 'reset', '--hard', '-q', merged)
    git(channel.source, 'push', '-q', 'origin', f'HEAD:refs/heads/{BRANCH}')
    before = sorted(p.name for p in (a.repo / 'objects' / 'pack').iterdir())
    with pytest.raises(DoorbellError):
        a.check_target()
    assert git(a.repo, 'rev-parse', ACCEPTED).strip() == receipt
    assert sorted(p.name for p in (a.repo / 'objects' / 'pack').iterdir()) == before


@pytest.mark.parametrize('field,bad', [('branch', 'agent-room'), ('branch', '../escape'),
    ('bootstrap_tip', 'HEAD'), ('pull_number', True), ('transport', 'shell'), ('path', '/tmp/x')])
def test_config_cannot_select_arbitrary_ref_path_or_transport(channel, field, bad):
    config = dict(channel.config, **{field: bad})
    with pytest.raises(DoorbellError):
        configuration(config)


def test_conflicting_event_bytes_and_wrong_role_do_not_push(channel):
    a, e = channel.adapter(), event()
    receipt = a.post(e)
    conflict = dict(e, event_kind='blocked')
    with pytest.raises(DoorbellError):
        a.find(conflict)
    with pytest.raises(DoorbellError):
        a.post(dict(e, role='claude-code'))
    assert channel.tip() == receipt


def test_capacity_bound_and_deterministic_local_commit(channel, monkeypatch):
    import agent_room.doorbell_git as module
    a, e = channel.adapter(), event()
    raw, path = encode(e).encode(), f'wake-{e["event_id"]}.json'
    assert a._commit(channel.seed, path, raw, e) == a._commit(channel.seed, path, raw, e)
    a.post(e)
    monkeypatch.setattr(module, 'MAX_RECORDS', 1)
    with pytest.raises(DoorbellError):
        a.post(event())
    assert git(channel.remote, 'rev-list', '--count', f'{channel.seed}..{channel.tip()}').strip() == '1'


def test_missing_anchor_cannot_silently_reenroll(channel):
    a = channel.adapter()
    git(a.repo, 'update-ref', '-d', ACCEPTED)
    with pytest.raises(DoorbellError):
        a.check_target()
    with pytest.raises(DoorbellError):
        a.enroll()


def test_production_prepare_commit_adapter_never_opens_token(channel, rig, monkeypatch):
    from agent_room import doorbell_worker as worker
    item = dict(state=str(channel.root / 'state'), checkpoint=str(rig.cp.path))
    monkeypatch.setattr(worker.custody, 'guard', lambda role: item)
    monkeypatch.setattr(worker.custody, 'root_json', lambda path: channel.config if path == worker.CONFIG else {})
    monkeypatch.setattr(worker.custody, 'install_environment', lambda *a: None)
    monkeypatch.setattr(worker.role_worker, 'room_for', lambda *a: SimpleNamespace(store=rig.store))
    monkeypatch.setattr(worker, 'comment_adapter', lambda *a: pytest.fail('API credential path'))
    result = worker.prepare('codex')
    assert isinstance(result.transport, GitCommitPR)
    assert result.transport.url == 'git@github.com:example/room.git'


def test_remote_ref_deleted_between_observation_and_push_is_not_recreated(channel, monkeypatch):
    import agent_room.doorbell_git as module
    a, e = channel.adapter(), event()
    real = module.command
    def delete_then_push(repo, *args, **kwargs):
        if args[0] == 'push':
            git(channel.remote, 'update-ref', '-d', f'refs/heads/{BRANCH}')
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(module, 'command', delete_then_push)
    with pytest.raises(DoorbellError):
        a.post(e)
    assert not git(channel.remote, 'for-each-ref', '--format=%(refname)', f'refs/heads/{BRANCH}').strip()


def test_crash_after_remote_acceptance_before_ledger_receipt(channel, rig, monkeypatch):
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise(); report(rig)
    save = door.ledger.save
    def crash(doc):
        if any(v['state'] == 'delivered' for v in doc['events'].values()):
            raise SystemExit('before receipt fsync')
        save(doc)
    monkeypatch.setattr(door.ledger, 'save', crash)
    with pytest.raises(SystemExit):
        door.drain()
    tip = channel.tip()
    monkeypatch.setattr(door.ledger, 'save', save)
    assert door.drain()['status'] == 'delivered'
    assert channel.tip() == tip


@pytest.mark.parametrize('receipt', [None, True, 1, 'HEAD', 'a' * 39, {}, []])
def test_commit_receipt_schema_cannot_be_reinterpreted_as_delivered(channel, rig, receipt):
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise()
    notice = from_report(rig.store.room_id(), report(rig))
    doc = door.ledger.load()
    doc['events'][notice['event_id']] = dict(event=notice, state='delivered', commit_oid=receipt)
    with pytest.raises(AgentRoomError):
        door.ledger.save(doc)
    assert channel.tip() == channel.seed


def test_config_switch_requires_explicit_ledger_migration(channel, rig):
    from tests.test_agent_room_doorbell import CONFIG, FakeGitHub
    a = channel.adapter()
    door = Doorbell(rig.store, rig.cp, a.root, channel.config, 'codex', a)
    door.ledger.initialise()
    fallback = Doorbell(rig.store, rig.cp, a.root, CONFIG, 'codex', FakeGitHub())
    with pytest.raises(DoorbellError):
        fallback.ledger.load()
