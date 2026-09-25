"""C1 architecture/guard tests. Mocked NSS is NOT a cross-UID security proof."""
import errno
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace as NS

import pytest

from agent_room import custody as c, role_worker, release_worker, transport_worker
from agent_room import custody_verify as verifier

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy'


def document():
    return json.loads((DEPLOY / 'custody/roles.json').read_text())


@pytest.fixture
def fake_host(monkeypatch):
    """All identity/filesystem mocks are contained here, never in runtime code."""
    doc = document()
    users, groups = {}, {}
    for i, (role, item) in enumerate(doc['roles'].items(), 2000):
        users[item['user']] = NS(pw_name=item['user'], pw_uid=i, pw_gid=i, pw_dir=item['home'])
        groups[item['group']] = NS(gr_gid=i, gr_mem=[])
    users['pr0'] = NS(pw_name='pr0', pw_uid=1000, pw_gid=1000)
    own = users['agentroom-claude']
    metadata = {}
    for role, item in doc['roles'].items():
        uid = users[item['user']].pw_uid
        for key in ('state_root', 'home', 'workspace', 'room', 'state'):
            metadata[item[key]] = NS(st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_nlink=1)
        metadata[f'{item["state_root"]}/keys'] = NS(st_mode=stat.S_IFDIR | 0o700, st_uid=uid, st_nlink=1)
        for key in ('signing_key', 'repository_key', 'canary'):
            metadata[item[key]] = NS(st_mode=stat.S_IFREG | 0o600, st_uid=uid, st_nlink=1)
        metadata[f'{item["home"]}/.gitconfig'] = NS(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1)
    monkeypatch.setattr(c, 'load_manifest', lambda: c.validate_manifest(doc))
    monkeypatch.setattr(c.pwd, 'getpwnam', lambda name: users[name])
    monkeypatch.setattr(c.pwd, 'getpwuid', lambda uid: next(u for u in users.values() if u.pw_uid == uid))
    monkeypatch.setattr(c.grp, 'getgrnam', lambda name: groups[name])
    monkeypatch.setattr(c.os, 'getgrouplist', lambda name, gid: [gid])
    monkeypatch.setattr(c.os, 'getresuid', lambda: (own.pw_uid,) * 3)
    monkeypatch.setattr(c.os, 'getresgid', lambda: (own.pw_gid,) * 3)
    monkeypatch.setattr(c.os, 'geteuid', lambda: own.pw_uid)
    monkeypatch.setattr(c.os, 'getgroups', lambda: [own.pw_gid])
    monkeypatch.setattr(c.os, 'access', lambda *a, **kw: True)
    monkeypatch.setattr(c, '_metadata', lambda p: metadata[str(p)])
    monkeypatch.setattr(c, 'root_file', Path)
    real_read = Path.read_text

    def read(path, *a, **kw):
        if str(path) == f'{doc["roles"]["claude-code"]["home"]}/.gitconfig':
            return c.git_config('claude-code')
        if str(path) == '/etc/agent-room/ssh/claude-code.conf':
            return c.ssh_config(doc['roles']['claude-code'])
        return real_read(path, *a, **kw)
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(c.os, 'open', lambda *a, **kw: (_ for _ in ()).throw(PermissionError(errno.EACCES, 'denied')))
    return doc, users, groups, metadata


def test_only_qualified_layout():
    d = c.validate_manifest(document())
    assert len({r['user'] for r in d['roles'].values()}) == 5
    assert len({r['state_root'] for r in d['roles'].values()}) == 5
    assert d['human']['private_key'] is None
    assert d['roles']['release-recorder']['client'] is None


@pytest.mark.parametrize('change', ['human', 'shared-user', 'shared-root', 'extra', 'bool-version', 'pr0'])
def test_manifest_mutations(change):
    d = document()
    if change == 'human': d['human']['private_key'] = '/host/key'
    elif change == 'shared-user': d['roles']['codex']['user'] = 'agentroom-claude'
    elif change == 'shared-root': d['roles']['codex']['state_root'] = '/var/lib/agent-room-claude'
    elif change == 'extra': d['roles']['codex']['ignore_isolation'] = True
    elif change == 'bool-version': d['version'] = True
    else: d['roles']['codex']['user'] = 'pr0'
    with pytest.raises(c.CustodyError): c.validate_manifest(d)


def test_guard_nominal_simulated_host(fake_host):
    assert c.guard('claude-code')['user'] == 'agentroom-claude'


@pytest.mark.parametrize('failure', ['uid', 'duplicate-uid', 'duplicate-gid', 'cross-group', 'inherited-group', 'pr0-group'])
def test_identity_refusals(fake_host, monkeypatch, failure):
    d, users, groups, _ = fake_host
    a, b = users['agentroom-claude'], users['agentroom-codex']
    if failure == 'uid': monkeypatch.setattr(c.os, 'getresuid', lambda: (1000,) * 3)
    elif failure == 'duplicate-uid': b.pw_uid = a.pw_uid
    elif failure == 'duplicate-gid':
        b.pw_gid = a.pw_gid
        groups['agentroom-codex'].gr_gid = a.pw_gid
    elif failure == 'cross-group': monkeypatch.setattr(c.os, 'getgrouplist', lambda n, g: [g, b.pw_gid])
    elif failure == 'inherited-group': monkeypatch.setattr(c.os, 'getgroups', lambda: [a.pw_gid, b.pw_gid])
    else: monkeypatch.setattr(c.os, 'getgrouplist', lambda n, g: [g, a.pw_gid] if n == 'pr0' else [g])
    with pytest.raises(c.CustodyError): c.guard('claude-code')


@pytest.mark.parametrize('kind', ['symlink', 'owner', 'group-read', 'world-read', 'hardlink', 'executable', 'parent-symlink', 'root-shared'])
def test_unsafe_private_paths(fake_host, kind):
    d, _, _, meta = fake_host
    item = d['roles']['claude-code']
    target = meta[item['signing_key']]
    if kind == 'symlink': target.st_mode = stat.S_IFLNK | 0o600
    elif kind == 'owner': target.st_uid = 1000
    elif kind == 'group-read': target.st_mode |= 0o040
    elif kind == 'world-read': target.st_mode |= 0o004
    elif kind == 'hardlink': target.st_nlink = 2
    elif kind == 'executable': target.st_mode |= 0o100
    elif kind == 'parent-symlink': meta[item['state_root'] + '/keys'].st_mode = stat.S_IFLNK | 0o700
    else: meta[item['state_root']].st_mode |= 0o050
    with pytest.raises(c.CustodyError): c.guard('claude-code')


@pytest.mark.parametrize('other', ['codex', 'coordinator', 'release-recorder', 'openai-research'])
def test_original_high_readable_sibling_refused_before_client(fake_host, monkeypatch, other):
    d, *_ = fake_host
    denied = c.os.open
    key = d['roles'][other]['signing_key']
    monkeypatch.setattr(c.os, 'open', lambda path, flags: 999 if str(path) == key else denied(path, flags))
    monkeypatch.setattr(c.os, 'close', lambda fd: None)
    monkeypatch.setattr(role_worker, 'room_for', lambda *a: pytest.fail('must refuse before signer/client'))
    with pytest.raises(c.CustodyError, match='unexpectedly readable'):
        role_worker.run('claude-code')


@pytest.mark.parametrize('error', [errno.ENOENT, errno.EIO, errno.ELOOP])
def test_missing_or_broken_sibling_is_not_isolation(fake_host, monkeypatch, error):
    def broken(*a): raise OSError(error, 'not proof')
    monkeypatch.setattr(c.os, 'open', broken)
    with pytest.raises(c.CustodyError, match='unknown'): c.guard('claude-code')


@pytest.mark.parametrize('mode,owner', [(0o644, 1000), (0o664, 0), (0o666, 0), (stat.S_IFLNK | 0o644, 0)])
def test_mutable_nonroot_symlink_manifest_rejected(monkeypatch, mode, owner):
    def metadata(path):
        if str(path) == str(c.MANIFEST):
            return NS(st_mode=(stat.S_IFREG | mode) if not mode & stat.S_IFLNK else mode,
                      st_uid=owner, st_nlink=1)
        return NS(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_nlink=1)
    monkeypatch.setattr(c, '_metadata', metadata)
    with pytest.raises(c.CustodyError): c.root_file(c.MANIFEST)


def test_config_ancestor_refused(monkeypatch):
    monkeypatch.setattr(c, '_metadata', lambda p: NS(st_mode=stat.S_IFDIR | 0o777, st_uid=0))
    with pytest.raises(c.CustodyError): c.root_file(c.MANIFEST)


def test_actual_unprivileged_manifest_refused(tmp_path):
    f = tmp_path / 'roles.json'
    f.write_text(json.dumps(document()))
    with pytest.raises(c.CustodyError): c.root_file(f)


def test_no_production_dispatch_on_guard_refusal(monkeypatch):
    def refuse(*a): raise c.CustodyError('custody refused')
    monkeypatch.setattr(c, 'guard', refuse)
    monkeypatch.setattr(c, 'root_json', lambda *a: pytest.fail('must not load requests'))
    assert role_worker.main(['claude-code']) == 1
    assert role_worker.main(['coordinator']) == 1
    assert release_worker.main([]) == 1
    assert transport_worker.main([]) == 1


@pytest.mark.parametrize('role', ['human', 'release-recorder', 'openai-research', '--insecure'])
def test_participant_cannot_choose_privileged_surface(role):
    assert role_worker.main([role]) == 1


def test_worker_args_cannot_choose_configs_or_receipts():
    assert role_worker.main(['codex', '/tmp/evil']) == 2
    assert release_worker.main(['reserve', 'evil']) == 2
    assert transport_worker.main(['/tmp/transport.json']) == 2


def test_environment_has_only_role_auth(monkeypatch):
    monkeypatch.setenv('SSH_AUTH_SOCK', '/pr0/agent')
    monkeypatch.setenv('OPENAI_API_KEY', 'NOT-A-KEY')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', '/pr0/config')
    monkeypatch.setenv('HOME', '/home/pr0')
    monkeypatch.setattr(c.os, 'umask', lambda mask: None)
    original = dict(os.environ)
    try:
        c.install_environment('codex', c.layout('codex'))
        assert os.environ['HOME'] == '/var/lib/agent-room-codex/home'
        assert os.environ['CODEX_HOME'].startswith(os.environ['HOME'])
        assert not {'SSH_AUTH_SOCK', 'OPENAI_API_KEY', 'GIT_CONFIG_GLOBAL'} & os.environ.keys()
    finally:
        os.environ.clear()
        os.environ.update(original)


@pytest.mark.parametrize('role', list(c.ACCOUNTS))
def test_templates_match_custody(role):
    item = c.layout(role)
    unit = (DEPLOY / verifier.UNITS[role]).read_text()
    for setting in (f'User={item["user"]}', f'Group={item["group"]}',
                    f'StateDirectory={Path(item["state_root"]).name}',
                    'UMask=0077', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
                    'AmbientCapabilities=', 'ProtectSystem=strict', 'ProtectHome=yes',
                    'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectProc=invisible',
                    'ProcSubset=pid', 'RestrictSUIDSGID=yes', 'LockPersonality=yes',
                    'Delegate=no', 'KillMode=control-group'):
        assert setting in unit
    inaccessible = ' '.join(l.split('=', 1)[1] for l in unit.splitlines() if l.startswith('InaccessiblePaths='))
    for other in c.ACCOUNTS:
        if other != role: assert c.layout(other)['state_root'] in inaccessible.split()
    readwrite = [l for l in unit.splitlines() if l.startswith(('ReadWritePaths=', 'ReadOnlyPaths='))]
    for other in c.ACCOUNTS:
        if other != role: assert all(c.layout(other)['state_root'] not in l for l in readwrite)
    assert not any(s in unit for s in ('sudo ', 'tests.', 'transport_library_fixture', '--insecure'))
    assert (DEPLOY / f'custody/ssh/{role}.conf').read_text() == c.ssh_config(item)
    assert (DEPLOY / f'custody/git/{role}.gitconfig').read_text() == c.git_config(role)


def test_release_has_no_model_or_generic_signing_surface():
    unit = (DEPLOY / verifier.UNITS['release-recorder']).read_text()
    exec_lines = [l for l in unit.splitlines() if l.startswith('Exec')]
    assert exec_lines == ['ExecStart=/usr/bin/python3 -s -m agent_room.release_worker']
    assert '[Install]' not in unit
    source = (ROOT / 'agent_room/release_worker.py').read_text()
    assert 'claude_participant' not in source and 'codex_participant' not in source
    assert 'subprocess' not in source and 'socket' not in source.split('"""')[2]
    assert "root_json('/etc/agent-room/release-request.json')" in source


@pytest.mark.parametrize('code,stderr,accept', [(0, '', False), (1, 'a password is required', True),
                                              (1, 'I/O failure', False), (127, '', False)])
def test_verifier_never_accepts_passwordless_root_or_unknown(monkeypatch, code, stderr, accept):
    monkeypatch.setattr(verifier.subprocess, 'run', lambda *a, **kw: NS(returncode=code, stderr=stderr))
    if accept: verifier.sudo_denied()
    else:
        with pytest.raises(c.CustodyError): verifier.sudo_denied()


def test_verifier_not_run_as_unprivileged_proof(monkeypatch):
    monkeypatch.setattr(verifier.os, 'geteuid', lambda: 1000)
    assert verifier.main([]) == 2


@pytest.mark.parametrize('role', ['claude-code', 'codex'])
def test_actual_adapter_wiring_is_after_guard_and_role_local(monkeypatch, role):
    from agent_room import claude_participant as claude, codex_participant as codex
    events = []
    item = c.layout(role)
    config = {'key_id': f'{role}-1', 'room_branch': 'agent-room', 'room_remote': 'origin'}
    monkeypatch.setattr(c, 'guard', lambda r: events.append(('guard', r)) or item)
    monkeypatch.setattr(c, 'root_json', lambda path: events.append(('config', path)) or config)
    monkeypatch.setattr(c, 'install_environment', lambda r, i: events.append(('environment', r)))
    monkeypatch.setattr(c, 'root_file', lambda path: events.append(('root_file', path)) or Path(path))
    monkeypatch.setattr(role_worker, 'room_for', lambda r, i, cfg: events.append(('room', r)) or 'room')

    class Invoker:
        def __init__(self, executable, *, cwd):
            events.append(('client', executable, cwd))

    class Adapter:
        def __init__(self, room, invoker): assert room == 'room'
        def run_turn(self): return {'one_turn': True}

    module = claude if role == 'claude-code' else codex
    monkeypatch.setattr(module, 'ClaudeInvoker' if role == 'claude-code' else 'CodexInvoker', Invoker)
    monkeypatch.setattr(module, 'ClaudeParticipant' if role == 'claude-code' else 'CodexParticipant', Adapter)
    assert role_worker.run(role) == {'one_turn': True}
    assert events == [('guard', role), ('config', f'/etc/agent-room/{role}.json'),
                      ('environment', role), ('room', role), ('root_file', item['client']),
                      ('client', item['client'], item['workspace'])]


@pytest.mark.parametrize('extra', ['role', 'uid', 'signer', 'signing_key', 'workspace', 'command', 'ignore_isolation'])
def test_role_config_cannot_select_custody(extra):
    config = {'key_id': 'codex-1', 'room_branch': 'agent-room', 'room_remote': 'origin', extra: 'evil'}
    with pytest.raises(c.CustodyError): role_worker.room_for('codex', c.layout('codex'), config)


def test_coordinator_reuses_signatures_without_other_identity(monkeypatch, signed_store, trust_material, tmp_path):
    from agent_room.ids import uuid7
    role = 'coordinator'
    item = dict(c.layout(role), room=str(signed_store.workdir), state=str(tmp_path / 'cursor'),
                signing_key=str(trust_material['signers'][role].key_path))
    config = {'key_id': 'coordinator-1', 'room_branch': 'agent-room', 'room_remote': 'origin',
              'message': {'message_id': uuid7(), 'thread_id': 't1', 'type': 'handoff',
                          'recipient': {'agent': 'codex'}, 'project': {}, 'body': {'text': 'inspect'}}}
    monkeypatch.setattr(c, 'guard', lambda r: item)
    monkeypatch.setattr(c, 'root_json', lambda p: config)
    monkeypatch.setattr(c, 'install_environment', lambda *a: None)
    monkeypatch.setattr(role_worker, 'GitMessageStore', lambda *a, **kw: signed_store)
    monkeypatch.setattr(role_worker.TrustPolicy, 'load', lambda p: trust_material['policy'])
    role_worker.run(role)
    messages = list(signed_store.iter_messages())
    assert len(messages) == 1
    assert messages[0]['sender']['agent'] == 'coordinator'
    assert signed_store.verify_store() == 1


@pytest.mark.parametrize('operation', ['reserve', 'reconcile'])
def test_release_fixed_manual_dispatch(monkeypatch, operation):
    item = c.layout('release-recorder')
    ticket = {'operation': operation, 'key_id': 'release-recorder-1', 'request_id': 'request'}
    if operation == 'reconcile': ticket.update(status='failed', result={'observed': 'not executed'})
    calls = []
    monkeypatch.setattr(c, 'guard', lambda r: calls.append(('guard', r)) or item)
    monkeypatch.setattr(c, 'root_json', lambda p: calls.append(('ticket', p)) or ticket)
    monkeypatch.setattr(c, 'install_environment', lambda *a: None)
    monkeypatch.setattr(release_worker, 'Ed25519Signer', lambda path, **kw: calls.append(('signer', path, kw)) or 'signer')
    monkeypatch.setattr(release_worker, 'GitMessageStore', lambda *a, **kw: 'store')
    monkeypatch.setattr(release_worker.TrustPolicy, 'load', lambda p: 'public-policy')
    monkeypatch.setattr(release_worker.release, operation, lambda *a, **kw: calls.append((operation, a, kw)) or {'ok': True})
    assert release_worker.run() == {'ok': True}
    assert calls[:2] == [('guard', 'release-recorder'), ('ticket', '/etc/agent-room/release-request.json')]
    assert calls[2] == ('signer', item['signing_key'], {'signer': 'release-recorder', 'key_id': 'release-recorder-1'})
    assert calls[3][0] == operation and calls[3][1] == ('store', 'request')
    assert calls[3][2]['workdir'] == item['workspace']
    assert calls[3][2]['checkpoint_path'] == item['checkpoint']
    assert calls[3][2]['state_path'] == f'{item["state"]}/release-reservation.json'


@pytest.mark.parametrize('ticket', [None, [], {'operation': 'command'},
    {'operation': 'reserve', 'key_id': 'k', 'request_id': 'r', 'signer': 'claude-code'},
    {'operation': 'reserve', 'key_id': 'k', 'request_id': 'r', 'target': '/tmp/evil'}])
def test_release_rejects_ticket_expansion(monkeypatch, ticket):
    monkeypatch.setattr(c, 'guard', lambda r: c.layout(r))
    monkeypatch.setattr(c, 'root_json', lambda p: ticket)
    monkeypatch.setattr(release_worker, 'Ed25519Signer', lambda *a, **kw: pytest.fail('no signer'))
    with pytest.raises(c.CustodyError): release_worker.run()


@pytest.mark.parametrize('field', ['room_workdir', 'control_workdir', 'trust_policy_path', 'checkpoint_path', 'state_dir', 'signing_key_path'])
def test_supervisor_cannot_name_other_custody(monkeypatch, field):
    config = NS(**json.loads((DEPLOY / 'transport.json.example').read_text()))
    setattr(config, field, '/var/lib/agent-room-release/keys/release-recorder.ed25519.pem')
    monkeypatch.setattr(c, 'private_path', lambda *a, **kw: None)
    with pytest.raises(c.CustodyError): c.check_transport(config, c.layout('openai-research'))


@pytest.mark.parametrize('role', list(c.ACCOUNTS))
def test_ssh_config_parses_without_network_or_agent(role):
    import subprocess
    output = subprocess.run(['/usr/bin/ssh', '-G', '-F', str(DEPLOY / f'custody/ssh/{role}.conf'),
                             'git@github.com'], capture_output=True, text=True, check=True).stdout
    assert 'identityagent none\n' in output
    assert 'identitiesonly yes\n' in output
    assert f'identityfile {c.layout(role)["repository_key"]}\n' in output
    for other in c.ACCOUNTS:
        if other != role: assert c.layout(other)['repository_key'] not in output


@pytest.mark.skip(reason='NOT TESTABLE UNTIL DEPLOYMENT: actual dedicated UIDs/users are not created here')
def test_actual_cross_uid_malicious_client_canary():
    """Mandatory activation prerequisite: custody_verify as an authorized operator."""
