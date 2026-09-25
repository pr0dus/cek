"""C5 only: explicit SSH custody and exact advertised recovery refs.

Local repositories/keys are disposable. Simulated NSS tests and an SSH adapter
exercise binding/wiring, not deployed cross-UID or production SSH enforcement.
"""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_room import custody, git_ingestion as ingestion, remote_sync
from agent_room.errors import AgentRoomError
from tests.conftest_agent_room import git
from tests.test_agent_room_custody_c1 import fake_host
from tests.test_agent_room_transport_remote_s3 import net


@pytest.mark.parametrize('role', list(custody.ACCOUNTS))
def test_network_role_is_derived_from_kernel_account_not_environment(monkeypatch, role):
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid:
                        SimpleNamespace(pw_name=custody.ACCOUNTS[role][0]))
    calls = []
    monkeypatch.setattr(custody, 'guard', lambda r: calls.append(r))
    monkeypatch.setenv('USER', 'agentroom-release')
    monkeypatch.setenv('HOME', '/fake/sibling/home')
    options, env = custody.network_git_binding(('fetch', 'origin'))
    assert env == {'GIT_ALLOW_PROTOCOL': 'ssh'}
    assert calls == [role]
    assert 'core.sshCommand=/usr/bin/ssh -F /etc/agent-room/ssh/'+role+'.conf' in options
    assert 'protocol.allow=never' in options
    assert 'protocol.ssh.allow=always' in options
    for scheme in ('file', 'git', 'http', 'https', 'ext'):
        assert 'protocol.'+scheme+'.allow=never' in options


def test_actual_guard_rechecks_ssh_config_for_network(fake_host, monkeypatch):
    # Existing full C1 guard, simulated identities/files; not guard=lambda True.
    assert 'core.sshCommand=/usr/bin/ssh -F /etc/agent-room/ssh/claude-code.conf' in (
        custody.network_git_binding(('fetch', 'origin'))[0])
    original = Path.read_text
    def changed(path, *args, **kwargs):
        if str(path) == '/etc/agent-room/ssh/claude-code.conf':
            return original(path, *args, **kwargs) + '    IdentityFile /unvalidated\n'
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', changed)
    with pytest.raises(custody.CustodyError, match='SSH config'):
        custody.network_git_binding(('fetch', 'origin'))


@pytest.mark.parametrize('mutation', ['uid', 'gitconfig', 'missing-ssh', 'cross-role-group'])
def test_invalid_custody_never_supplies_network_options(fake_host, monkeypatch, mutation):
    doc, users, groups, meta = fake_host
    if mutation == 'uid':
        monkeypatch.setattr(custody.os, 'getresuid', lambda: (1000, 1000, 1000))
    elif mutation == 'cross-role-group':
        monkeypatch.setattr(custody.os, 'getgroups', lambda: [users['agentroom-codex'].pw_gid])
    elif mutation == 'missing-ssh':
        original = custody.root_file
        def missing(path):
            if str(path).startswith('/etc/agent-room/ssh/'):
                raise custody.CustodyError('missing protected SSH configuration')
            return original(path)
        monkeypatch.setattr(custody, 'root_file', missing)
    else:
        meta[doc['roles']['claude-code']['home']+'/.gitconfig'].st_uid = 1000
    with pytest.raises(custody.CustodyError):
        custody.network_git_binding(('fetch', 'origin'))


@pytest.mark.parametrize('entry', ['quarantine', 'transport', 'library', 'library-bytes'])
@pytest.mark.parametrize('url', ['ssh://audit.invalid/repo', 'git@audit.invalid:repo'])
def test_unchecked_ssh_cannot_fall_back_at_any_network_boundary(net, tmp_path, monkeypatch, entry, url):
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_name='unprovisioned'))
    home = tmp_path/'malicious-home'
    home.mkdir()
    marker = tmp_path/'BYPASS'
    helper = tmp_path/'untrusted-ssh'
    helper.write_text('#!/bin/sh\n/usr/bin/touch '+str(marker)+'\nexit 1\n')
    helper.chmod(0o700)
    (home/'.gitconfig').write_text('[core]\n\tsshCommand = '+str(helper)+'\n')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('GIT_SSH_COMMAND', str(helper))
    monkeypatch.setenv('GIT_SSH', str(helper))
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'protocol.ssh.allow')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'always')
    repo = net['room'].workdir
    # Configure before invoking the guarded helper, not through a mock Git result.
    git(repo, 'config', 'core.sshCommand', str(helper))
    git(repo, 'config', 'protocol.ssh.allow', 'always')
    if entry == 'quarantine':
        with pytest.raises(AgentRoomError):
            ingestion.fetch_verified(repo, url, 'refs/heads/agent-room',
                                     'refs/heads/probe', lambda *a: pytest.fail('no verification'))
    elif entry == 'transport':
        with pytest.raises(AgentRoomError): remote_sync.run_git(repo, 'ls-remote', url)
    elif entry == 'library':
        with pytest.raises(AgentRoomError): net['room']._git('ls-remote', url)
    else:
        with pytest.raises(AgentRoomError): net['room']._git_bytes('ls-remote', url)
    assert not marker.exists()


@pytest.mark.parametrize('entry', ['quarantine', 'transport', 'library', 'library-bytes'])
def test_changed_guard_fails_before_starting_network_process(net, monkeypatch, entry):
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_name='agentroom-claude'))
    def refused(role): raise custody.CustodyError('custody changed')
    monkeypatch.setattr(custody, 'guard', refused)
    def forbidden(*a, **k): pytest.fail('network subprocess must not start')
    if entry == 'quarantine':
        monkeypatch.setattr(ingestion, 'run_bounded', forbidden)
        with pytest.raises(custody.CustodyError): ingestion.command(net['room'].workdir, 'fetch', 'origin')
    elif entry == 'transport':
        monkeypatch.setattr(remote_sync, 'run_bounded', forbidden)
        with pytest.raises(custody.CustodyError): remote_sync.run_git(net['room'].workdir, 'ls-remote', 'origin')
    else:
        import agent_room.gitstore as module
        monkeypatch.setattr(module.subprocess, 'run', forbidden)
        with pytest.raises(custody.CustodyError):
            (net['room']._git_bytes if entry.endswith('bytes') else net['room']._git)('push', 'origin')


@pytest.mark.parametrize('entry', ['quarantine', 'transport', 'library', 'library-bytes'])
@pytest.mark.parametrize('alternate', ['file', 'https', 'custom-helper'])
def test_checked_role_cannot_fall_back_to_alternate_transport(net, tmp_path, monkeypatch, entry, alternate):
    # Even a repo-config allow rule and a rewrite to an arbitrary helper must
    # not bypass the checked SSH transport. This test makes no network contact.
    repo = net['room'].workdir
    marker = tmp_path/'BYPASS'
    helper = tmp_path/'git-remote-c5-fixture'
    helper.write_text('#!/bin/sh\n/usr/bin/touch '+str(marker)+'\nexit 1\n')
    helper.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path)+':'+os.environ['PATH'])
    monkeypatch.setenv('GIT_ALLOW_PROTOCOL', 'file:https:c5-fixture')
    git(repo, 'config', 'protocol.c5-fixture.allow', 'always')
    git(repo, 'config', 'protocol.file.allow', 'always')
    git(repo, 'config', 'protocol.https.allow', 'always')
    url = {'file': str(net['origin_room']), 'https': 'https://invalid.example/no-network',
           'custom-helper': 'c5-fixture::not-a-real-remote'}[alternate]
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_name='agentroom-claude'))
    monkeypatch.setattr(custody, 'guard', lambda r: None)
    with pytest.raises(AgentRoomError, match='not allowed'):
        if entry == 'quarantine': ingestion.command(repo, 'fetch', url)
        elif entry == 'transport': remote_sync.run_git(repo, 'ls-remote', url)
        elif entry == 'library': net['room']._git('ls-remote', url)
        else: net['room']._git_bytes('ls-remote', url)
    assert not marker.exists()


def test_url_rewrite_cannot_escape_checked_protocol(net, tmp_path, monkeypatch):
    repo = net['room'].workdir
    marker = tmp_path/'BYPASS'
    helper = tmp_path/'git-remote-c5-fixture'
    helper.write_text('#!/bin/sh\n/usr/bin/touch '+str(marker)+'\nexit 1\n')
    helper.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path)+':'+os.environ['PATH'])
    git(repo, 'config', 'url.c5-fixture::.insteadOf', 'ssh://apparent.invalid/')
    git(repo, 'config', 'protocol.c5-fixture.allow', 'always')
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_name='agentroom-claude'))
    monkeypatch.setattr(custody, 'guard', lambda r: None)
    with pytest.raises(AgentRoomError, match='not allowed'):
        remote_sync.run_git(repo, 'ls-remote', 'ssh://apparent.invalid/repo')
    assert not marker.exists()


def test_same_explicit_binding_in_observation_and_actual_quarantine_fetch(net, tmp_path, monkeypatch):
    # Actual Git protocol/pack transfer through an in-test SSH adapter. No real
    # SSH credentials, users or production paths are created. The single argv
    # replacement below substitutes only the nonexistent installed SSH command.
    adapter = tmp_path/'ssh_fixture.py'
    log = tmp_path/'ssh_calls.jsonl'
    adapter.write_text('import os,sys,json,shlex\n'
        'with open('+repr(str(log))+', "a") as f: f.write(json.dumps(sys.argv)+"\\n")\n'
        'args=shlex.split(sys.argv[-1])\n'
        'assert len(args)==2 and args[0]=="git-upload-pack"\n'
        'os.execv("/usr/bin/git", ["git", "upload-pack", args[1]])\n')
    url = 'ssh://public-fixture'+str(net['origin_room'])
    git(net['room'].workdir, 'remote', 'set-url', 'origin', url)
    monkeypatch.setattr(custody.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_name='agentroom-claude'))
    guarded = []
    monkeypatch.setattr(custody, 'guard', lambda r: guarded.append(r))
    expected = 'core.sshCommand=/usr/bin/ssh -F /etc/agent-room/ssh/claude-code.conf'
    actual_run = ingestion.run_bounded
    seen = []
    def observe(argv, **kwargs):
        if expected in argv:
            seen.append((argv.copy(), kwargs['env'].copy()))
            argv = [a if a != expected else 'core.sshCommand=/usr/bin/python3 '+str(adapter) for a in argv]
        return actual_run(argv, **kwargs)
    monkeypatch.setattr(ingestion, 'run_bounded', observe)
    monkeypatch.setattr(remote_sync, 'run_bounded', observe)
    monkeypatch.setenv('GIT_SSH_COMMAND', '/untrusted')
    observed = remote_sync.run_git(net['room'].workdir, 'ls-remote', 'origin', 'refs/heads/agent-room')
    verified = []
    def verify(path, branch, tip):
        # Complete signed candidate validation, not just a fake success marker.
        from agent_room import GitMessageStore
        candidate = GitMessageStore(path, branch=branch, trust=net['policy'])
        assert candidate.verify_store() == 1
        verified.append(candidate.current_tip())
    tip = ingestion.fetch_verified(net['room'].workdir, 'origin', 'refs/heads/agent-room',
                                   'refs/heads/c5-candidate', verify)
    assert verified == [tip] and tip in observed.stdout.decode()
    assert len(seen) == len(guarded) == 2
    assert all('GIT_SSH_COMMAND' not in env for argv, env in seen)
    assert all(env['GIT_ALLOW_PROTOCOL'] == 'ssh' for argv, env in seen)
    assert seen[1][1]['GIT_CONFIG_GLOBAL'] == '/dev/null'
    assert all(expected in argv and 'ssh.variant=ssh' in argv for argv, env in seen)
    assert all('protocol.http.allow=never' in argv for argv, env in seen)
    assert len(log.read_text().splitlines()) == 2
    assert not (net['room'].workdir/'.git/agent-room-quarantine/attempt').exists()


def test_ambiguous_ref_does_not_trigger_fetch_fallback(net, monkeypatch):
    store = net['room']; store.remote = 'origin'
    tip, root = store.current_tip(), store.room_id()
    git(net['origin_room'], 'update-ref', 'refs/heads/aaa/refs/heads/agent-room', tip)
    git(net['origin_room'], 'update-ref', store.ref, root)
    monkeypatch.setattr(store, '_fetch_verified_remote',
                        lambda: pytest.fail('ambiguous advertisement cannot authorize fallback'))
    result = store._reconcile_push(tip)
    assert result[0] is None and result[1] is False
    assert isinstance(result[2], AgentRoomError)


@pytest.mark.parametrize('alias', ['refs/heads/aaa/refs/heads/agent-room',
    'refs/tags/refs/heads/agent-room', 'refs/namespaces/other/refs/heads/agent-room',
    'refs/heads/agent-room-copy', 'refs/heads/agent-room/sub', 'refs/tags/agent-room',
    'refs/heads/agent-rооm'])
@pytest.mark.parametrize('canonical_present', [True, False])
def test_real_adversarial_ref_cannot_prove_library_delivery(net, alias, canonical_present):
    store = net['room']; store.remote = 'origin'
    tip, root = store.current_tip(), store.room_id()
    if not canonical_present:
        git(net['origin_room'], 'update-ref', '-d', store.ref)
    if canonical_present and alias.startswith(store.ref+'/'):
        # Git itself rejects this directory/file conflict. Exercise that fact
        # rather than pretending the two refs can coexist in a real remote.
        import subprocess
        result = subprocess.run(['git', 'update-ref', alias, tip],
                                cwd=net['origin_room'], capture_output=True)
        assert result.returncode != 0
    else:
        git(net['origin_room'], 'update-ref', alias, tip)
    if canonical_present:
        git(net['origin_room'], 'update-ref', store.ref, root)
    result = store._reconcile_push(tip)
    assert result[0] is not True, (alias, result)
    if result[1]: assert result[0] is False
    else: assert result[0] is None and isinstance(result[2], AgentRoomError)


def test_ambiguous_even_when_exact_ref_also_matches_fails_closed(net):
    store = net['room']; store.remote = 'origin'
    tip = store.current_tip()
    git(net['origin_room'], 'update-ref', 'refs/heads/aaa/refs/heads/agent-room', tip)
    result = store._reconcile_push(tip)
    assert result[0] is None and result[1] is False
    assert isinstance(result[2], AgentRoomError)


@pytest.mark.parametrize('advertisement', ['\n', 'bad', '{oid} {ref}\n',
    '{oid}\t{ref}\textra\n', '{oid}\t{ref}\n{oid}\t{ref}\n',
    'bad\t{ref}\n', 'ffffffff\t{ref}\n', '{oid}\t{ref}\x00\n',
    '{oid}\trefs/tags/agent-room\n', '{oid}\t{ref}\n\n'])
def test_malformed_advertisement_never_proves_delivery(net, monkeypatch, advertisement):
    store=net['room']; store.remote='origin'
    tip=store.current_tip()
    original=store._git
    def observe(*args, **kwargs):
        if args[0]=='ls-remote':
            return SimpleNamespace(returncode=0, stdout=advertisement.format(oid=tip,ref=store.ref),stderr='')
        return original(*args, **kwargs)
    monkeypatch.setattr(store,'_git',observe)
    result=store._reconcile_push(tip)
    assert result[0] is None and result[1] is False and isinstance(result[2],AgentRoomError)


def test_exact_tip_and_verified_descendant_remain_valid(net):
    store=net['room']; store.remote='origin'
    tip=store.current_tip()
    assert store._reconcile_push(tip)==(True,True,None)
    net['other'].post(thread_id='fresh',type='observation',body={'text':'descendant'})
    git(net['other_room'].workdir,'push','-q','origin','agent-room')
    assert store._reconcile_push(tip)==(True,True,None)
