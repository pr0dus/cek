"""Read-only *post-deployment* cross-UID verifier, never an installer.

Run from reviewed root-owned code as an authorized root operator AFTER separate
deployment approval. It forks, drops supplementary groups/GID/UID, and attempts
real opens as each principal. It neither creates users/keys nor changes policy.
Do not run using pr0's passwordless sudo to manufacture implementation evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

from . import custody

UNITS = {'claude-code': 'agent-room-claude.service', 'codex': 'agent-room-codex.service',
         'openai-research': 'agent-room-transport.service',
         'coordinator': 'agent-room-coordinator.service',
         'release-recorder': 'agent-room-release.service'}


def sudo_denied():
    try:
        result = subprocess.run(['/usr/bin/sudo', '-n', 'true'], capture_output=True,
                                text=True, timeout=8, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise custody.CustodyError('sudo authority probe unavailable') from exc
    if result.returncode == 0:
        raise custody.CustodyError('passwordless-root activation blocker remains')
    if result.returncode != 1 or not any(s in result.stderr for s in (
            'a password is required', 'not allowed', 'not in the sudoers')):
        raise custody.CustodyError('sudo denial not established')


def check_units():
    for role, unit in UNITS.items():
        path = custody.root_file(f'/etc/systemd/system/{unit}')
        template = custody.root_file(f'{custody.CODE}/deploy/{unit}')
        custody._require(path.read_bytes() == template.read_bytes(), f'unit drift: {unit}')
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                                 '--property=User,Group,DropInPaths,FragmentPath,LoadState'],
                                capture_output=True, text=True, timeout=8, check=True)
        props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        user, _ = custody.ACCOUNTS[role]
        custody._require(props == {'User': user, 'Group': user, 'DropInPaths': '',
                                   'FragmentPath': str(path), 'LoadState': 'loaded'},
                         f'effective unit identity/drop-ins differ: {unit}')
    rule = custody.root_file('/etc/polkit-1/rules.d/49-agent-room-deny-management.rules')
    expected = custody.root_file(f'{custody.CODE}/deploy/custody/49-agent-room-deny-management.rules')
    custody._require(rule.read_bytes() == expected.read_bytes(), 'service management policy drift')


def probe_role(role):
    item = custody.guard(role)
    # Only the PUBLIC canary is read. No key bytes appear in a report.
    with Path(item['canary']).open('rb') as stream:
        canary = stream.read(4097)
    custody._require(1 <= len(canary) <= 4096, 'public canary size invalid')
    sudo_denied()
    return {'role': role, 'uid': os.geteuid(), 'own_canary_sha256': hashlib.sha256(canary).hexdigest(),
            'sibling_keys_and_state': 'PERMISSION_DENIED', 'guard': 'accepted'}


def as_user(user, role):
    """Actual unprivileged child, not mocked modes or caller-declared UID."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            os.environ.clear()
            os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', HOME=user.pw_dir)
            if role is None:
                sudo_denied()
                result = {'role': 'pr0', 'passwordless_root': False}
            else:
                result = probe_role(role)
            payload = {'ok': True, 'result': result}
        except Exception as exc:
            payload = {'ok': False, 'error': f'{type(exc).__name__}: {exc}'}
        os.write(write_fd, json.dumps(payload).encode())
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, 'rb') as stream:
        payload = stream.read(16384)
    _, status = os.waitpid(pid, 0)
    custody._require(status == 0, 'identity probe crashed')
    result = json.loads(payload)
    custody._require(result['ok'], str(result.get('error')))
    return result['result']


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv) or os.geteuid() != 0:
        print('BLOCKED: post-deployment authorized root operator required; no implementation proof')
        return 2
    try:
        document = custody.load_manifest()
        resolved = custody.identities(document)
        check_units()
        # Prove objects exist and have correct owners BEFORE the per-role
        # negative opens; an absent sibling is not an isolation success.
        for role, (user, _, _) in resolved.items():
            item = document['roles'][role]
            custody.private_path(item['state_root'], user.pw_uid, directory=True)
            for name in ('signing_key', 'repository_key', 'canary'):
                custody.private_path(item[name], user.pw_uid)
        results = [as_user(pwd.getpwnam('pr0'), None)]
        results += [as_user(user, role) for role, (user, _, _) in resolved.items()]
    except Exception as exc:
        print(json.dumps({'result': 'BLOCKED', 'reason': f'{type(exc).__name__}: {exc}'}))
        return 1
    print(json.dumps({'result': 'CUSTODY_PROBES_PASS', 'roles': results,
                      'scope': 'host UID/key custody only, not S4 qualification or activation'}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
