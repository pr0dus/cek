"""S4-C1 production custody. No user switching, provisioning or secret creation.

The root-installed manifest is the only production configuration authority.
Direct library construction is useful for disposable tests, NOT a custody proof.
The guard intentionally cannot qualify a shared-UID deployment.
"""
import errno
import grp
import os
from pathlib import Path
import pwd
import stat

from . import canonical
from .errors import AgentRoomError

MANIFEST = Path('/etc/agent-room/roles.json')
TRUST_POLICY = '/etc/agent-room/trust-policy.json'
CODE = '/opt/agent-room/current'
# Semantic roles and account names are not request-selectable.
ACCOUNTS = {
    'claude-code': ('agentroom-claude', '/var/lib/agent-room-claude'),
    'codex': ('agentroom-codex', '/var/lib/agent-room-codex'),
    'openai-research': ('agentroom', '/var/lib/agent-room'),
    'coordinator': ('agentroom-coordinator', '/var/lib/agent-room-coordinator'),
    'release-recorder': ('agentroom-release', '/var/lib/agent-room-release'),
}
CLIENTS = {'claude-code': '/opt/agent-room/clients/bin/claude',
           'codex': '/opt/agent-room/clients/bin/codex'}


class CustodyError(AgentRoomError):
    """Production identity or filesystem custody could not be established."""


def _require(condition, reason):
    if not condition:
        raise CustodyError(reason)


def layout(role):
    """The only supported production layout; no free-form private paths."""
    user, root = ACCOUNTS[role]
    return dict(user=user, group=user, state_root=root,
                signing_key=f'{root}/keys/{role}.ed25519.pem',
                repository_key=f'{root}/keys/repository.ed25519',
                canary=f'{root}/custody.canary', home=f'{root}/home',
                workspace=f'{root}/workspace', room=f'{root}/room',
                state=f'{root}/state', checkpoint=f'{root}/checkpoint.json',
                client=CLIENTS.get(role))


def validate_manifest(document):
    _require(isinstance(document, dict) and set(document) == {
        'version', 'roles', 'human', 'trust_policy'}, 'invalid custody manifest fields')
    _require(type(document['version']) is int and document['version'] == 1,
             'invalid custody version')
    _require(document['human'] == {'location': 'off-host', 'private_key': None},
             'human private material must remain off-host')
    _require(document['trust_policy'] == TRUST_POLICY, 'wrong public policy path')
    roles = document['roles']
    _require(isinstance(roles, dict) and set(roles) == set(ACCOUNTS),
             'exactly five host roles required')
    for role in ACCOUNTS:
        _require(isinstance(roles[role], dict) and roles[role] == layout(role),
                 f'{role}: unsupported production custody layout')
    return document


def _metadata(path):
    try:
        return Path(path).lstat()
    except OSError as exc:
        raise CustodyError(f'cannot inspect required custody path: {path}') from exc


def root_file(path):
    """Reject symlinks and writable ancestors as well as a mutable leaf."""
    path = Path(path)
    _require(path.is_absolute(), 'root configuration must be absolute')
    for parent in reversed(path.parents):
        info = _metadata(parent)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                 and not info.st_mode & 0o022, f'untrusted config ancestor: {parent}')
    info = _metadata(path)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
             and not info.st_mode & 0o022 and info.st_nlink == 1,
             f'configuration must be a root-owned immutable regular file: {path}')
    return path


def root_json(path):
    path = root_file(path)
    try:
        _require(path.stat().st_size <= 1024 * 1024, 'configuration too large')
        return canonical.strict_loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CustodyError('cannot read root configuration') from exc


def load_manifest():
    return validate_manifest(root_json(MANIFEST))


def identities(document):
    """NSS and actual memberships, not just different configured names."""
    resolved = {}
    try:
        for role, item in document['roles'].items():
            user = pwd.getpwnam(item['user'])
            group = grp.getgrnam(item['group'])
            _require(user.pw_uid != 0 and user.pw_gid == group.gr_gid,
                     f'{role}: invalid primary UID/GID')
            resolved[role] = (user, group, set(os.getgrouplist(user.pw_name, user.pw_gid)))
    except (KeyError, OSError) as exc:
        raise CustodyError('all dedicated role accounts/groups must exist') from exc
    _require(len({v[0].pw_uid for v in resolved.values()}) == len(resolved),
             'role UIDs must be pairwise distinct')
    _require(len({v[1].gr_gid for v in resolved.values()}) == len(resolved),
             'role private GIDs must be pairwise distinct')
    for role, (_, _, groups) in resolved.items():
        for other, (_, group, _) in resolved.items():
            _require(role == other or group.gr_gid not in groups,
                     f'{role}: cross-role private group membership')
    try:
        owner = pwd.getpwnam('pr0')
        owner_groups = os.getgrouplist(owner.pw_name, owner.pw_gid)
    except (KeyError, OSError) as exc:
        raise CustodyError('cannot establish pr0 group isolation') from exc
    _require(owner.pw_uid not in {v[0].pw_uid for v in resolved.values()},
             'pr0 is not a role identity')
    _require(not set(owner_groups) & {v[1].gr_gid for v in resolved.values()},
             'pr0 must not belong to role private groups')
    return resolved


def private_path(path, uid, *, directory=False):
    info = _metadata(path)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    _require(kind(info.st_mode) and info.st_uid == uid
             and not info.st_mode & 0o7077,
             f'private path must be owned only by its role: {path}')
    if not directory:
        _require(info.st_nlink == 1 and not info.st_mode & 0o100,
                 f'private file must be non-executable and unlinked: {path}')
    # Walk to the declared root. No symlinked intermediate keys/home directory.
    root = next((Path(r) for _, r in ACCOUNTS.values()
                 if Path(path).is_relative_to(r)), None)
    _require(root is not None, 'private path outside role roots')
    for parent in Path(path).parents:
        if not parent.is_relative_to(root):
            break
        info = _metadata(parent)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                 and not info.st_mode & 0o7077, f'unsafe private ancestor: {parent}')


def require_denied(path, *, directory=False):
    """A real kernel denial; missing files/IO failures are not proof of custody."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return
        raise CustodyError(f'isolation unknown (not permission-denied): {path}') from exc
    else:
        os.close(fd)
        raise CustodyError(f'sibling private path unexpectedly readable: {path}')


def ssh_config(item):
    return ('Host *\n    IdentityAgent none\n    IdentitiesOnly yes\n'
            f'    IdentityFile {item["repository_key"]}\n'
            '    BatchMode yes\n    StrictHostKeyChecking yes\n'
            '    UserKnownHostsFile /etc/agent-room/known_hosts\n'
            '    ForwardAgent no\n    ProxyCommand none\n    ProxyJump none\n')


def git_config(role):
    return ('[credential]\n\thelper =\n[core]\n'
            f'\tsshCommand = /usr/bin/ssh -F /etc/agent-room/ssh/{role}.conf\n')


def network_git_binding(args):
    """Bind every actual Git network operation, including quarantine/recovery.

    Never copy a command from HOME, repo config, a request or GIT_SSH*. The
    kernel's current account selects the fixed role; the existing full guard
    rechecks its custody before an explicit, highest-precedence Git option is
    produced. Quarantine may keep global/system Git config disabled. Returned
    environment entries must be applied AFTER sanitising inherited variables.

    Unprovisioned development/library accounts may still use disposable local
    remotes (and their existing non-SSH transports), but cannot fall back to
    unchecked SSH. This is not a deployment or a cross-UID isolation proof.
    """
    if not args or args[0] not in ('fetch', 'push', 'ls-remote'):
        return (), {}
    try:
        account = pwd.getpwuid(os.geteuid()).pw_name
    except (KeyError, OSError) as exc:
        raise CustodyError('cannot establish Git transport account') from exc
    role = next((r for r, (name, _) in ACCOUNTS.items() if name == account), None)
    if role is None:
        return (('-c', 'protocol.ssh.allow=never', '-c', 'core.sshCommand=/bin/false'),
                {'GIT_ALLOW_PROTOCOL': 'file:git:http:https'})
    guard(role)
    # No alternate production transport/helper or implicit SSH selection. All
    # supported built-in non-SSH protocols are explicitly disabled as well as
    # the default for unknown helpers. Environment overrides are stripped by
    # each caller's existing sanitised_env boundary.
    options = ('-c', 'core.sshCommand=/usr/bin/ssh -F /etc/agent-room/ssh/'+role+'.conf',
            '-c', 'ssh.variant=ssh', '-c', 'credential.helper=',
            '-c', 'protocol.allow=never', '-c', 'protocol.ssh.allow=always',
            '-c', 'protocol.file.allow=never', '-c', 'protocol.git.allow=never',
            '-c', 'protocol.http.allow=never', '-c', 'protocol.https.allow=never',
            '-c', 'protocol.ext.allow=never')
    # Git's transport allowlist overrides even protocol.<arbitrary-helper>.allow
    # in a repo config or a URL rewrite. protocol.allow=never alone does not.
    return options, {'GIT_ALLOW_PROTOCOL': 'ssh'}


def guard(role):
    """Production entrypoints call this before any signer, Git or client use."""
    document = load_manifest()
    _require(role in ACCOUNTS, 'unknown production role')
    resolved = identities(document)
    user, group, _ = resolved[role]
    _require(os.getresuid() == (user.pw_uid,) * 3
             and os.getresgid() == (group.gr_gid,) * 3,
             'worker must already run as its dedicated role identity')
    _require(pwd.getpwuid(os.geteuid()).pw_name == user.pw_name,
             'effective UID does not resolve to the configured role')
    _require(not set(os.getgroups()) & {g.gr_gid for r, (_, g, _) in resolved.items()
                                      if r != role}, 'inherited sibling groups')
    item = document['roles'][role]
    for name in ('state_root', 'home', 'workspace', 'room', 'state'):
        private_path(item[name], user.pw_uid, directory=True)
    for name in ('signing_key', 'repository_key', 'canary'):
        private_path(item[name], user.pw_uid)
        _require(os.access(item[name], os.R_OK, effective_ids=True), 'own private file unreadable')
    for other, sibling in document['roles'].items():
        if other != role:
            require_denied(sibling['state_root'], directory=True)
            for name in ('signing_key', 'repository_key', 'canary'):
                require_denied(sibling[name])
    root_file(TRUST_POLICY)
    root_file('/etc/agent-room/known_hosts')
    ssh_path = root_file(f'/etc/agent-room/ssh/{role}.conf')
    _require(ssh_path.read_text() == ssh_config(item), 'SSH config is not role-scoped')
    # A root-owned .gitconfig under role-owned home cannot grant sibling access;
    # exact text + fresh HOME prevent inheriting pr0 helpers/agent at startup.
    config = Path(item['home']) / '.gitconfig'
    info = _metadata(config)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
             and not info.st_mode & 0o022 and info.st_nlink == 1,
             'role Git config must be root-installed')
    _require(config.read_text() == git_config(role), 'unexpected credential helper/Git config')
    return item


def install_environment(role, item):
    """Whole-environment replacement in the one-shot worker, never pr0's auth."""
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', HOME=item['home'],
                      USER=item['user'], LOGNAME=item['user'], LANG='C.UTF-8',
                      XDG_CONFIG_HOME=f'{item["home"]}/.config',
                      XDG_CACHE_HOME=f'{item["home"]}/.cache',
                      CODEX_HOME=f'{item["home"]}/.codex',
                      CLAUDE_CONFIG_DIR=f'{item["home"]}/.claude',
                      PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
                      GIT_TERMINAL_PROMPT='0')
    os.umask(0o077)


def check_transport(config, item):
    expected = dict(room_workdir=item['room'], control_workdir=f'{item["state_root"]}/control',
                    trust_policy_path=TRUST_POLICY, checkpoint_path=item['checkpoint'],
                    state_dir=item['state'], signing_key_path=item['signing_key'])
    for field, value in expected.items():
        _require(getattr(config, field) == value, f'transport escapes supervisor custody: {field}')
    private_path(config.control_workdir, os.geteuid(), directory=True)
