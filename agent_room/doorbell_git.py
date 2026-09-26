"""PR head updates over the existing role SSH binding; metadata has no authority.

A dedicated private Git cache, never the room/source checkout. All operations
run under Doorbell's role-local lifecycle lock. No checkout, hooks, shell,
API credential, branch creation, force replacement or model invocation.
"""
import datetime as dt
from pathlib import Path
import re

from .doorbell import configuration, MAX_RECORDS
from .doorbell_protocol import DoorbellError, ROLES, decode, encode, require
from .errors import AgentRoomError
from .git_ingestion import command, fetch_verified, storage
from .protected_state import oid
from .transport_state import private_directory

ACCEPTED = 'refs/heads/doorbell-accepted'
CANDIDATE = 'refs/heads/doorbell-candidate'
WAKE_PATH = re.compile(r'wake-([0-9a-f]{64})\.json\Z')


class GitCommitPR:
    """post/find both reconcile immutable event bytes before one bounded CAS.

    SSH cannot query GitHub PR state/node identity. Root-owned enrollment pins
    the previously reviewed PR-to-head mapping; Work filters the exact PR.
    A confirmed Git receipt proves branch delivery, never Work consumption.
    """

    def __init__(self, config, role, state_dir):
        self.config = configuration(config)
        require(self.config.get('transport') == 'pr-commit' and role in ROLES,
                'commit doorbell configuration/role')
        self.role = role
        self.root = Path(state_dir)
        self.repo = self.root / 'git'
        self.url = 'git@github.com:' + self.config['repository'] + '.git'
        self.ref = 'refs/heads/' + self.config['branch']
        self.seed = self.config['bootstrap_tip']

    def enroll(self):
        """Explicit cache enrollment; never silently recreate lost continuity."""
        require(not self.repo.exists(), 'doorbell Git cache already exists')
        with private_directory(self.repo):
            command(self.repo, 'init', '-q', '--bare', '--template=')
            command(self.repo, 'remote', 'add', 'origin', self.url)
            tip = self._fetch(self.seed)
            command(self.repo, 'update-ref', ACCEPTED, tip)

    def _remote_tip(self):
        raw = command(self.repo, 'ls-remote', '--exit-code', 'origin', self.ref)
        rows = raw.decode('ascii').splitlines()
        parts = rows[0].split('\t') if len(rows) == 1 else []
        require(len(parts) == 2 and oid(parts[0]) and parts[1] == self.ref,
                'missing/ambiguous exact doorbell ref')
        return parts[0]

    def _verify(self, repo, tip, accepted):
        rows = command(repo, 'rev-list', '--first-parent', '--parents', tip).decode().splitlines()
        require(0 < len(rows) <= MAX_RECORDS + 128, 'doorbell history bound')
        chain = [row.split() for row in rows]
        identities = [row[0] for row in chain]
        require(self.seed in identities and accepted in identities, 'doorbell rollback/replacement')
        suffix = chain[:identities.index(self.seed)]
        require(len(suffix) <= MAX_RECORDS, 'doorbell event capacity')
        seed_paths = command(repo, 'ls-tree', '-r', '--name-only', self.seed).decode().splitlines()
        require(not any(WAKE_PATH.fullmatch(p) for p in seed_paths), 'bootstrap contains wakes')
        for row in reversed(suffix):
            require(len(row) == 2, 'doorbell history must be linear')
            change = command(repo, 'diff-tree', '--no-commit-id', '--name-status',
                             '--no-renames', '-r', row[1], row[0]).decode().splitlines()
            require(len(change) == 1 and change[0].startswith('A\twake-'),
                    'doorbell commits add exactly one immutable wake')
            path = change[0][2:]
            match = WAKE_PATH.fullmatch(path)
            require(match is not None, 'doorbell path')
            tree = command(repo, 'ls-tree', row[0], '--', path).decode().strip().split()
            require(len(tree) == 4 and tree[:2] == ['100644', 'blob'] and tree[3] == path,
                    'doorbell artifact mode')
            raw = command(repo, 'cat-file', 'blob', tree[2]).decode('utf-8')
            event = decode(raw)
            require(encode(event) == raw and event['event_id'] == match[1],
                    'noncanonical/misnamed wake')

    def _fetch(self, accepted):
        self._remote_tip()  # Ref must exist; no bootstrap through push.
        tip = fetch_verified(self.repo, 'origin', self.ref, CANDIDATE,
                             lambda repo, branch, tip: self._verify(repo, tip, accepted))
        require(self._remote_tip() == tip, 'doorbell ref moved during observation')
        return tip

    def _observe(self):
        with private_directory(self.repo):
            require(command(self.repo, 'rev-parse', '--is-bare-repository').strip() == b'true',
                    'doorbell cache must be bare')
            for args in [('remote', 'get-url', 'origin'), ('remote', 'get-url', '--push', 'origin')]:
                require(command(self.repo, *args).decode().strip() == self.url,
                        'doorbell repository changed')
            accepted = command(self.repo, 'rev-parse', '--verify', ACCEPTED).decode().strip()
            require(oid(accepted), 'missing doorbell continuity anchor')
            tip = self._fetch(accepted)
            command(self.repo, 'update-ref', ACCEPTED, tip, accepted)
            return tip

    def check_target(self):
        try:
            self._observe()
        except (AgentRoomError, OSError, ValueError, UnicodeError):
            raise DoorbellError('doorbell Git target unavailable or refused') from None

    def _receipt(self, tip, path, raw):
        entries = command(self.repo, 'ls-tree', tip, '--', path).decode().strip()
        if not entries:
            return None
        fields = entries.split()
        require(len(fields) == 4 and fields[:2] == ['100644', 'blob'], 'wake mode conflict')
        require(command(self.repo, 'cat-file', 'blob', fields[2]) == raw, 'immutable wake conflict')
        commit = command(self.repo, 'log', '-1', '--format=%H', tip, '--', path).decode().strip()
        require(oid(commit), 'wake receipt identity')
        return commit

    def _commit(self, parent, path, raw, event):
        storage(self.repo / 'objects')
        blob = command(self.repo, 'hash-object', '-w', '--stdin', input=raw).decode().strip()
        entries = command(self.repo, 'ls-tree', '-z', parent)
        tree = command(self.repo, 'mktree', '-z', input=entries +
                       f'100644 blob {blob}\t{path}\0'.encode()).decode().strip()
        # Stable bytes for retry on the same parent; no wall-time/nonce churn.
        seconds = int(dt.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp())
        who = f'Agent Room <doorbell@localhost> {seconds} +0000'
        commit = (f'tree {tree}\nparent {parent}\nauthor {who}\ncommitter {who}\n\n'
                  f'Agent Room wake {event["event_id"]}\n').encode()
        result = command(self.repo, 'hash-object', '-t', 'commit', '-w', '--stdin',
                         input=commit).decode().strip()
        storage(self.repo / 'objects')
        return result

    def _deliver(self, event):
        raw = encode(event).encode('utf-8')
        require(event['role'] == self.role, 'wrong wake role')
        path = 'wake-' + event['event_id'] + '.json'
        parent = self._observe()
        receipt = self._receipt(parent, path, raw)
        if receipt is not None:
            return receipt
        count = command(self.repo, 'rev-list', '--count', self.seed + '..' + parent).decode().strip()
        require(int(count) < MAX_RECORDS, 'doorbell branch capacity; explicit maintenance')
        commit = self._commit(parent, path, raw, event)
        try:
            # Direct child of observed H. Lease is never permission to rewrite H.
            command(self.repo, 'push', '--porcelain', f'--force-with-lease={self.ref}:{parent}',
                    'origin', f'{commit}:{self.ref}')
        except AgentRoomError:
            pass  # Acknowledgement is not proof either way. Reobserve exactly.
        return self._receipt(self._observe(), path, raw)

    def post(self, event):
        try:
            return self._deliver(event)
        except (AgentRoomError, OSError, ValueError, UnicodeError):
            raise DoorbellError('doorbell Git delivery unresolved; recover only') from None

    def find(self, event):
        # Unlike POST comments, an absent immutable path can safely be retried
        # under an exact lease. Concurrent emitters cannot add it twice.
        return self.post(event)
