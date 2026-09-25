"""C2: one remote-head-bound reservation, never a generic message rebase.

The signed room/checkpoint remains the authority. This role-local journal is
only recovery bookkeeping: exact signed intent before commit/push, then the
observed delivery. Unknown delivery never grants permission or mints a second
receipt. A recovered reservation requires manual reconciliation, not a second
permission to act. There is no executor, model, daemon or request-selected Git
operation here.
"""
import os
from pathlib import Path

from . import canonical, release
from .checkpoint import TrustCheckpoint
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .remote_sync import Anchor, RoomRemote, SyncError, OID_RE, run_git

MAX_RESERVATION_ATTEMPTS = 3


def _sync_directory(path):
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _Journal(Anchor):
    def save(self):
        super().save()
        _sync_directory(self.path)


class RemoteReservation:
    """Narrow, synchronous delivery. All callers share the room writer lock."""

    def __init__(self, store, *, checkpoint_path, state_path):
        if not store.remote or checkpoint_path is None or state_path is None:
            raise release.ReleaseError(
                'remote release requires an out-of-band checkpoint and durable release state')
        self.store = store
        self.checkpoint_path = Path(checkpoint_path)
        self.state_path = Path(state_path)
        self.remote = RoomRemote(store.workdir, store.remote, store.branch)
        self.candidate_branch = f'{store.branch}-release-candidate'

    def _observe(self):
        """Verify before installation, then confirm the exact authoritative ref."""
        checkpoint = TrustCheckpoint.load(self.checkpoint_path)
        head = self.remote.fetch_candidate(self.candidate_branch)
        probe = GitMessageStore(self.store.workdir, branch=self.candidate_branch,
                                trust=self.store.trust)
        report = checkpoint.verify_candidate(probe)
        if (report['candidate_tip'] != head or probe.current_tip() != head
                or self.remote.required_remote_tip() != head):
            raise SyncError('authoritative release head moved during verification')
        return head, probe, checkpoint

    def _install(self, head, checkpoint):
        self.store.assert_clean_checkout()
        self.remote.install(head)
        checkpoint.accept(self.store, candidate_tip=head)
        _sync_directory(self.checkpoint_path)

    def _journal(self, workdir):
        journal = _Journal(self.state_path, 'release-reservation-v1')
        identity = dict(room=self.store.room_id(), branch=self.store.branch,
                        remote=self.store.remote, checkout=str(self.store.workdir.resolve()),
                        target=str(Path(workdir).resolve()),
                        checkpoint=str(self.checkpoint_path.resolve()))
        if 'identity' not in journal.document:
            if set(journal.document) != {'kind', 'created_at'}:
                raise release.ReleaseError('malformed release journal')
            journal.set(identity=identity, pending=None)
        if journal.get('identity') != identity or 'pending' not in journal.document:
            raise release.ReleaseError('release journal identity/schema mismatch')
        pending = journal.get('pending')
        if pending is not None:
            if not isinstance(pending, dict) or set(pending) != {
                    'parent', 'envelope', 'authorisation', 'commit'}:
                raise release.ReleaseError('malformed pending reservation')
            if not isinstance(pending['parent'], str) or not OID_RE.fullmatch(pending['parent']):
                raise release.ReleaseError('invalid reservation parent')
            if pending['commit'] is not None and (not isinstance(pending['commit'], str)
                    or not OID_RE.fullmatch(pending['commit'])):
                raise release.ReleaseError('invalid reservation commit')
            envelope, authority = pending['envelope'], pending['authorisation']
            canonical.verify(envelope)
            if (not isinstance(authority, dict) or envelope.get('type') != 'execution_receipt'
                    or not isinstance(envelope.get('receipt'), dict)
                    or envelope['receipt'].get('status') != 'uncertain'
                    or envelope['receipt'].get('request_message_id') != authority.get('request_message_id')
                    or envelope['receipt'].get('decision_id') != authority.get('decision_id')
                    or envelope['receipt'].get('action_nonce') != authority.get('action_nonce')
                    or authority.get('action_permitted') is not False):
                raise release.ReleaseError('pending reservation binding mismatch')
        return journal

    def _exact_commit(self, store, pending):
        """Find exact original artifact AND parent; same ID/digest alone is insufficient."""
        envelope = pending['envelope']
        message = store.resolve_message(envelope['message_id'])
        if message is None:
            return None
        if message != envelope:
            raise release.ReleaseError('pending reservation artifact changed')
        path = store.message_path(message['thread_id'], message['message_id'])
        commit = store._history()[path]
        parents = store._git('rev-list', '--parents', '-n', '1', commit).stdout.split()
        if parents != [commit, pending['parent']]:
            raise release.ReleaseError('reservation was reparented, not published by exact CAS')
        if pending['commit'] is not None and pending['commit'] != commit:
            raise release.ReleaseError('reservation commit identity changed')
        changes = store._git_bytes('diff-tree', '--no-commit-id', '--name-only', '-r', '-z', commit)
        if changes != path.encode() + b'\0':
            raise release.ReleaseError('reservation commit contains additional changes')
        return commit

    @staticmethod
    def _unknown(pending, reason):
        return {'authorisation': {'action_permitted': False},
                'delivery': {'state': 'unknown', 'reason': str(reason),
                             'message_id': pending['envelope']['message_id'],
                             'commit': pending['commit'], 'parent': pending['parent']},
                'next_step': 'reconcile this exact pending reservation; do not act or repost'}

    def _finish(self, journal, pending, head, commit, checkpoint, *, recovered):
        self._install(head, checkpoint)
        receipt = pending['envelope']['receipt']
        # Durable consumption BEFORE returning permission. A crash after this
        # point cannot repeat permission: normal authorise sees the receipt.
        delivered = dict(state='delivered', head=head, commit=commit,
                         parent=pending['parent'], message_id=pending['envelope']['message_id'])
        journal.set(pending=None, last_delivery=delivered)
        authority = dict(pending['authorisation'], action_permitted=not recovered)
        authority['next_step'] = ('manual reconciliation required; do not execute again' if recovered
                                  else 'perform the action manually, then reconcile()')
        authority['note'] = ('The exact nonce is reserved as uncertain. Later rejection does not '
                             'prove that no side effect occurred. No executor ran here.')
        return {'authorisation': authority, 'delivery': delivered,
                'recovered': recovered,
                'receipt': dict(message_id=delivered['message_id'], commit=commit,
                                receipt_id=receipt['receipt_id'], receipt_status='uncertain',
                                pushed=True, pushed_known=True)}

    def _settle(self, journal, *, recovered):
        """Observe first. Never discard an intent on a push exit-code guess."""
        pending = journal.get('pending')
        try:
            head, probe, checkpoint = self._observe()
            commit = self._exact_commit(probe, pending)
            if commit is not None:
                return self._finish(journal, pending, head, commit, checkpoint, recovered=recovered)
            # Proven absent on one verified, remote-confirmed descendant.
            # Discard only our exact local provisional child, never arbitrary
            # local history. Keep intent until reset/install/checkpoint finish.
            local = self.store.current_tip()
            provisional = self._exact_commit(self.store, pending)
            if local not in (pending['parent'], head, provisional):
                raise release.ReleaseError('unexpected local history during release recovery')
            self.store.assert_clean_checkout()
            if provisional is not None and local == provisional:
                run_git(self.store.workdir, 'reset', '--hard', '--quiet', pending['parent'])
            self._install(head, checkpoint)
            journal.set(pending=None, last_delivery=dict(state='absent', head=head,
                        message_id=pending['envelope']['message_id'], commit=provisional))
            return None
        except (AgentRoomError, OSError, ValueError) as exc:
            return self._unknown(pending, exc)

    def reserve(self, request_id, *, workdir, signer, result=None):
        with self.store.writer_lock():
            self.store.assert_room_branch()
            self.store.assert_clean_checkout()
            journal = self._journal(workdir)
            if journal.get('pending') is not None:
                # Always reconcile the previous exact transaction first, even
                # if the operator changed the root-authored request ticket.
                settled = self._settle(journal, recovered=True)
                if settled is not None:
                    return settled
            for _attempt in range(MAX_RESERVATION_ATTEMPTS):
                head, _probe, checkpoint = self._observe()
                self._install(head, checkpoint)
                try:
                    authority = release.authorise(self.store, request_id, workdir=workdir)
                except release.ReleaseBlocked as exc:
                    exc.report['action_permitted'] = False
                    raise
                request = release._load_request(self.store, request_id)
                release.assert_transition(release.receipt_state(self.store, request), 'uncertain')
                envelope = release._receipt_envelope(self.store, request, status='uncertain',
                            decision_id=authority['decision_id'], signer=signer,
                            result=result if result is not None else {'stage': 'reserved'})
                if self.store.current_tip() != head:
                    raise release.ReleaseError('local head changed during authorization')
                pending = dict(parent=head, envelope=envelope, authorisation=authority, commit=None)
                # Intent is durable before local append, closing commit-before-
                # ledger crash ambiguity. No remote publication can precede it.
                journal.set(pending=pending)
                try:
                    self.store.append_receipt(envelope, publish=False)
                    pending['commit'] = self._exact_commit(self.store, pending)
                    journal.set(pending=pending)
                    self.remote.push_with_lease(head)
                except (AgentRoomError, OSError, ValueError) as exc:
                    # Includes a commit that landed but whose acknowledgement
                    # was lost. Reconciliation derives reality, not this flag.
                    settled = self._settle(journal, recovered=False)
                    if settled is not None:
                        return settled
                    continue
                settled = self._settle(journal, recovered=False)
                if settled is not None:
                    return settled
            raise release.ReleaseBlocked('bounded reservation attempts exhausted', report={
                'state': 'blocked_remote_movement', 'releasable': False,
                'action_permitted': False})

    def reconcile(self, request_id, *, workdir, signer, status, result, receipt_id=None):
        """A manual terminal report also settles any pending publication first."""
        with self.store.writer_lock():
            self.store.assert_room_branch()
            self.store.assert_clean_checkout()
            journal = self._journal(workdir)
            if journal.get('pending') is not None:
                settled = self._settle(journal, recovered=True)
                if settled is not None and settled['delivery']['state'] == 'unknown':
                    return settled
            head, _probe, checkpoint = self._observe()
            self._install(head, checkpoint)
            # This reports the operator's past side effect, never permits a
            # new one. Existing terminal-receipt/state-machine rules apply.
            return release._reconcile_local(self.store, request_id, status=status,
                       result=result, receipt_id=receipt_id, signer=signer)
