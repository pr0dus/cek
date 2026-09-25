"""C2 actual remote reservation path. Real Git/signatures, disposable identities.

Fault hooks only change scheduling/acknowledgements, never authorization,
verification or Git state. These are implementation regressions, not S4.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, release
from agent_room.checkpoint import TrustCheckpoint, policy_digest
from agent_room.decision import HumanDecisionAuthority, evaluate_gate
from agent_room.errors import AgentRoomError, PushRaceError
from agent_room.release_delivery import RemoteReservation, MAX_RESERVATION_ATTEMPTS
from agent_room.remote_sync import RoomRemote, SyncError, run_git
from agent_room.snapshot import snapshot_manifest
from agent_room.supervisor import context_digest
from tests.conftest_agent_room import git, configure_identity, build_trust


@pytest.fixture
def case(tmp_path):
    author = GitMessageStore.initialise(tmp_path / 'author', branch='agent-room')
    configure_identity(author.workdir)
    policy, signers = build_trust(tmp_path / 'disposable-keys', author)
    author.trust = policy
    agent = AgentRoom(author, 'claude-code', ParticipantCursor(tmp_path / 'cursor', 'claude-code'),
                      signer=signers['claude-code'])
    target = tmp_path / 'target'
    target.mkdir()
    git(target, 'init', '-q', '-b', 'work')
    configure_identity(target)
    git(target, 'remote', 'add', 'origin', 'https://github.com/example/c2-fixture.git')
    (target / 'file.txt').write_text('public fixture\n')
    git(target, 'add', 'file.txt')
    git(target, 'commit', '-qm', 'base')
    base = git(target, 'rev-parse', 'HEAD').strip()
    manifest = snapshot_manifest(target, base)
    question = agent.post(thread_id='review', type='question', body={'text': 'review'},
                          recipient={'agent': 'openai-research'})
    context = context_digest(author.resolve_message(question['message_id']), author.thread_messages('review'))
    action = dict(action_id='activate-agent-room-transport', scope='disposable test', consequential=True,
                  parameters=dict(repo='example/c2-fixture', branch='agent-room', expect_branch_absent=True),
                  binding=dict(snapshot_sha256=manifest['manifest_sha256'], supervisor_context_sha256=context,
                               project=dict(repo='example/c2-fixture', commit=base), action_nonce='c2-public-nonce-0001',
                               measurement=dict(
                                   snapshot=dict(kind='git-worktree-manifest', snapshot_schema_version=manifest['snapshot_schema_version'], base_commit=base),
                                   context=dict(kind='agent-room-thread-context', thread_id='review',
                                                target_message_id=question['message_id'], cutoff_message_id=question['message_id']))))
    request = agent.post(thread_id='review', type='decision_request', parent_id=question['message_id'],
                         body={'text': 'request'}, action=action, human_approval_required=True)['message_id']
    HumanDecisionAuthority(author).record(request, 'approve', signer=signers['human'], decision_id='initial-approval')
    remote = tmp_path / 'remote.git'
    git(tmp_path, 'init', '--bare', '-q', str(remote))
    git(author.workdir, 'remote', 'add', 'origin', str(remote))
    git(author.workdir, 'push', '-q', 'origin', 'agent-room')
    clone = tmp_path / 'release'
    git(tmp_path, 'clone', '-q', '-b', 'agent-room', str(remote), str(clone))
    store = GitMessageStore(clone, branch='agent-room', remote='origin', trust=policy)
    checkpoint = tmp_path / 'checkpoint.json'
    TrustCheckpoint.bootstrap(store, expected_genesis=store.room_id(), expected_tip=store.current_tip(),
                              expected_trust_policy_sha256=policy_digest(policy), path=checkpoint)
    author.remote = 'origin'
    return SimpleNamespace(author=author, store=store, agent=agent, signers=signers, target=target,
                           request=request, remote=remote, checkpoint=checkpoint,
                           state=tmp_path / 'state' / 'release.json', manifest=manifest, context=context)


def reserve(c):
    return release.reserve(c.store, c.request, workdir=c.target, signer=c.signers['release-recorder'],
                           checkpoint_path=c.checkpoint, state_path=c.state)


def decision(c, verdict='reject', identity='withdrawn'):
    return HumanDecisionAuthority(c.author).record(c.request, verdict, signer=c.signers['human'], decision_id=identity)


def remote_messages(c):
    # Independent view from the actual bare ref, not the release checkout.
    observer = GitMessageStore(c.remote, branch='agent-room', trust=c.store.trust)
    return list(observer.iter_messages())


def reservations(c):
    return [m for m in remote_messages(c) if m['type'] == 'execution_receipt' and m['receipt']['status'] == 'uncertain']


def before_first_publish(monkeypatch, effect):
    original = RoomRemote.push_with_lease
    calls = []
    def push(self, expected):
        calls.append((expected, self.local_tip()))
        if len(calls) == 1:
            effect()
        return original(self, expected)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    return calls


def test_A_C_original_rejection_before_reserve_start(case):
    """Unweakened fac06 exploit: valid human rejection already on remote."""
    rejection = decision(case)
    assert case.store.current_tip() != rejection['commit']
    with pytest.raises(release.ReleaseBlocked) as caught:
        reserve(case)
    assert caught.value.report['state'] == 'blocked_rejected'
    assert caught.value.report['action_permitted'] is False
    assert reservations(case) == []
    assert case.store.current_tip() == rejection['commit']


def test_B_C_withdrawal_between_authorise_and_publish(case, monkeypatch):
    calls = before_first_publish(monkeypatch, lambda: decision(case))
    with pytest.raises(release.ReleaseBlocked) as caught:
        reserve(case)
    assert caught.value.report['state'] == 'blocked_rejected'
    assert len(calls) == 1
    assert reservations(case) == []
    assert git(case.store.workdir, 'rev-list', '--parents', '-n', '1', calls[0][1]).split() == [calls[0][1], calls[0][0]]


def test_D_unrelated_move_full_reauthorization_no_generic_rebase(case, monkeypatch):
    calls = before_first_publish(monkeypatch, lambda: case.agent.post(
        thread_id='unrelated', type='observation', body={'text': 'other thread'}))
    original_authorise = release.authorise
    evaluations = []
    def observe(*args, **kwargs):
        evaluations.append(args[0].current_tip())
        return original_authorise(*args, **kwargs)
    monkeypatch.setattr(release, 'authorise', observe)
    monkeypatch.setattr(case.store, '_push_locked', lambda: pytest.fail('generic push forbidden'))
    result = reserve(case)
    assert result['authorisation']['action_permitted'] is True
    assert len(calls) == len(evaluations) == 2
    assert evaluations == [head for head, _ in calls]
    assert len(reservations(case)) == 1
    assert calls[0][1] != result['receipt']['commit']
    assert git(case.store.workdir, 'rev-list', '--parents', '-n', '1', result['receipt']['commit']).split() == [result['receipt']['commit'], evaluations[-1]]


def test_G_new_effective_approval_bound_to_actual_parent(case, monkeypatch):
    calls = before_first_publish(monkeypatch, lambda: decision(case, 'approve', 'new-effective-approval'))
    result = reserve(case)
    assert len(calls) == 2
    assert result['authorisation']['decision_id'] == 'new-effective-approval'
    assert reservations(case)[0]['receipt']['decision_id'] == 'new-effective-approval'
    parent = GitMessageStore(case.store.workdir, branch=case.store.branch, trust=case.store.trust)
    assert parent.is_strict_ancestor(calls[-1][0], result['receipt']['commit'])


def test_E_actual_acceptance_lost_acknowledgement(case, monkeypatch):
    import agent_room.remote_sync as sync
    original = sync.run_git
    pushed = []
    def lose_ack(workdir, *args, **kwargs):
        result = original(workdir, *args, **kwargs)
        if args[0] == 'push':
            assert result.returncode == 0
            pushed.append(git(case.remote, 'rev-parse', 'refs/heads/agent-room').strip())
            raise SyncError('acknowledgement lost AFTER real successful push')
        return result
    monkeypatch.setattr(sync, 'run_git', lose_ack)
    result = reserve(case)
    assert result['authorisation']['action_permitted'] is True
    assert pushed == [result['receipt']['commit']]
    assert len(reservations(case)) == 1
    with pytest.raises(release.ReleaseBlocked): reserve(case)


@pytest.mark.parametrize('accepted', [True, False])
def test_F_unknown_delivery_survives_restart(case, monkeypatch, accepted):
    original_push = RoomRemote.push_with_lease
    original_observe = RemoteReservation._observe
    fail_observation = [False]
    def observe(self):
        if fail_observation[0]: raise SyncError('remote observation unavailable')
        return original_observe(self)
    def push(self, expected):
        if accepted: original_push(self, expected)
        fail_observation[0] = True
        raise SyncError('unknown push outcome')
    monkeypatch.setattr(RemoteReservation, '_observe', observe)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    first = reserve(case)
    assert first['delivery']['state'] == 'unknown'
    assert first['authorisation']['action_permitted'] is False
    pending_bytes = case.state.read_bytes()
    local_tip = case.store.current_tip()
    # New objects, loading durable state as a restarted process would.
    case.store = GitMessageStore(case.store.workdir, branch='agent-room', remote='origin', trust=case.store.trust)
    again = reserve(case)
    assert again['delivery']['state'] == 'unknown'
    assert case.store.current_tip() == local_tip
    assert case.state.read_bytes() == pending_bytes
    fail_observation[0] = False
    monkeypatch.setattr(RoomRemote, 'push_with_lease', original_push)
    if accepted:
        result = reserve(case)
        assert result['recovered'] is True
        assert result['authorisation']['action_permitted'] is False
        assert result['receipt']['commit'] == local_tip
        assert len(reservations(case)) == 1
    else:
        decision(case)
        with pytest.raises(release.ReleaseBlocked) as caught: reserve(case)
        assert caught.value.report['state'] == 'blocked_rejected'
        assert reservations(case) == []


def test_H_rejection_after_reservation_does_not_erase_uncertain(case):
    first = reserve(case)
    git(case.author.workdir, 'pull', '--ff-only', '-q', 'origin', 'agent-room')
    decision(case)
    with pytest.raises(release.ReleaseBlocked): reserve(case)
    state = release.receipt_state(case.store, case.store.resolve_message(case.request))
    assert state['consumed'] is True and state['unresolved'] is True
    assert len(reservations(case)) == 1
    assert first['authorisation']['action_permitted'] is True
    release.reconcile(case.store, case.request, status='failed', result={'observed': 'manual action not performed'},
                      signer=case.signers['release-recorder'], workdir=case.target,
                      checkpoint_path=case.checkpoint, state_path=case.state)
    assert not release.receipt_state(case.store, case.store.resolve_message(case.request))['unresolved']


@pytest.mark.parametrize('kind', ['rollback', 'replacement', 'missing', 'unreadable'])
def test_I_J_bad_authoritative_head(case, kind):
    original = case.store.current_tip()
    checkpoint = case.checkpoint.read_bytes()
    if kind == 'rollback':
        git(case.remote, 'update-ref', 'refs/heads/agent-room', case.store.room_id())
    elif kind == 'replacement':
        replacement = GitMessageStore.initialise(case.remote.parent / 'replacement', branch='agent-room')
        git(replacement.workdir, 'push', '-q', '--force', str(case.remote), 'agent-room')
    elif kind == 'missing': git(case.remote, 'update-ref', '-d', 'refs/heads/agent-room')
    else: git(case.store.workdir, 'remote', 'set-url', 'origin', str(case.remote.parent / 'not-a-remote'))
    with pytest.raises(AgentRoomError): reserve(case)
    assert case.store.current_tip() == original
    assert case.checkpoint.read_bytes() == checkpoint


def test_remote_library_cannot_fall_back_to_generic_release(case):
    with pytest.raises(release.ReleaseError, match='checkpoint'):
        release.reserve(case.store, case.request, workdir=case.target, signer=case.signers['release-recorder'])
    assert reservations(case) == []


def test_remote_movement_retry_is_bounded(case, monkeypatch):
    original = RoomRemote.push_with_lease
    calls = []
    def push(self, head):
        calls.append(head)
        case.agent.post(thread_id='unrelated', type='observation', body={'text': str(len(calls))})
        return original(self, head)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    with pytest.raises(release.ReleaseBlocked, match='bounded'): reserve(case)
    assert len(calls) == MAX_RESERVATION_ATTEMPTS
    assert reservations(case) == []


def test_raw_generic_rebase_cannot_reparent_reservation(case):
    authority = release.authorise(case.store, case.request, workdir=case.target)
    envelope = release._receipt_envelope(case.store, case.store.resolve_message(case.request), status='uncertain',
                  result={'stage': 'reserved'}, decision_id=authority['decision_id'], signer=case.signers['release-recorder'])
    with pytest.raises(AgentRoomError, match='exact-head CAS'): case.store.append_receipt(envelope)
    case.store.append_receipt(envelope, publish=False)
    original = case.store.current_tip()
    decision(case)
    with pytest.raises(PushRaceError, match='cannot use generic Git rebase'): case.store.push()
    assert case.store.current_tip() == original
    assert reservations(case) == []


@pytest.mark.parametrize('malformation', ['json', 'binding', 'parent'])
def test_corrupt_pending_state_fails_closed(case, monkeypatch, malformation):
    original_observe = RemoteReservation._observe
    invoked = [False]
    def push(*a):
        invoked[0] = True
        raise SyncError('injected ambiguity')
    def observe(self):
        if invoked[0]: raise SyncError('unavailable')
        return original_observe(self)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    monkeypatch.setattr(RemoteReservation, '_observe', observe)
    reserve(case)
    if malformation == 'json': case.state.write_text('{')
    else:
        doc = json.loads(case.state.read_text())
        if malformation == 'binding': doc['pending']['authorisation']['decision_id'] = 'fake'
        else: doc['pending']['parent'] = 'HEAD~1'
        case.state.write_text(json.dumps(doc))
    with pytest.raises(AgentRoomError): reserve(case)
    assert reservations(case) == []


def test_real_fresh_process_reconciles_exact_pending(case, monkeypatch):
    original = RoomRemote.push_with_lease
    original_observe = RemoteReservation._observe
    pushed = [False]
    def push(self, expected):
        original(self, expected)
        pushed[0] = True
        raise SyncError('real acceptance, lost acknowledgement')
    def observe(self):
        if pushed[0]: raise SyncError('observation unavailable after push')
        return original_observe(self)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    monkeypatch.setattr(RemoteReservation, '_observe', observe)
    before = reserve(case)
    assert before['delivery']['state'] == 'unknown'
    policy_file = case.target.parent / 'public-policy.json'
    case.store.trust.save(policy_file)
    signer = case.signers['release-recorder']
    values = [str(case.store.workdir), str(policy_file), case.request, str(case.target),
              str(signer.key_path), signer.key_id, str(case.checkpoint), str(case.state)]
    program = '''
import json, sys
from agent_room import GitMessageStore, release
from agent_room.auth import Ed25519Signer
from agent_room.trust import TrustPolicy
w,p,r,t,k,kid,c,s = json.loads(sys.argv[1])
store = GitMessageStore(w, branch="agent-room", remote="origin", trust=TrustPolicy.load(p))
signer = Ed25519Signer(k, signer="release-recorder", key_id=kid)
print(json.dumps(release.reserve(store,r,workdir=t,signer=signer,checkpoint_path=c,state_path=s)))
'''
    proc = subprocess.run([sys.executable, '-c', program, json.dumps(values)], capture_output=True,
                          text=True, timeout=60, env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])})
    assert proc.returncode == 0, proc.stderr
    after = json.loads(proc.stdout)
    assert after['authorisation']['action_permitted'] is False
    assert after['recovered'] is True
    assert after['receipt']['message_id'] == before['delivery']['message_id']
    assert len(reservations(case)) == 1


@pytest.mark.parametrize('boundary', ['intent', 'commit', 'accepted', 'consumed'])
def test_crash_boundaries_preserve_one_shot(case, monkeypatch, boundary):
    from agent_room.release_delivery import _Journal
    class Crash(BaseException): pass
    save = _Journal.save
    append = case.store.append_receipt
    push = RoomRemote.push_with_lease
    def crash_save(self):
        save(self)
        if boundary == 'intent' and self.get('pending') is not None: raise Crash()
        if boundary == 'consumed' and self.get('last_delivery', {}).get('state') == 'delivered': raise Crash()
    def crash_append(*a, **kw):
        append(*a, **kw)
        raise Crash()
    def crash_push(self, expected):
        push(self, expected)
        raise Crash()
    with monkeypatch.context() as patch:
        if boundary in ('intent', 'consumed'): patch.setattr(_Journal, 'save', crash_save)
        elif boundary == 'commit': patch.setattr(case.store, 'append_receipt', crash_append)
        else: patch.setattr(RoomRemote, 'push_with_lease', crash_push)
        with pytest.raises(Crash): reserve(case)
    case.store = GitMessageStore(case.store.workdir, branch='agent-room', remote='origin', trust=case.store.trust)
    if boundary == 'consumed':
        with pytest.raises(release.ReleaseBlocked): reserve(case)
    else:
        result = reserve(case)
        assert result['authorisation']['action_permitted'] is (boundary != 'accepted')
    assert len(reservations(case)) == 1


def test_pending_unknown_cannot_be_bypassed_by_reconcile_ticket(case, monkeypatch):
    original = RemoteReservation._observe
    uncertain = [False]
    def observe(self):
        if uncertain[0]: raise SyncError('no remote observation')
        return original(self)
    def push(*a):
        uncertain[0] = True
        raise SyncError('unknown push')
    monkeypatch.setattr(RoomRemote, 'push_with_lease', push)
    monkeypatch.setattr(RemoteReservation, '_observe', observe)
    reserve(case)
    before = case.state.read_bytes()
    result = release.reconcile(case.store, case.request, status='failed', result={},
                      signer=case.signers['release-recorder'], workdir=case.target,
                      checkpoint_path=case.checkpoint, state_path=case.state)
    assert result['delivery']['state'] == 'unknown'
    assert result['authorisation']['action_permitted'] is False
    assert before == case.state.read_bytes()
    assert reservations(case) == []


@pytest.mark.parametrize('kind', ['rollback', 'missing', 'unsigned'])
def test_I_J_remote_corruption_during_publication_retains_intent(case, monkeypatch, kind):
    def corrupt():
        if kind == 'rollback':
            git(case.remote, 'update-ref', 'refs/heads/agent-room', case.store.room_id())
        elif kind == 'missing':
            git(case.remote, 'update-ref', '-d', 'refs/heads/agent-room')
        else:
            # A raw Git writer adds untrusted namespace content; not installed.
            (case.author.workdir / 'unauthorized.txt').write_text('untrusted')
            git(case.author.workdir, 'add', 'unauthorized.txt')
            git(case.author.workdir, 'commit', '-qm', 'invalid remote history')
            git(case.author.workdir, 'push', '-q', 'origin', 'agent-room')
    calls = before_first_publish(monkeypatch, corrupt)
    result = reserve(case)
    assert result['authorisation']['action_permitted'] is False
    assert result['delivery']['state'] == 'unknown'
    assert len(calls) == 1
    assert case.store.current_tip() == calls[0][1]
    assert json.loads(case.state.read_text())['pending']['commit'] == calls[0][1]


def test_remote_same_thread_unreviewed_message_blocks_reauthorization(case, monkeypatch):
    before_first_publish(monkeypatch, lambda: case.agent.post(
        thread_id='review', type='observation', body={'text': 'unreviewed after cutoff'}))
    with pytest.raises(release.ReleaseBlocked) as caught: reserve(case)
    assert caught.value.report['state'] == 'blocked_unreviewed'
    assert reservations(case) == []


def test_changed_target_is_remeasured_after_remote_move(case, monkeypatch):
    def move_and_edit():
        case.agent.post(thread_id='unrelated', type='observation', body={'text': 'move'})
        (case.target / 'file.txt').write_text('different target\n')
    before_first_publish(monkeypatch, move_and_edit)
    with pytest.raises(release.ReleaseBlocked) as caught: reserve(case)
    assert caught.value.report['state'] == 'blocked_stale'
    assert reservations(case) == []


def test_two_release_clones_cannot_both_reserve(case, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    second = case.target.parent / 'second-release'
    git(case.target.parent, 'clone', '-q', '-b', 'agent-room', str(case.remote), str(second))
    other = GitMessageStore(second, branch='agent-room', remote='origin', trust=case.store.trust)
    checkpoint = case.target.parent / 'second-checkpoint.json'
    TrustCheckpoint.bootstrap(other, expected_genesis=other.room_id(), expected_tip=other.current_tip(),
                              expected_trust_policy_sha256=policy_digest(other.trust), path=checkpoint)
    barrier = threading.Barrier(2)
    original = RoomRemote.push_with_lease
    def concurrent_push(self, expected):
        barrier.wait(timeout=30)
        return original(self, expected)
    monkeypatch.setattr(RoomRemote, 'push_with_lease', concurrent_push)
    def attempt(store, cp, state):
        try:
            return release.reserve(store, case.request, workdir=case.target,
                signer=case.signers['release-recorder'], checkpoint_path=cp, state_path=state)
        except AgentRoomError as exc:
            return {'authorisation': {'action_permitted': False}, 'blocked': type(exc).__name__}
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(attempt, case.store, case.checkpoint, case.state)
        second = pool.submit(attempt, other, checkpoint, case.target.parent / 'second-state.json')
        results = [first.result(timeout=60), second.result(timeout=60)]
    assert sum(r['authorisation']['action_permitted'] for r in results) == 1
    assert len(reservations(case)) == 1
