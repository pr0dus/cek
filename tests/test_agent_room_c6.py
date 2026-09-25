"""C6: bounded generic recovery, including the real 10 MB C5-V attack.

All remotes, signers and writers are disposable. Stream injection below tests
the real process runner, not a fabricated successful Git observation.
"""
import subprocess
import sys

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor
from agent_room import gitstore, remote_sync
from agent_room.errors import AgentRoomError, DeliveryError, GitTimeout
from tests.conftest_agent_room import git
from tests.test_agent_room_transport_remote_s3 import net


def test_large_advertisement_on_real_post_is_bounded_unknown_and_retryable(net, monkeypatch):
    store = net['room']
    store.remote = 'origin'
    base = store.current_tip()
    net['other'].post(thread_id='concurrent', type='observation', body={'text': 'other writer'})
    git(net['other_room'].workdir, 'push', '-q', 'origin', 'agent-room')
    packed = net['origin_room']/'packed-refs'
    heading = '# pack-refs with: peeled fully-peeled sorted\n'
    packed.write_text(heading + ''.join(
        f'{base} refs/heads/{i:06d}-' + 'z'*180 + '/refs/heads/agent-room\n'
        for i in range(40000)))
    assert packed.stat().st_size == 10480045
    original = gitstore.run_bounded
    observed = []
    def bounded(argv, **kwargs):
        result = original(argv, **kwargs)
        observed.append((argv, kwargs, result))
        return result
    monkeypatch.setattr(gitstore, 'run_bounded', bounded)
    def no_fetch():
        pytest.fail('output-limited recovery must not fall back to fetch or rebase')
    original_fetch = store._fetch_verified_remote
    monkeypatch.setattr(store, '_fetch_verified_remote', no_fetch)
    api = AgentRoom(store, 'claude-code', ParticipantCursor(net['tmp']/'state', 'claude-code'),
                    signer=net['signers']['claude-code'])
    with pytest.raises(DeliveryError) as caught:
        api.post(thread_id='local', type='observation', body={'text': 'normal participant post'})
    error = caught.value
    assert error.locally_committed is True and error.locally_committed_known
    assert error.commit == store.current_tip() and error.commit_known
    assert error.message_id and error.path
    assert error.pushed is None and not error.pushed_known
    assert 'output bound exceeded' in str(error.recovery_error)
    assert len(observed) == 1
    argv, kwargs, result = observed[0]
    assert argv[-3:] == ['ls-remote', 'origin', store.ref]
    assert kwargs['max_output_bytes'] == remote_sync.MAX_GIT_OUTPUT_BYTES == 8*1024*1024
    assert kwargs['timeout'] == gitstore.GIT_TIMEOUT_SECONDS == 60
    assert result.output_limited and result.limited_streams == ('stdout',)
    assert len(result.stdout) == 8*1024*1024
    assert len(result.stderr) <= 8*1024*1024
    assert result.teardown and not result.timed_out
    assert store.verify_store() == 2
    assert GitMessageStore(net['origin_room'], trust=store.trust).verify_store() == 2
    assert git(store.workdir, 'status', '--porcelain') == ''
    # Resolve the hostile advertisement only in the disposable remote, then
    # retry DELIVERY of the same immutable message, not the participant post.
    packed.write_text(heading)
    monkeypatch.setattr(store, '_fetch_verified_remote', original_fetch)
    assert store.push()['pushed'] is True
    assert store.verify_store() == 3
    remote = GitMessageStore(net['origin_room'], trust=store.trust)
    assert remote.verify_store() == 3
    assert sum(m['message_id'] == error.message_id for m in remote.iter_messages()) == 1


@pytest.mark.parametrize('delta', [-1, 0, 1])
def test_real_exact_ref_boundary_is_strict_and_never_parses_truncated_prefix(net, monkeypatch, delta):
    store = net['room']
    store.remote = 'origin'
    tip = store.current_tip()
    # The existing runner refuses at the cap, so limit+1 is needed to accept
    # this exact advertisement. A truncated prefix must never prove delivery.
    size = len(f'{tip}\t{store.ref}\n'.encode())
    monkeypatch.setattr(remote_sync, 'MAX_GIT_OUTPUT_BYTES', size + delta)
    result = store._reconcile_push(tip)
    if delta == 1:
        assert result == (True, True, None)
    else:
        assert result[:2] == (None, False)
        assert isinstance(result[2], AgentRoomError)
        assert 'output bound exceeded' in str(result[2])


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('size', [1023, 1024, 1025])
def test_both_streams_are_bounded_during_read(net, monkeypatch, stream, size):
    store = net['room']
    store.remote = 'origin'
    tip = store.current_tip()
    exact = f'{tip}\t{store.ref}\n'.encode()
    monkeypatch.setattr(remote_sync, 'MAX_GIT_OUTPUT_BYTES', 1024)
    original = gitstore.run_bounded
    seen = []
    def producer(argv, **kwargs):
        assert argv[-3:] == ['ls-remote', 'origin', store.ref]
        code = ('' if stream == 'stdout' else f'sys.stdout.buffer.write({exact!r});sys.stdout.flush();')
        code = 'import sys;' + code + f'sys.{stream}.buffer.write(b"x"*{size})'
        result = original([sys.executable, '-c', code], **kwargs)
        seen.append(result)
        return result
    monkeypatch.setattr(gitstore, 'run_bounded', producer)
    result = store._reconcile_push(tip)
    assert len(seen) == 1
    assert len(seen[0].stdout) <= 1024 and len(seen[0].stderr) <= 1024
    if size >= 1024:
        assert seen[0].output_limited
        assert seen[0].limited_streams == (stream,)
        assert result[:2] == (None, False)
        assert 'output bound exceeded' in str(result[2])
    elif stream == 'stderr':
        assert result == (True, True, None)
    else:
        assert not seen[0].output_limited
        assert result[:2] == (None, False)
        assert 'invalid exact-ref' in str(result[2])


def test_timeout_with_valid_prefix_stays_unknown(net, monkeypatch):
    store = net['room']
    store.remote = 'origin'
    tip = store.current_tip()
    monkeypatch.setattr(gitstore, 'GIT_TIMEOUT_SECONDS', 0.05)
    original = gitstore.run_bounded
    def producer(argv, **kwargs):
        code = 'import sys,time;sys.stdout.write('+repr(f'{tip}\t{store.ref}\n')+');sys.stdout.flush();time.sleep(10)'
        return original([sys.executable, '-c', code], **kwargs)
    monkeypatch.setattr(gitstore, 'run_bounded', producer)
    result = store._reconcile_push(tip)
    assert result[:2] == (None, False)
    assert isinstance(result[2], GitTimeout)


@pytest.mark.parametrize('failure', [OSError('start failure'), ValueError('bad argv')])
def test_runner_failure_stays_inside_error_contract(net, monkeypatch, failure):
    store = net['room']
    store.remote = 'origin'
    tip = store.current_tip()
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(gitstore, 'run_bounded', fail)
    result = store._reconcile_push(tip)
    assert result[:2] == (None, False)
    assert isinstance(result[2], AgentRoomError)


def test_recovery_cannot_fall_back_to_unbounded_capture(net, monkeypatch):
    store = net['room']
    store.remote = 'origin'
    tip = store.current_tip()
    original = subprocess.run
    def reject_capture(argv, **kwargs):
        assert 'ls-remote' not in argv, 'recovery returned to communicate/capture_output'
        return original(argv, **kwargs)
    monkeypatch.setattr(subprocess, 'run', reject_capture)
    assert store._reconcile_push(tip) == (True, True, None)
