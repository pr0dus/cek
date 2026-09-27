from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from agent_room import task_dispatch as dispatch
from agent_room.errors import AgentRoomError


def test_fixed_dispatch_no_request_argv(monkeypatch):
    calls=[]
    monkeypatch.setattr(dispatch.os,'geteuid',lambda:0)
    monkeypatch.setattr(dispatch,'consume',lambda *a:calls.append(a))
    monkeypatch.setattr(dispatch.subprocess,'run',lambda command,**kw:
                        calls.append((command,kw)) or SimpleNamespace(returncode=0))
    assert dispatch.run('codex')==0
    assert calls[-1][0]==['/usr/bin/systemctl','start','agent-room-codex.service']
    assert calls[-1][1]['timeout']==1250
    for role in ('root','release-recorder','codex; touch /tmp/x',[],None):
        with pytest.raises(AgentRoomError): dispatch.run(role)


def test_nonroot_dispatch_refused(monkeypatch):
    monkeypatch.setattr(dispatch.os,'geteuid',lambda:1000)
    with pytest.raises(AgentRoomError): dispatch.run('codex')


@pytest.mark.parametrize('attack',['symlink','hardlink','public','wrong-owner','directory'])
def test_wake_file_cannot_redirect_privileged_starter(tmp_path,monkeypatch,attack):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(dispatch.pwd,'getpwnam',lambda _:SimpleNamespace(pw_uid=os.getuid()))
    path=tmp_path/'hint'
    target=tmp_path/'untouched'
    target.write_text('keep'); target.chmod(0o600)
    if attack=='symlink': path.symlink_to(target)
    elif attack=='hardlink': os.link(target,path)
    elif attack=='directory': path.mkdir()
    else:
        path.write_text(''); path.chmod(0o644 if attack=='public' else 0o600)
    if attack=='wrong-owner':
        monkeypatch.setattr(dispatch.pwd,'getpwnam',lambda _:SimpleNamespace(pw_uid=os.getuid()+1))
    with pytest.raises(AgentRoomError): dispatch.consume(path,'fixture')
    assert target.read_text()=='keep'


def test_wake_consumption_is_hint_only_and_repeated_missing_is_safe(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(dispatch.pwd,'getpwnam',lambda _:SimpleNamespace(pw_uid=os.getuid()))
    path=tmp_path/'hint'; path.write_text('not a command'); path.chmod(0o600)
    dispatch.consume(path,'fixture')
    assert not path.exists()
    dispatch.consume(path,'fixture')


def test_no_timers_and_one_role_per_home_view():
    root=Path(__file__).resolve().parents[1]/'deploy'
    for name in ('codex','claude'):
        unit=(root/f'agent-room-{name}.service').read_text()
        assert f'BindPaths=/run/agent-room-home-{name}:/home/pr0' in unit
        assert 'ProtectHome=tmpfs' in unit
        assert f'Requires=agent-room-home-view@{name}.service' in unit
        path=(root/f'agent-room-dispatch-{name}.path').read_text()
        assert 'PathExists=' in path and 'OnCalendar' not in path
