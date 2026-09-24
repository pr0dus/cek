"""Shared fixtures for the Agent Room tests.

Every fixture builds a throwaway Git repository under pytest's tmp_path. No
test touches the real `agent-room` transport branch, any real remote, or the
existing chatgpt-ubuntu-bridge.
"""

import subprocess

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor


def git(repo, *args):
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, f"git {' '.join(args)}: {proc.stderr}"
    return proc.stdout


def configure_identity(repo):
    git(repo, "config", "user.name", "test")
    git(repo, "config", "user.email", "test@localhost")


@pytest.fixture
def store(tmp_path):
    """A local-only append-only store. No remote, so nothing can be pushed."""
    s = GitMessageStore.initialise(tmp_path / "room", branch="agent-room")
    configure_identity(s.workdir)
    return s


@pytest.fixture
def room(store, tmp_path):
    cursor = ParticipantCursor(tmp_path / "state", "claude-code")
    return AgentRoom(store, "claude-code", cursor)


@pytest.fixture
def bare_remote(tmp_path):
    """A bare repo standing in for the GitHub remote."""
    path = tmp_path / "remote.git"
    path.mkdir()
    git(path, "init", "-q", "--bare")
    return path


# -- Issue #5 helpers -------------------------------------------------------

#: Stand-in digests. Real ones come from `snapshot.snapshot_manifest` and
#: `supervisor.context_digest`; these keep binding tests independent of a
#: checkout.
SNAPSHOT_SHA = "a" * 64
CONTEXT_SHA = "b" * 64


#: Stand-in identities for a consequential binding. Real ones come from the
#: repository and thread under test; these keep binding tests independent of a
#: checkout while still exercising the mandatory shape.
BASE_COMMIT = "b" * 40
PROJECT = {"repo": "pr0dus/cek", "commit": "c" * 40}

#: Structured parameters for each action the schema knows. Prose scope is for
#: the human; these are what a later check compares.
ACTION_SAMPLES = {
    "activate-agent-room-transport": {
        "repo": "pr0dus/cek", "branch": "agent-room",
        "expect_branch_absent": True,
    },
    "merge-agent-room-infrastructure": {
        "repo": "pr0dus/cek", "base_branch": "main",
        "head_branch": "feat/agent-room-store",
        "expect_head_commit": "d" * 40,
    },
}


def measurement_recipe(*, thread_id="t1", target=None, cutoff=None,
                       base_commit=BASE_COMMIT) -> dict:
    """How the release path would derive current state for itself."""
    from agent_room.ids import uuid7

    return {
        "snapshot": {"kind": "git-worktree-manifest",
                     "snapshot_schema_version": 2,
                     "base_commit": base_commit},
        "context": {"kind": "agent-room-thread-context",
                    "thread_id": thread_id,
                    "target_message_id": target or uuid7(),
                    "cutoff_message_id": cutoff or uuid7()},
    }


def bound_action(
    action_id: str = "activate-agent-room-transport",
    *,
    snapshot: str = SNAPSHOT_SHA,
    context: str = CONTEXT_SHA,
    scope: str = "create the production agent-room transport branch",
    consequential: bool = True,
    project: dict | None = None,
    measurement: dict | None = None,
    nonce: str = "test-nonce-0001",
    parameters: dict | None = None,
    thread_id: str = "t1",
) -> dict:
    binding = {"snapshot_sha256": snapshot, "supervisor_context_sha256": context}
    if consequential:
        binding["project"] = dict(PROJECT) if project is None else project
        binding["measurement"] = (measurement if measurement is not None
                                  else measurement_recipe(thread_id=thread_id))
        binding["action_nonce"] = nonce
    elif project is not None:
        binding["project"] = project
    action = {
        "action_id": action_id,
        "scope": scope,
        "consequential": consequential,
        "binding": binding,
    }
    if consequential:
        action["parameters"] = (parameters if parameters is not None
                                else dict(ACTION_SAMPLES[action_id]))
    elif parameters is not None:
        action["parameters"] = parameters
    return action


def post_decision_request(room, thread_id: str = "t1", **kwargs) -> dict:
    """An agent asking a human to release a bound consequential action."""
    text = kwargs.pop("text", "This needs a human decision.")
    kwargs.setdefault("thread_id", thread_id)
    return room.post(
        thread_id=thread_id, type="decision_request", body={"text": text},
        human_approval_required=True, action=bound_action(**kwargs),
    )


# -- Issue #13 S2 helpers ---------------------------------------------------

#: Every identity the authenticated fixtures pin a disposable key for. The
#: human key here stands in for a credential that in production lives in a
#: phone's keystore and never exists on this host.
SIGNED_ROLES = ("claude-code", "codex", "openai-research", "release-recorder",
                "coordinator")


def build_trust(keydir, store, roles=SIGNED_ROLES):
    """A disposable trust policy plus signers for every pinned identity.

    The participants are added through real human-signed updates rather than
    written into the bootstrap document, so the fixtures exercise the same
    rotation path production would.
    """
    from agent_room import auth, trust as trust_module

    human = auth.generate_ed25519_keypair(keydir, "human-1")
    human_signer = auth.Ed25519Signer(human["private_key_path"],
                                      signer="human", key_id="human-1")
    policy = trust_module.TrustPolicy.bootstrap(
        room_id=store.room_id(), human_key_id="human-1",
        human_public_key=human["public_key"],
        human_custody=trust_module.CUSTODY_DEVICE,
    )
    signers = {"human": human_signer}
    for role in roles:
        key_id = f"{role}-1"
        pair = auth.generate_ed25519_keypair(keydir, key_id)
        # Every boundary is mandatory and must be a commit in this room's
        # history; at bootstrap the only one is the genesis.
        policy.apply_update(trust_module.build_update(
            policy, human_signer, action="add", participant=role,
            new_key_id=key_id, public_key=pair["public_key"],
            effective_commit=store.current_tip(),
        ), store=store)
        signers[role] = auth.Ed25519Signer(pair["private_key_path"],
                                           signer=role, key_id=key_id)
    return policy, signers


@pytest.fixture
def trust_material(tmp_path, store):
    """Disposable keys and a pinned policy for the throwaway room."""
    policy, signers = build_trust(tmp_path / "keys", store)
    return {"policy": policy, "signers": signers,
            "keydir": tmp_path / "keys",
            "policy_path": tmp_path / "trust.json"}


@pytest.fixture
def signed_store(store, trust_material):
    """The same throwaway store, with authentication turned on."""
    store.trust = trust_material["policy"]
    return store


@pytest.fixture
def signed_room(signed_store, trust_material, tmp_path):
    from agent_room import AgentRoom

    return AgentRoom(signed_store, "claude-code",
                     ParticipantCursor(tmp_path / "state", "claude-code"),
                     signer=trust_material["signers"]["claude-code"])
