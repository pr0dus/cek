# S4-C1 — host participant custody correction (implementation only)

Authority: Issue #13 comment 5818959858. Base `7e26d80a706fc321a436fc96009550e70ca15b4b`.
No S4 qualification, deployment, user creation, production credentials, sudo
policy change, merge, service activation or live Agent Room is authorized here.

## Before → intended production boundary

The S4-A High was an actual ordinary child process reading a sibling 0600
canary inside a 0700 directory owned by the same UID. Restricted client flags,
file names and umasks cannot prevent this. C1 does not make clients trustworthy;
it limits compromised clients to their own cryptographic identity.

| Role | Unix user and private group | Private root | Signing key below root |
|---|---|---|---|
| claude-code | agentroom-claude | /var/lib/agent-room-claude | keys/claude-code.ed25519.pem |
| codex | agentroom-codex | /var/lib/agent-room-codex | keys/codex.ed25519.pem |
| openai-research | agentroom | /var/lib/agent-room | keys/openai-research.ed25519.pem |
| coordinator | agentroom-coordinator | /var/lib/agent-room-coordinator | keys/coordinator.ed25519.pem |
| release-recorder | agentroom-release | /var/lib/agent-room-release | keys/release-recorder.ed25519.pem |
| human | off-host personal device | **none on host** | **none on host** |

All five users must resolve to distinct non-root UIDs, with distinct private
primary groups and no cross-role memberships (including supplementary groups).
`pr0` is not a role and cannot be in any private group. No account is created
by this code. Unknown/missing users fail closed; distinct names alone are not proof.

Each root is 0700 owned by its role. Each private key is 0600 or stricter,
regular, non-symlinked, single-link, with private intermediate directories.
Every root has its own `room/`, `workspace/`, `state/` (cursor/turn state),
`checkpoint.json`, `home/`, `keys/repository.ed25519` and public
`custody.canary`. No shared private-key directory. Room/workspaces are separate
clones, **not** shared linked worktrees or `/home/pr0/projects/...`.
Cross-role collaboration is via signed Git/room artifacts.

## Production launch and guard

Root installs the exact reviewed `deploy/custody/roles.json` as
`/etc/agent-room/roles.json`, without widening its schema/layout. It contains
paths and roles, never secrets. Root-owned non-writable ancestors and leaf
are checked, and symlinks are rejected. Public trust remains only in the
root-owned `/etc/agent-room/trust-policy.json`.

Production launches are:

- Claude/Codex: their system one-shot → `role_worker <literal-role>` → custody
  guard → root-only worker config → existing participant adapter → existing
  client invoker. The client remains the role UID, never `pr0` or a sibling.
- Coordinator: a separate UID and a root-authored one-shot `handoff` with fixed
  message ID. This retains the signed coordinator protocol role without giving
  it model invocation or impersonation via development `Coordinator.room_for`.
- Supervisor: existing `transport_worker` and fixed transport config; now guarded
  as `openai-research` before transport construction. It still has only the S3
  allowlisted requests. Paths must match its root exactly; no sibling key or
  release authority enters the transport. Its control clone stays under its root.
- Release: separate `release_worker`, described below.

`custody.guard()` checks real/effective/saved UIDs/GIDs, NSS role resolution,
unique IDs, groups, own root/key/credential/canary metadata/readability,
root-owned configuration, and actual `open(O_RDONLY)` denial for every
sibling root/key/repository key/canary. ENOENT, EIO and symlink errors are
**unknown**, not isolation success. No `--insecure` bypass exists.

The whole inherited environment is discarded by the one-shot workers before
Git/signing/model operations. HOME, CODEX_HOME, CLAUDE_CONFIG_DIR and XDG paths
are role-local. No SSH_AUTH_SOCK, inherited API token, pr0 credential helper,
or caller Git environment survives. Root installs the exact role `.gitconfig`
from `deploy/custody/git/` into that role's home, and exact SSH config into
`/etc/agent-room/ssh/`. These are checked byte-for-byte. SSH uses
`IdentityAgent none`, `IdentitiesOnly yes`, an explicit own-role repository key,
no forwarding/proxy and pinned root-owned known_hosts. Configure clones with
SSH remotes and no additional local credential helper/sshCommand/includes.
Actual credentials and client authentication are a later authorized deployment
task, not copied from pr0 here.

The reviewed code goes under root-owned `/opt/agent-room/current`; the reviewed
client launch files go under `/opt/agent-room/clients/bin/{claude,codex}`.
The entry files must be real root-owned files, not user-writable wrappers or
symlinks. Install the clients' complete dependencies root-owned as well.
Actual client compatibility and remote credential operation remain untested
until deployment. Client flags do not constitute the cross-role boundary.

## Manual release custody

`agent-room-release.service` has no timer, install target, socket, generic
command argument or model executable. The operator prepares exactly one
root-owned `/etc/agent-room/release-request.json`, then explicitly starts the
unit after authorization. Only `reserve` and `reconcile` are allowed. The target
workspace and signer are fixed by the release role; no remote payload selects
them. Reserve still verifies device-signed human approval, current measurements
and project identity, then writes a one-shot reservation **before** the manual
side effect. Nothing in this worker executes that side effect. Reconcile records
the operator's actual result. An uncertain reservation remains blocked per S2.

Participants cannot write the ticket or read the release key. Services hide
the system bus and systemd private socket. The reviewed polkit rule in
`deploy/custody/` denies service management to all role users, as additional
host-side defence. Its installation/effect must be checked later; no rule or
sudo policy is changed by this implementation. Do not authorize model roles to
start the release unit. There is no signer daemon or unattended reserve API.

## System templates and limits

Four new system one-shot templates plus the updated supervisor template use
the exact per-role User/Group/StateDirectory, UMask0077, NoNewPrivileges, no
capabilities/delegation, strict read-only system, protected home/proc, private
tmp/devices, cgroup kill, and explicit inaccessible sibling roots. Code/config
are read-only. Models may use their own workspace and nominal network access;
this is **not** a claim of general sandboxing from their own data/credentials.
No unit is installed. Offline verify/security scores are configuration analysis,
not executed containment or client-compatibility proofs.

## Development/library boundary

Direct `AgentRoom`, signers, `TransportWorker`, generic `agent-room claude-turn`
or `codex-turn` construction under a shared account remains development/manual
tooling, NOT qualified production custody. Tests may use disposable same-user
keys. The S3 cgroup test now explicitly invokes `tests.transport_library_fixture`
so it tests the unchanged transport mechanics without pretending to be a
guarded production launch. No service template references this fixture or
offers a bypass. All actual production entrypoints enforce the guard.

## Mandatory later verification — NOT TESTABLE UNTIL DEPLOYMENT

1. Provision reviewed distinct identities and root-owned code/config *only*
   under later explicit authority; create public canaries and separate role
   credentials then. Preserve human private material off-host.
2. Check actual cross-UID filesystem and group/ACL behaviour, installed client
   auth/workspaces, kernel service containment and remote credentials.
3. Run `python3 -m agent_room.custody_verify` from authorized root-owned code
   as the authorized operator. It is read-only: no install/chmod/chown/useradd,
   key creation or policy edits. It validates exact installed units and no
   drop-ins, checks each role's actual UID in a privilege-dropped child, reads
   only its public canary, and requires permission-denied for all sibling keys
   and roots. It checks pr0 groups and refuses success if `pr0` can run
   `sudo -n true`; Claude/Codex must also fail that probe. Unavailable/ambiguous
   checks are BLOCKED, not PASS. No test success is inferred from key modes alone.
4. Independently reproduce malicious Claude→Codex/coordinator/release/supervisor
   and reciprocal Codex denial. Independently verify role processes cannot
   initiate release/system service operations under effective host policy.
5. Resume S4 only under separate review authority. These probes are custody-only,
   not a complete S4 gate or activation permission.

The implementation test suite explicitly skips the actual cross-UID canary:
**NOT TESTABLE UNTIL DEPLOYMENT**. It never uses sudo/user creation to fake it.
Current `pr0 → NOPASSWD: ALL` is an unchanged, separate activation blocker.
Even perfect per-UID permissions do not survive arbitrary root/kernel access.
