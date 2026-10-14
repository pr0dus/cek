# Owner-authorized home access — Issue 17

This prospectively supersedes the S4 coding-worker home denial, not historical
validation evidence. Codex and Claude workers are trusted with all of pr0's
home, including credentials/configuration and indirect effects on privileged
workflows. pr0/root remain trusted administrators. This is NOT the old S4
home-isolation threat model and grants no human/release signer authority.

Both workers retain distinct non-root UIDs, empty capabilities, no-new-privileges,
root-owned installed code/configuration, read-only system paths and masked sibling
role roots. Dedicated model authentication is still used, never copied from pr0.

The fixed root-owned `agent-room-home-view@codex.service` and
`agent-room-home-view@claude.service` run separate bindfs views over exactly
`/home/pr0`, each with one fixed presented UID/GID and owner-only permissions.
One shared mirror view is not used: cross-UID inode permission caching failed
the actual namespace probe. Workers bind their role's view at the
original path inside their namespaces. Original ownership/modes are not rewritten.
Existing and future private files, including later chmod, are exposed by view
permissions; this is not an ACL inheritance claim. New files are owned by pr0.
No world-writable directory, recursive chown, CAP_DAC_OVERRIDE on agents or
per-project allowlist is used. Chown/chgrp through the view are denied; xattrs
are read-only. Symlinks are not dereferenced by the privileged mounter: targets
outside home retain their OS access policy. Immutable/readonly filesystems and
external symlink targets are not made writable. Submounts inside home are traversed
by the view subject to their actual filesystem availability. No ioctl forwarding.

The production invokers opt into the fixed `/home/pr0` working root. Codex's
workspace-write sandbox is insufficient for full home (.git/.codex exclusions),
so this explicit policy uses external systemd confinement and danger-full-access,
with user config ignored, ordinary exec rules retained and on-request approvals.
Claude uses safe-mode and manual permissions (unanswerable prompts denied),
with only fixed Upwork/WebFX/LYFE public WebFetch domains allowed, under
the same OS boundary; Claude enablement remains independent and disabled during
permission qualification. Default library invocations remain restricted.

Rollback: stop only idle coding workers, restore saved units/configuration and
installed source symlink, daemon-reload, then stop both home-view instances. No
recursive home-permission rollback is needed because original modes/owners are
unchanged. Do not discard task journals or replay uncertain work on rollback.

This document is a policy/implementation description, not a qualification receipt.
Real namespace/model probes and dispatch qualification must pass before claiming
Issue 17 complete.
