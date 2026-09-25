# C5 — checked SSH custody through quarantine; exact-ref recovery

Scope: only the two Medium findings against C4 commit
`6c8215712114e2ada5c691cbf2f3406753a2d6ce`. No deployment or activation.

## Reproduced before editing

1. C1's checked role Git config supplied `core.sshCommand`, but quarantine
   deliberately disabled global/system config. A disposable SSH observer
   demonstrated that ordinary remote observation used the pinned command and
   the actual quarantine fetch used a different PATH-selected `ssh` instead.
   Neither observer opened a network connection.
2. A disposable remote advertised both `refs/heads/aaa/refs/heads/agent-room`
   (the message tip) and `refs/heads/agent-room` (genesis). Git's suffix pattern
   returned the alias first. The generic library reported delivery even though
   the authoritative branch did not contain the message. The narrow transport
   already refused that ambiguous advertisement.

## One binding at every Git network boundary

`custody.network_git_binding` selects the fixed C1 role from the effective Unix
account, not request metadata, HOME, USER, a caller-selected role or Git config.
The existing full C1 custody guard runs immediately before each `fetch`, `push`
or `ls-remote`. A valid role receives the explicit command-line Git setting:

```
core.sshCommand=/usr/bin/ssh -F /etc/agent-room/ssh/<fixed-role>.conf
```

The root-owned SSH file must still exactly match C1's key/agent/host-key policy.
There is no new SSH configuration format or provisioning operation. The same
helper is consumed by the narrow transport, generic library (text and byte Git
paths), and actual quarantine fetch. Release and recovery fetches use those
same boundaries. Quarantine continues to disable arbitrary global/system config
and retains every C4 disk/memory/object/verification/promotion limit.

Inherited `GIT_*` overrides are removed. The explicit SSH setting wins over
repository/HOME configuration. Checked roles also receive a trusted
`GIT_ALLOW_PROTOCOL=ssh` **after** sanitization: alternate transports, URL
rewrites to helpers, and `protocol.<helper>.allow=always` cannot bypass the SSH
boundary. SSH variant and credential-helper behavior are explicit.

Unprovisioned library/development accounts have no validated role key: SSH and
custom helpers fail closed rather than falling back to an inherited identity.
Disposable local Git and existing non-SSH built-ins (file/git/http/https) remain
available there; they are not a production role/custody proof. Production
entrypoints continue to require the unchanged dedicated-role C1 guard.

## Exact authoritative ref, not a suffix

`GitMessageStore._reconcile_push` requires exactly one advertisement line, a
full lowercase object ID, and a tab-delimited ref byte-for-byte equal to the
configured authoritative `refs/heads/...`. Extra lines, alias-only results,
malformed fields, tags and namespace-confusable refs cannot prove delivery.

Ambiguity returns `pushed=None, pushed_known=False` with a controlled error;
it does not select a convenient line or start a fetch fallback. A genuine empty
advertisement still proves absence. An exact matching tip proves delivery. A
different exact tip still requires the existing bounded, verified exact-ref
fetch plus ancestry check. Generic non-authority message rebase semantics and
C2 authority-bearing reservation CAS are unchanged.

## Regression boundary

Permanent C5 tests cover all five role mappings; full C1 guard refusal on
changed/missing configuration or identity; inherited/repository/HOME overrides;
real Git rejection of alternate protocols/helpers; real Git SSH-adapter
observation and bounded quarantine transfer; suffix/tag/namespace/lookalike refs;
malformed advertisements; no ambiguity fallback; exact tip and verified
descendant success. The directory/file ref conflict that Git itself prohibits
is tested as a Git refusal, not represented as an impossible remote fixture.

The SSH adapter and simulated NSS/files are disposable test instrumentation,
not production credentials or cross-UID proof. Actual cross-UID denial, actual
repository-key scope, root-installed configuration and installed-unit/cgroup
enforcement remain **NOT TESTABLE UNTIL DEPLOYMENT**. The RuntimeMaxSec/oneshot
Low, passwordless-sudo activation blocker, optional arcengine absence and all
deployment/owner-authorization prerequisites remain unchanged. C5 implementation
regressions do not constitute independent S4 acceptance.
