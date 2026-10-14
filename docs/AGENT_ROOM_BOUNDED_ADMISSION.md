# Bounded restoration admission

Production coding and control entry points require the root-owned
`/etc/agent-room/task-admission.json`, checked by existing custody guards.
Its exact fields are `version: 1`, `requests` and `tasks`; each map has at most
16 canonical UUIDv7 keys and SHA-256 values. Missing or malformed enrollment
fails closed. A request is bound to its exact raw bytes; a task is bound to
canonical JSON of its ID, fixed recipient and instruction. Requests cannot
supply this policy or select infrastructure. Library-only disposable tests
remain explicitly separate from production custody.

Unlisted historical control requests are held before parsing, not consumed.
Unlisted signed tasks and historical submission recovery are held without
journal/cursor changes or fake results. An admitted existing invocation intent
remains uncertain and cannot invoke again. Output recovery preserves the same
signed message. Fresh IDs do not authorize repeating ambiguous old work.

The one preexisting reconciliation annotation exception binds its exact path,
blob and original add-commit. It is inert: never parsed as a request, result,
approval or receipt. Namespace closure, linear append-only history, checkpoints
and remote rollback protections remain in force.

For maintenance, first establish all fixed workers/transport are idle and
reconcile state. Back up root-owned configuration and installed-source identity;
hold coding and fixed dispatch paths, install the reviewed tracked-source
candidate, enroll only intended exact-content work, and restart the existing
webhook so cached code uses the new gate. Restart performs a bounded queue pass,
so admission must already be installed. Preserve all journal/checkpoint/history
and dedicated identity/key/home custody. Do not operate shared research units.

Rollback while idle: hold coding/dispatch again, restore prior source/config,
retain the new admission evidence and every journal/output, and leave workers
held until backlog safety is reestablished. Never replay intent, reset state or
force-push. This maintenance mechanism grants no human/release signing authority;
existing off-host approval gates remain unchanged.
