# Issue 17 typed supervisor tasks

Read OWNER_HOME for the explicit owner-authorized trust-model change. Old S4
coding-worker home-denial instructions are historical, not current policy.
Human/release gates and sibling custody outside home are unchanged.

The existing authenticated control transport accepts `task_submit` with exactly:

```json
{"control_schema_version":1,"request_id":"<canonical UUIDv7>",
 "created_at":"<UTC timestamp>","operation":"task_submit",
 "params":{"task_id":"<canonical UUIDv7>","recipient":"codex",
           "instruction":"<bounded natural-language task>"}}
```

Recipient is codex or claude-code. No argv, executable, unit, model, auth, path,
environment or release-authority overrides exist. Instruction is model input,
not a shell command interpreted by transport. The existing private control
repository and verified monotonic transport history remain the admission path.
Only a signed openai-research question with the exact task format is eligible;
old traffic and imported replies do not trigger model work.

Deployment explicitly enrolls `state/tasks/tasks.json` separately in the
supervisor and each coding role's private state. Missing/corrupt journals refuse;
they are never initialized implicitly. Journals have a 256-task/8MiB bound and
require explicit administrative capacity maintenance, not automatic eviction.
Submission persists the exact signed envelope before publishing. Retrying the
same task ID/content reconciles the same artifact; changed content is refused.

Two fixed root-owned path/service pairs consume private wake hints and start
only their literal non-root coding unit. Wake files are not authority. No timer,
polling, GitHub Actions or arbitrary command dispatcher is introduced. Boot
reconciliation may start a finite worker scan; no eligible task means no model.
Claude remains disabled unless separately authorized in root configuration.

The role lock covers verified sync, task selection and intent persistence.
Intent is fsynced before the sole model call. If the process/client fails after
intent but before output is durable, the result is UNCERTAIN; restart never
invokes again. Administrative diagnosis is required, not a favorable retry.
Durable output is reconciled without another model call. A local unpublished
tail is recoverable only if every commit adds an exact journal-bound signed
reply; unknown local work remains blocked and is never reset. Checkpoint and
signature checks precede admission and follow delivery.

Models use the existing response schema and terminal format
`agent-room-terminal-v1/end_report` (or another existing terminal kind).
Signed terminal replies target openai-research. The existing PR1 commit doorbell
carries metadata only. A supervisor must verify the referenced signed artifact
and digest through export/notice verification before interpreting the report.
The doorbell cannot prove ChatGPT has actually awakened or acted on the event.

Recovery: preserve journals and room/checkpoint evidence. An uncertain task must
not be resubmitted under a new ID to obtain a second model attempt. Restarting
transport/worker is reconciliation, not permission to erase invocation intent.
Do not reset old signed messages, cursors, task IDs or checkpoints.
