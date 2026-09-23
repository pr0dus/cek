"""Small CLI over the library. No daemon, no poller, no scheduling.

Every command is one shot: it runs, prints JSON, and exits. Anything that
would keep running belongs to Issues #3/#4, not here.
"""

import argparse
import json
import sys
from pathlib import Path

from . import canonical
from .cursor import ParticipantCursor
from .errors import AgentRoomError, DeliveryError
from .gitstore import DEFAULT_BRANCH, GitMessageStore
from .room import AgentRoom


#: Distinguishes "committed locally, not delivered" from an ordinary failure.
EXIT_PARTIAL_DELIVERY = 3


def _room(args) -> AgentRoom:
    store = GitMessageStore(args.repo, branch=args.branch, remote=args.remote)
    cursor = ParticipantCursor(args.state_dir, args.participant) if args.state_dir else None
    return AgentRoom(store, args.participant, cursor)


def _emit(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")


def _json_arg(value: str | None, default):
    """Parse a CLI JSON argument, rejecting duplicate keys like stored JSON.

    The default applies only when the option was *not given*. An explicit
    empty string is input, and invalid input at that - silently turning
    `--recipient ''` into a broadcast would be exactly the coercion the
    library boundary refuses.
    """
    if value is None:
        return default
    return canonical.strict_loads(value)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-room", description=__doc__.splitlines()[0])
    p.add_argument("--repo", required=True, help="git repo dedicated to the room branch")
    p.add_argument("--branch", default=DEFAULT_BRANCH)
    p.add_argument("--remote", default=None, help="optional push remote")
    p.add_argument("--participant", required=True, help="this participant's agent name")
    p.add_argument("--state-dir", default=None, help="participant-local cursor directory")
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the orphan room branch in --repo")

    post = sub.add_parser("post", help="post a message")
    post.add_argument("--thread-id", required=True)
    post.add_argument("--type", required=True)
    post.add_argument("--body", required=True, help="JSON object")
    post.add_argument("--recipient", default=None, help="JSON object")
    post.add_argument("--project", default=None, help="JSON object")
    post.add_argument("--evidence", default=None, help="JSON list")
    post.add_argument("--claim", default=None, help="JSON object")
    post.add_argument("--action", default=None,
                      help="JSON object: the bound consequential action a "
                           "decision_request asks a human to release")
    post.add_argument("--status", default="open")
    post.add_argument("--reply-requested", action="store_true")
    post.add_argument("--human-approval-required", action="store_true")

    reply = sub.add_parser("reply", help="reply to a message")
    reply.add_argument("--parent-id", required=True)
    reply.add_argument("--type", required=True)
    reply.add_argument("--body", required=True, help="JSON object")
    reply.add_argument("--recipient", default=None)
    reply.add_argument("--project", default=None)
    reply.add_argument("--evidence", default=None)
    reply.add_argument("--claim", default=None)
    reply.add_argument("--action", default=None,
                       help="JSON object: the bound consequential action a "
                            "decision_request asks a human to release")
    reply.add_argument("--status", default="open")
    reply.add_argument("--reply-requested", action="store_true")
    reply.add_argument("--human-approval-required", action="store_true")

    get = sub.add_parser("get", help="get one message")
    get.add_argument("--thread-id", required=True)
    get.add_argument("--message-id", required=True)

    thread = sub.add_parser("thread", help="get a complete thread")
    thread.add_argument("--thread-id", required=True)
    thread.add_argument("--tree", action="store_true", help="show parent/child structure")

    inbox = sub.add_parser("inbox", help="list unread messages for --participant")
    inbox.add_argument("--all", action="store_true", help="include acknowledged")

    ack = sub.add_parser("ack", help="acknowledge a message (not agreement)")
    ack.add_argument("--message-id", required=True)

    q = sub.add_parser("query", help="query the log")
    q.add_argument("--participant-name", default=None)
    q.add_argument("--project-repo", default=None)
    q.add_argument("--thread-id", default=None)

    sub.add_parser("threads", help="list thread ids in commit order")
    turn = sub.add_parser(
        "claude-turn",
        help="run ONE bounded Claude Code turn against an unread message "
             "(one shot; no daemon, no loop)",
    )
    turn.add_argument("--message-id", default=None,
                      help="target message; default is the oldest unread")
    turn.add_argument("--dry-run", action="store_true",
                      help="select and build the prompt without invoking Claude")
    turn.add_argument("--claude-bin", default=None, help="claude executable")
    turn.add_argument("--model", default=None)
    turn.add_argument("--project-dir", default=None,
                      help="working directory for the Claude turn")
    turn.add_argument("--timeout", type=int, default=None)
    turn.add_argument("--turn-timeout", type=float, default=None,
                      help="bounded wait for another in-flight turn (seconds)")
    turn.add_argument("--tool-profile", default=None,
                      help="named tool profile (default: none). Only qualified "
                           "profiles are accepted; raw client flags are not.")

    codex = sub.add_parser(
        "codex-turn",
        help="run ONE bounded Codex turn against an unread message "
             "(one shot; no daemon, no loop)",
    )
    codex.add_argument("--message-id", default=None)
    codex.add_argument("--dry-run", action="store_true")
    codex.add_argument("--codex-bin", default=None)
    codex.add_argument("--model", default=None)
    codex.add_argument("--project-dir", default=None)
    codex.add_argument("--timeout", type=int, default=None)
    codex.add_argument("--turn-timeout", type=float, default=None)
    codex.add_argument("--tool-profile", default=None,
                       help="named tool profile (default: none). Only qualified "
                            "profiles are accepted; raw client flags are not.")
    codex.add_argument("--sandbox", default=None,
                       choices=["read-only", "workspace-write"],
                       help="Codex sandbox policy (default read-only). "
                            "danger-full-access is deliberately not offered.")

    export = sub.add_parser(
        "supervisor-export",
        help="emit the canonical supervisor packet for one message addressed "
             "to openai-research (read-only, deterministic)",
    )
    export.add_argument("--message-id", default=None)
    export.add_argument("--out", default=None, help="write the packet to a file")

    imp = sub.add_parser(
        "supervisor-import",
        help="post ONE structured supervisor response, bound to the context "
             "hash it reviewed (one shot; no daemon, no loop)",
    )
    imp.add_argument("--response", required=True,
                     help="path to the supervisor response JSON, or - for stdin")
    imp.add_argument("--message-id", default=None)
    imp.add_argument("--turn-timeout", type=float, default=None)

    snap = sub.add_parser(
        "snapshot",
        help="deterministic manifest of the inspected state of a checkout "
             "against a base commit (read-only; trusts no builder file list)",
    )
    snap.add_argument("--target", required=True,
                      help="checkout to measure (NOT the room repo)")
    snap.add_argument("--base-commit", required=True,
                      help="full object id of the authorized baseline")
    snap.add_argument("--out", default=None, help="write the manifest to a file")

    gate = sub.add_parser(
        "gate-status",
        help="whether a bound consequential action is releasable right now "
             "(read-only; fail-closed)",
    )
    gate.add_argument("--request-id", required=True,
                      help="the decision_request message id")
    gate.add_argument("--snapshot-sha256", default=None,
                      help="inspected-state manifest digest observed NOW")
    gate.add_argument("--context-sha256", default=None,
                      help="supervisor packet context digest observed NOW")

    pend = sub.add_parser(
        "pending-decisions",
        help="bound decision requests with no human decision recorded",
    )
    pend.add_argument("--thread-id", default=None)

    decide = sub.add_parser(
        "human-decide",
        help="HUMAN ONLY: record one approval or rejection. This is the "
             "separate authority surface; no participant or orchestrator "
             "code may invoke it.",
    )
    decide.add_argument("--request-id", required=True)
    # Not `required`: `--show` must be usable on its own, so a person can read
    # what would be decided before naming a verdict at all.
    decide.add_argument("--decision", default=None, choices=["approve", "reject"])
    decide.add_argument("--decision-id", default=None)
    decide.add_argument("--note", default=None)
    decide.add_argument("--expect-action-id", default=None,
                        help="refuse unless the request binds this action")
    decide.add_argument("--expect-snapshot-sha256", default=None,
                        help="refuse unless the request binds this snapshot")
    decide.add_argument("--expect-context-sha256", default=None,
                        help="refuse unless the request binds this context")
    decide.add_argument("--show", action="store_true",
                        help="print what would be decided and exit without "
                             "recording anything")
    decide.add_argument(
        "--confirm-human", action="store_true",
        help="required. Asserts a person is invoking this, which is exactly "
             "what the capability boundary rests on.",
    )

    proof = sub.add_parser(
        "proof",
        help="run ONE agreed proof command and record what was observed "
             "(exit status, output digests, immutable artifact)",
    )
    proof.add_argument("--proof-id", required=True)
    proof.add_argument("--target", required=True, help="cwd for the command")
    proof.add_argument("--run-dir", required=True,
                       help="artifact directory, OUTSIDE the inspected checkout")
    proof.add_argument("--repo-commit", default=None)
    proof.add_argument("--snapshot-sha256", default=None)
    proof.add_argument("--timeout", type=float, default=None)
    # NB: dest is deliberately not "command" - the subparser already owns
    # that name, and shadowing it would erase which subcommand ran.
    proof.add_argument("command_argv", nargs="+", metavar="COMMAND",
                       help="the command to run, after --")

    sub.add_parser(
        "push",
        help="retry delivery of already-committed messages to --remote "
             "(one shot, bounded retry; not a daemon)",
    )
    verify = sub.add_parser(
        "verify",
        help="full-store integrity check (history, identity, schema, digests, "
             "references, causality)",
    )
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            store = GitMessageStore.initialise(args.repo, branch=args.branch)
            _emit({"initialised": str(store.workdir), "branch": store.branch})
            return 0

        # Surfaces that deliberately do NOT build an agent room: a room posts
        # as a participant, and none of these five acts as one. `human-decide`
        # in particular must never be reachable through a participant object.
        if args.command == "snapshot":
            from .snapshot import snapshot_manifest
            manifest = snapshot_manifest(args.target, args.base_commit)
            if args.out:
                Path(args.out).write_text(
                    canonical.canonical_text(manifest), encoding="utf-8")
                _emit({"written": args.out,
                       "manifest_sha256": manifest["manifest_sha256"]})
            else:
                _emit(manifest)
            return 0
        if args.command == "proof":
            from .proof import run_proof
            record = run_proof(
                args.command_argv, cwd=args.target, run_dir=args.run_dir,
                proof_id=args.proof_id, repo_commit=args.repo_commit,
                snapshot_sha256=args.snapshot_sha256,
                **({"timeout": args.timeout} if args.timeout else {}),
            )
            _emit(record)
            return 0
        if args.command in ("gate-status", "pending-decisions", "human-decide"):
            from . import decision as decision_mod
            store = GitMessageStore(args.repo, branch=args.branch,
                                    remote=args.remote)
            if args.command == "gate-status":
                _emit(decision_mod.evaluate_gate(
                    store, args.request_id,
                    snapshot_sha256=args.snapshot_sha256,
                    supervisor_context_sha256=args.context_sha256,
                ))
                return 0
            if args.command == "pending-decisions":
                _emit(decision_mod.pending_requests(store, args.thread_id))
                return 0
            authority = decision_mod.HumanDecisionAuthority(store)
            if args.show:
                _emit(authority.describe(args.request_id))
                return 0
            if args.decision is None:
                print("human-decide needs --decision approve|reject, or --show "
                      "to read what would be decided.", file=sys.stderr)
                return 2
            if not args.confirm_human:
                print(
                    "Refusing to record a decision without --confirm-human. "
                    "This surface carries human authority and is never invoked "
                    "automatically; run with --show first to see exactly what "
                    "would be decided.",
                    file=sys.stderr,
                )
                return 2
            _emit(authority.record(
                args.request_id, args.decision,
                decision_id=args.decision_id, note=args.note,
                expect_action_id=args.expect_action_id,
                expect_snapshot_sha256=args.expect_snapshot_sha256,
                expect_supervisor_context_sha256=args.expect_context_sha256,
            ))
            return 0

        room = _room(args)

        if args.command == "post":
            _emit(room.post(
                thread_id=args.thread_id, type=args.type,
                body=_json_arg(args.body, {}),
                recipient=_json_arg(args.recipient, None),
                project=_json_arg(args.project, None),
                evidence=_json_arg(args.evidence, None),
                claim=_json_arg(args.claim, None),
                action=_json_arg(args.action, None),
                status=args.status,
                reply_requested=args.reply_requested,
                human_approval_required=args.human_approval_required,
            ))
        elif args.command == "reply":
            _emit(room.reply(
                args.parent_id, type=args.type,
                body=_json_arg(args.body, {}),
                recipient=_json_arg(args.recipient, None),
                project=_json_arg(args.project, None),
                evidence=_json_arg(args.evidence, None),
                claim=_json_arg(args.claim, None),
                action=_json_arg(args.action, None),
                status=args.status,
                reply_requested=args.reply_requested,
                human_approval_required=args.human_approval_required,
            ))
        elif args.command == "get":
            _emit(room.get(args.thread_id, args.message_id))
        elif args.command == "thread":
            _emit(room.thread_tree(args.thread_id) if args.tree else room.thread(args.thread_id))
        elif args.command == "inbox":
            _emit(room.inbox(unread_only=not args.all))
        elif args.command == "ack":
            _emit(room.acknowledge(args.message_id))
        elif args.command == "threads":
            _emit(room.store.thread_ids())
        elif args.command == "push":
            _emit(room.store.push())
        elif args.command == "supervisor-export":
            from .supervisor import SupervisorBoundary
            packet = SupervisorBoundary(room).export(args.message_id)
            if args.out:
                from . import canonical as _c
                Path(args.out).write_text(_c.canonical_text(packet), encoding="utf-8")
                _emit({"written": args.out,
                       "context_sha256": packet["context_sha256"],
                       "target_message_id": packet["target_message_id"]})
            else:
                _emit(packet)
        elif args.command == "supervisor-import":
            from .supervisor import SupervisorBoundary
            raw = (sys.stdin.read() if args.response == "-"
                   else Path(args.response).read_text(encoding="utf-8"))
            boundary = SupervisorBoundary(
                room,
                turn_timeout=args.turn_timeout if args.turn_timeout is not None else None,
            )
            _emit(boundary.import_response(raw, message_id=args.message_id))
        elif args.command == "codex-turn":
            from . import tool_profiles
            from .codex_participant import (
                DEFAULT_CODEX_BIN, DEFAULT_SANDBOX, DEFAULT_TIMEOUT_SECONDS,
                DEFAULT_TURN_LOCK_TIMEOUT_SECONDS as CODEX_TURN_TIMEOUT,
                CodexInvoker, CodexParticipant,
            )
            invoker = CodexInvoker(
                args.codex_bin or DEFAULT_CODEX_BIN,
                cwd=args.project_dir,
                model=args.model,
                timeout=args.timeout or DEFAULT_TIMEOUT_SECONDS,
                sandbox=args.sandbox or DEFAULT_SANDBOX,
                tool_profile=args.tool_profile or tool_profiles.NONE,
            )
            participant = CodexParticipant(
                room, invoker,
                turn_timeout=args.turn_timeout
                if args.turn_timeout is not None else CODEX_TURN_TIMEOUT,
            )
            _emit(participant.run_turn(args.message_id, dry_run=args.dry_run))
        elif args.command == "claude-turn":
            from .claude_participant import (
                DEFAULT_CLAUDE_BIN, DEFAULT_TIMEOUT_SECONDS,
                ClaudeInvoker, ClaudeParticipant,
            )
            # `restricted` is not exposed: the adapter must not offer a way to
            # silently widen the installed client's permission system.
            from . import tool_profiles
            invoker = ClaudeInvoker(
                args.claude_bin or DEFAULT_CLAUDE_BIN,
                cwd=args.project_dir,
                model=args.model,
                timeout=args.timeout or DEFAULT_TIMEOUT_SECONDS,
                tool_profile=args.tool_profile or tool_profiles.NONE,
            )
            from .claude_participant import DEFAULT_TURN_LOCK_TIMEOUT_SECONDS
            participant = ClaudeParticipant(
                room, invoker,
                turn_timeout=args.turn_timeout
                if args.turn_timeout is not None
                else DEFAULT_TURN_LOCK_TIMEOUT_SECONDS,
            )
            _emit(participant.run_turn(args.message_id, dry_run=args.dry_run))
        elif args.command == "verify":
            _emit({"verified": room.store.verify_store()})
        elif args.command == "query":
            if args.participant_name:
                _emit(room.by_participant(args.participant_name))
            elif args.project_repo:
                _emit(room.by_project(args.project_repo))
            elif args.thread_id:
                _emit(room.by_thread(args.thread_id))
            else:
                _emit(room.all_messages())
        return 0
    except DeliveryError as exc:
        # The message is already durable locally. Emit that as data on stdout
        # so a CLI-only participant can retry `push` rather than reposting
        # under a fresh UUID and duplicating the message permanently.
        _emit(exc.as_result())
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_PARTIAL_DELIVERY
    except AgentRoomError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"InputError: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
