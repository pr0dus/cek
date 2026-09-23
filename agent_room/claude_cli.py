"""One-shot Claude participant commands. Opens an existing room; never creates it."""

import argparse
import sys

from .canonical import strict_loads
from .claude_participant import ClaudeParticipant
from .cli import EXIT_PARTIAL_DELIVERY, _emit
from .errors import AgentRoomError, DeliveryError, SchemaError
from .gitstore import DEFAULT_BRANCH


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--state-dir", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    inbox = commands.add_parser("inbox")
    inbox.add_argument("--all", action="store_true")
    thread = commands.add_parser("thread")
    thread.add_argument("thread_id")
    thread.add_argument("--tree", action="store_true")
    get = commands.add_parser("get")
    get.add_argument("thread_id")
    get.add_argument("message_id")
    ack = commands.add_parser("ack")
    ack.add_argument("message_id")
    for name, identifier in (("send", "thread_id"), ("reply", "parent_id")):
        post = commands.add_parser(name)
        post.add_argument(identifier)
        post.add_argument("--message", required=True, help="JSON with type, body and optional envelope content")
    commands.add_parser("push")
    commands.add_parser("verify")
    turn = commands.add_parser("turn")
    turn.add_argument("--project-dir", required=True, help="trusted directory used as Claude's cwd")
    turn.add_argument("--message-id")
    turn.add_argument("--timeout", type=float, default=120)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        participant = ClaudeParticipant(args.repo, branch=args.branch, remote=args.remote,
                                        state_dir=args.state_dir)
        if args.command == "inbox":
            result = participant.inbox(unread_only=not args.all)
        elif args.command == "thread":
            result = (participant.thread_tree(args.thread_id) if args.tree
                      else participant.thread(args.thread_id))
        elif args.command == "get":
            result = participant.get(args.thread_id, args.message_id)
        elif args.command == "ack":
            result = participant.acknowledge(args.message_id)
        elif args.command in ("send", "reply"):
            message = strict_loads(args.message)
            allowed = {"type", "body", "recipient", "project", "evidence", "claim",
                       "status", "reply_requested", "human_approval_required"}
            if (not isinstance(message, dict) or set(message) - allowed
                    or not {"type", "body"}.issubset(message)):
                raise SchemaError("message has forbidden or missing fields; identity and linkage are fixed")
            result = (participant.start_thread(thread_id=args.thread_id, **message)
                      if args.command == "send" else participant.reply(args.parent_id, **message))
        elif args.command == "turn":
            result = participant.turn(project_dir=args.project_dir,
                                      message_id=args.message_id, timeout=args.timeout)
        elif args.command == "push":
            result = participant.push()
        else:
            result = {"verified": participant.verify()}
        _emit(result)
        return 0
    except DeliveryError as exc:
        _emit(exc.as_result())
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_PARTIAL_DELIVERY
    except (AgentRoomError, OSError, ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
