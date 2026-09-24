"""Entrypoint for one bounded transport invocation.

Deliberately tiny. The unit file names a fixed config path and this runs one
pass over the control queue and exits; systemd owns the lifecycle, the cgroup
and the timer. There is no loop here, no reconnect logic and no daemon state —
each run either completes or fails visibly, which is the property a
home-grown forever-loop keeps losing.

The single argument is the config path, and it comes from a root-owned unit
file, never from a request.
"""

import json
import sys

from .transport import TransportConfig, TransportWorker
from . import custody

DEFAULT_CONFIG = "/etc/agent-room/transport.json"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv != [DEFAULT_CONFIG]:
        print("usage: python3 -m agent_room.transport_worker [config.json]",
              file=sys.stderr)
        return 2
    config_path = argv[0] if argv else DEFAULT_CONFIG
    try:
        item = custody.guard('openai-research')
        custody.root_file(config_path)
        config = TransportConfig.load(config_path)
        custody.check_transport(config, item)
        custody.install_environment('openai-research', item)
        summary = TransportWorker(config).run()
    except Exception as exc:                          # noqa: BLE001
        # One line, no traceback, no paths beyond the config: the journal of
        # an unattended service is not a place to leak state.
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
