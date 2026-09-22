"""Pytest configuration.

Adds the repository root to `sys.path` so `agent_room` imports without an
install step, and re-exports the Agent Room fixtures.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.conftest_agent_room import (  # noqa: E402,F401
    bare_remote,
    configure_identity,
    git,
    room,
    store,
)
