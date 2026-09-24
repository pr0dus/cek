"""Disposable S3 cgroup fixture. Never shipped as a service entrypoint."""
import json
import sys

from agent_room.transport import TransportConfig, TransportWorker

if __name__ == '__main__':
    print(json.dumps(TransportWorker(TransportConfig.load(sys.argv[1])).run()))
