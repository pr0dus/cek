"""Manual-only release ceremony, no models, socket, remote queue or executor.

The operator installs one root-owned ticket then starts the non-installable
system unit. Tickets do not grant human approval: S2 remeasurement, signature
and one-shot receipt checks still apply. Reserve never executes the action.
"""
import json
import sys

from . import custody, release
from .auth import Ed25519Signer
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .trust import TrustPolicy


def run():
    item = custody.guard('release-recorder')
    ticket = custody.root_json('/etc/agent-room/release-request.json')
    common = {'operation', 'key_id', 'request_id'}
    if not isinstance(ticket, dict):
        raise custody.CustodyError('release ticket must be an object')
    operation = ticket.get('operation')
    fields = common if operation == 'reserve' else common | {'status', 'result'}
    if operation not in ('reserve', 'reconcile') or set(ticket) != fields:
        raise custody.CustodyError('manual release ticket is not a supported ceremony')
    custody.install_environment('release-recorder', item)
    signer = Ed25519Signer(item['signing_key'], signer='release-recorder', key_id=ticket['key_id'])
    store = GitMessageStore(item['room'], branch='agent-room', remote='origin',
                            trust=TrustPolicy.load(custody.TRUST_POLICY))
    if operation == 'reserve':
        return release.reserve(store, ticket['request_id'], workdir=item['workspace'], signer=signer)
    return release.reconcile(store, ticket['request_id'], status=ticket['status'],
                             result=ticket['result'], signer=signer)


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print('release_worker takes no request arguments', file=sys.stderr)
        return 2
    try:
        result = run()
    except (AgentRoomError, OSError, ValueError) as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
