# Agent Room event-driven control wake

The GitHub webhook is a wake signal only. It never carries a command, path,
identity, model prompt or authority.

Production route:

- public endpoint: `https://agent-room.weslr.de/github/control-wake`
- Cloudflare Tunnel origin: `http://192.168.2.47:8787`
- receiver bind: `192.168.2.47:8787`
- repository: `pr0dus/agent-room-transport`
- accepted GitHub event: `push`
- accepted ref: `refs/heads/agent-room-control`

The receiver verifies `X-Hub-Signature-256` using the dedicated root-owned
`/etc/agent-room/webhook.secret`, then wakes exactly one bounded
`TransportWorker` pass against `/etc/agent-room/transport.json`. Concurrent
pushes are coalesced into a later pass; the durable control ledger remains the
replay/idempotency authority.

No webhook field selects an operation. Operations remain limited by the
existing closed control request schema in `agent_room.transport`.

The previous periodic transport timer is a fallback only. Disable it only after
a live signed webhook delivery proves the event-driven path.
