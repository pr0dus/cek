"""Verified-report wake orchestration and the dormant PR-comment adapter.

Report selection, signing and verification are independent of WakeTransport.
The reviewed comment adapter never retries an ambiguous POST; the Git adapter
may retry only through its immutable-artifact/exact-lease reconciliation.
"""
import http.client
import json
import os
from pathlib import Path
import re
import secrets
from typing import Protocol

from . import canonical
from .errors import AgentRoomError
from .doorbell_protocol import DoorbellError, ROLES, decode, encode, from_report, require
from .transport_state import private_directory, private_lock, check_file, WORKER_LOCK

MAX_HTTP_BYTES = 1024 * 1024
MAX_PAGES = 8
MAX_EVENTS_PER_PASS = 8
MAX_RECORDS = 2048
MAX_LEDGER_BYTES = 3 * 1024 * 1024


def configuration(value):
    commit = isinstance(value, dict) and value.get('transport') == 'pr-commit'
    fields = {'repository', 'pull_number', 'pull_node_id'}
    fields |= {'transport', 'branch', 'bootstrap_tip'} if commit else {'actor_ids'}
    require(isinstance(value, dict) and set(value) == fields, 'doorbell config fields')
    require(isinstance(value['repository'], str) and re.fullmatch(
        r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', value['repository']) is not None,
        'doorbell repository')
    require(type(value['pull_number']) is int and value['pull_number'] > 0, 'doorbell PR')
    require(isinstance(value['pull_node_id'], str) and re.fullmatch(
        r'[A-Za-z0-9_=-]{1,128}', value['pull_node_id']) is not None, 'doorbell PR node')
    if commit:
        from .protected_state import oid
        require(value['branch'] == 'supervisor-doorbell-v1', 'fixed doorbell branch required')
        require(oid(value['bootstrap_tip']), 'doorbell bootstrap tip')
        return json.loads(canonical.canonical_text(value))
    require(isinstance(value['actor_ids'], dict) and set(value['actor_ids']) == set(ROLES),
            'doorbell actors')
    require(all(type(v) is int and v > 0 for v in value['actor_ids'].values()), 'doorbell actor IDs')
    return json.loads(canonical.canonical_text(value))


def receipt_field(config):
    return 'commit_oid' if config.get('transport') == 'pr-commit' else 'comment_id'


def valid_receipt(config, value):
    from .protected_state import oid
    return oid(value) if receipt_field(config) == 'commit_oid' else type(value) is int and value > 0


class WakeTransport(Protocol):
    """Metadata-only adapter. Opaque receipt, or unresolved; never invokes a model.

    post attempts initial delivery; find reconciles an uncertain intent. Only a
    transport with immutable remote identity may safely retry during find.
    """
    def check_target(self) -> None: ...
    def post(self, event): ...
    def find(self, event): ...


class GitHubPR:
    """Fixed api.github.com TLS endpoint; no redirects, subprocesses or URLs in input."""

    def __init__(self, config, role, token):
        self.config = configuration(config)
        require(role in ROLES, 'doorbell role')
        require(isinstance(token, str) and re.fullmatch(r'[A-Za-z0-9_]{10,1024}', token),
                'doorbell credential format')
        self.role, self._token = role, token
        self.prefix = '/repos/' + self.config['repository']

    def _request(self, method, suffix, payload=None):
        connection = http.client.HTTPSConnection('api.github.com', timeout=10)
        try:
            data = None if payload is None else canonical.canonical_bytes(payload)
            connection.request(method, self.prefix + suffix, body=data, headers={
                'Authorization': 'Bearer ' + self._token,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'agent-room-doorbell-v1',
                'Content-Type': 'application/json',
            })
            response = connection.getresponse()
            require(response.status == (201 if method == 'POST' else 200),
                    'GitHub notification request not confirmed')
            length = response.getheader('Content-Length')
            require(length is None or (length.isdigit() and int(length) <= MAX_HTTP_BYTES),
                    'GitHub response too large')
            raw = response.read(MAX_HTTP_BYTES + 1)
            require(len(raw) <= MAX_HTTP_BYTES, 'GitHub response too large')
            return canonical.strict_loads(raw)
        except (AgentRoomError, http.client.HTTPException, OSError, ValueError):
            # Never echo exception text/headers/body/token from network failures.
            raise DoorbellError('GitHub notification I/O unresolved') from None
        finally:
            connection.close()

    def check_target(self):
        result = self._request('GET', '/pulls/' + str(self.config['pull_number']))
        require(isinstance(result, dict) and result.get('state') == 'open'
                and result.get('node_id') == self.config['pull_node_id']
                and type(result.get('number')) is int
                and result['number'] == self.config['pull_number'], 'wrong/closed doorbell PR')
        base = result.get('base')
        require(isinstance(base, dict) and isinstance(base.get('repo'), dict)
                and base['repo'].get('full_name') == self.config['repository'], 'wrong PR repository')

    def _comment_id(self, comment, body):
        require(isinstance(comment, dict), 'malformed GitHub comment')
        user = comment.get('user')
        require(isinstance(user, dict) and type(user.get('id')) is int
                and user['id'] == self.config['actor_ids'][self.role],
                'wrong doorbell comment actor')
        cid = comment.get('id')
        require(type(cid) is int and cid > 0 and comment.get('body') == body,
                'wrong doorbell comment binding')
        expected = f"https://api.github.com/repos/{self.config['repository']}/issues/{self.config['pull_number']}"
        require(comment.get('issue_url') == expected, 'wrong doorbell comment PR')
        return cid

    def post(self, event):
        body = encode(event)
        require(event['role'] == self.role, 'wrong event role')
        comment = self._request('POST', f"/issues/{self.config['pull_number']}/comments", {'body': body})
        return self._comment_id(comment, body)

    def find(self, event):
        """Finite reconciliation; no match never authorizes another POST."""
        body, matches = encode(event), []
        for page in range(1, MAX_PAGES + 1):
            result = self._request('GET', f"/issues/{self.config['pull_number']}/comments?per_page=100&page={page}")
            require(isinstance(result, list) and len(result) <= 100, 'malformed comment page')
            for item in result:
                require(isinstance(item, dict), 'malformed comment')
                if item.get('body') == body:
                    matches.append(self._comment_id(item, body))
            if len(result) < 100:
                require(len(matches) <= 1, 'duplicate doorbell comments require inspection')
                return matches[0] if matches else None
        raise DoorbellError('comment reconciliation bound reached; no repost')


class DeliveryLedger:
    """One role-owned ledger with an explicit initial enrollment, not TOFU."""

    def __init__(self, root, identity):
        self.root, self.identity = Path(root), identity

    def initialise(self):
        with private_lock(self.root, WORKER_LOCK):
            with private_directory(self.root) as directory:
                fd = os.open('ledger.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'wb') as out:
                    out.write(canonical.canonical_bytes(dict(version=1, identity=self.identity, events={})))
                    out.flush()
                    os.fsync(out.fileno())
                os.fsync(directory)

    def load(self):
        with private_directory(self.root) as directory:
            try:
                fd = os.open('ledger.json', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
            except OSError:
                raise DoorbellError('missing/unreadable doorbell ledger; explicit enrollment required') from None
            with os.fdopen(fd, 'rb') as inp:
                require(check_file(inp.fileno()).st_size <= MAX_LEDGER_BYTES, 'doorbell ledger too large')
                raw = inp.read(MAX_LEDGER_BYTES + 1)
                require(len(raw) <= MAX_LEDGER_BYTES, 'doorbell ledger too large')
        doc = canonical.strict_loads(raw)
        self.validate(doc)
        return doc

    def validate(self, doc):
        require(isinstance(doc, dict) and set(doc) == {'version', 'identity', 'events'}, 'ledger fields')
        require(type(doc['version']) is int and doc['version'] == 1
                and canonical.canonical_bytes(doc['identity']) == canonical.canonical_bytes(self.identity),
                'ledger identity/version')
        require(isinstance(doc['events'], dict) and len(doc['events']) <= MAX_RECORDS, 'ledger bounds')
        field = receipt_field(self.identity['config'])
        for key, entry in doc['events'].items():
            require(isinstance(entry, dict) and set(entry) == {'event', 'state', field}, 'ledger entry')
            event = decode(encode(entry['event']))
            require(key == event['event_id'] and event['role'] == self.identity['role']
                    and event['room_id'] == self.identity['room_id'], 'ledger event identity')
            require(entry['state'] in ('uncertain', 'delivered'), 'ledger delivery state')
            require((entry['state'] == 'uncertain' and entry[field] is None)
                    or (entry['state'] == 'delivered' and valid_receipt(self.identity['config'], entry[field])), 'ledger receipt')

    def save(self, doc):
        # Caller holds WORKER_LOCK across read/verify/network/write.
        self.validate(doc)
        data = canonical.canonical_bytes(doc)
        require(len(data) <= MAX_LEDGER_BYTES, 'doorbell ledger too large')
        with private_directory(self.root) as directory:
            name = '.doorbell-' + secrets.token_hex(16)
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'wb') as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(name, 'ledger.json', src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            except BaseException:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass
                raise


class Doorbell:
    def __init__(self, store, checkpoint, state_dir, config, role, github: WakeTransport):
        require(store.trust is not None and role in ROLES, 'authenticated coding role required')
        self.store, self.checkpoint, self.role, self.transport = store, checkpoint, role, github
        self.config = configuration(config)
        self.ledger = DeliveryLedger(state_dir, dict(room_id=store.room_id(), role=role, config=self.config))

    def drain(self):
        """Only confirmed remote reports; at most eight notifications, no model call."""
        with private_lock(self.ledger.root, WORKER_LOCK):
            doc = self.ledger.load()
            with self.store.writer_lock():
                require(self.store.remote is not None, 'remote delivery must be provable')
                self.checkpoint.verify_candidate(self.store)
                tip = self.store.current_tip()
                delivered, known, _ = self.store._reconcile_push(tip)
                require(delivered is True and known is True, 'room report delivery unproven')
                require(self.store.current_tip() == tip, 'room changed during doorbell verification')
                events = []
                for report in self.store.iter_messages():
                    if report['sender']['agent'] == self.role:
                        event = from_report(self.store.room_id(), report)
                        if event is not None:
                            events.append(event)
                self.checkpoint.accept(self.store, tip)
            ids = {event['event_id'] for event in events}
            require(set(doc['events']) <= ids, 'prior notification report missing; no ledger reset')
            eligible = [e for e in events if doc['events'].get(e['event_id'], {}).get('state') != 'delivered']
            if not eligible:
                return {'status': 'idle', 'events': []}
            self.transport.check_target()
            results = []
            field = receipt_field(self.config)
            for event in eligible[:MAX_EVENTS_PER_PASS]:
                key = event['event_id']
                old = doc['events'].get(key)
                if old is not None:
                    require(old['event'] == event, 'changed event binding')
                    try:
                        cid = self.transport.find(event)
                    except DoorbellError:
                        cid = None
                else:
                    require(len(doc['events']) < MAX_RECORDS, 'doorbell history bound; explicit maintenance')
                    # Durable intent precedes any potentially ambiguous transport write.
                    doc['events'][key] = dict(event=event, state='uncertain', **{field: None})
                    self.ledger.save(doc)
                    try:
                        cid = self.transport.post(event)
                    except DoorbellError:
                        cid = None
                if cid is None:
                    results.append({'event_id': key, 'state': 'uncertain'})
                    break
                require(valid_receipt(self.config, cid), 'invalid delivery receipt')
                doc['events'][key].update(state='delivered', **{field: cid})
                self.ledger.save(doc)
                results.append({'event_id': key, 'state': 'delivered', field: cid})
            return {'status': 'uncertain' if results[-1]['state'] == 'uncertain' else 'delivered',
                    'events': results, 'remaining': len(eligible) - len(results)}
