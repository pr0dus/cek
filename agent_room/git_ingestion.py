"""C4 bounded quarantine. Network bytes never land in the authoritative ODB.

Linux/prlimit is mandatory, not a best-effort fallback. A fresh repository,
one exact ref, --keep/unpackLimit=0, no tags/FETCH_HEAD/reflogs/maintenance
means fetch writes one pack and one index, not an attacker-sized loose-file
fanout. RLIMIT_FSIZE applies while those files are written; RLIMIT_AS bounds
index/delta expansion. A second, exact reachable-only pack is exported after
the caller's full protocol verification. See docs/AGENT_ROOM_TRANSPORT_C4.md.
"""
import os
import re
import shutil
import stat
from pathlib import Path

from .errors import AgentRoomError
from .process import run_bounded, sanitised_env
from .transport_state import private_directory, private_lock, STATE_LOCK

PACK_BYTES = 16 * 1024 * 1024
MEMORY_BYTES = 512 * 1024 * 1024
OBJECT_BYTES = 1024 * 1024
GRAPH_BYTES = 32 * 1024 * 1024
OBJECT_COUNT = 20000
PERSISTENT_BYTES = 128 * 1024 * 1024
PERSISTENT_FILES = 40000
TIMEOUT = 120
OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
CONFIG = ('-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
          '-c', 'protocol.ext.allow=never', '-c', 'fetch.unpackLimit=0',
          '-c', 'transfer.unpackLimit=0', '-c', 'fetch.fsckObjects=true',
          '-c', 'transfer.fsckObjects=true', '-c', 'gc.auto=0',
          '-c', 'maintenance.auto=false', '-c', 'core.logAllRefUpdates=false',
          '-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m',
          '-c', 'core.deltaBaseCacheLimit=16m', '-c', 'fetch.writeCommitGraph=false')


class IngestionError(AgentRoomError):
    pass


def verify_local_artifacts(original, candidate):
    """Keep local-artifact semantics even across isolated ODBs. No alternates.

    Candidate references were checked in quarantine; also check against objects
    already available locally so isolation cannot downgrade a bad local locator
    to an unavailable foreign object. Neither check fetches evidence.
    """
    from .schema import validate_evidence
    original.assert_no_history_overrides()
    for path, commit in candidate._history().items():
        envelope = candidate._load_raw(path, commit)
        validate_evidence(envelope['evidence'], verifier=original._artifact_verifier)


def command(path, *args, input=None):
    result = run_bounded(
        ['/usr/bin/prlimit', f'--fsize={PACK_BYTES}:{PACK_BYTES}',
         f'--as={MEMORY_BYTES}:{MEMORY_BYTES}', '--core=0:0', '--',
         'git', '--no-replace-objects', *CONFIG, *args],
        cwd=path, input=input, timeout=TIMEOUT, max_output_bytes=PACK_BYTES,
        env=sanitised_env(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                          GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1',
                          GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false'))
    if result.returncode != 0 or result.timed_out or result.output_limited:
        raise IngestionError(f'bounded Git ingestion {args[0]} refused: '
                             f'{result.stderr.decode("utf-8", "replace")[:250]}')
    return result.stdout


def storage(path, *, extra_files=0):
    """Include unreachable/partial packs; never silently prune accepted history."""
    if Path(path).is_symlink() or not Path(path).is_dir():
        raise IngestionError('object store root is absent or a symlink')
    total, count = 0, 0
    def unreadable(error):
        raise IngestionError(f'cannot inventory object store: {error}')
    for root, dirs, files in os.walk(path, followlinks=False, onerror=unreadable):
        for name in dirs + files:
            info = (Path(root)/name).lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise IngestionError('unsafe object-store path')
            count += 1
            total += max(info.st_size, info.st_blocks * 512)
            if total > PERSISTENT_BYTES or count + extra_files > PERSISTENT_FILES:
                raise IngestionError('persistent object budget exceeded; explicit maintenance required')
    return total


def census(path, tip):
    objects = command(path, 'rev-list', '--objects', '--no-object-names', tip).splitlines()
    if not objects or len(objects) > OBJECT_COUNT or any(not OID.fullmatch(o.decode('ascii')) for o in objects):
        raise IngestionError('candidate object count/identity budget exceeded')
    rows = command(path, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
                   input=b'\n'.join(objects) + b'\n').splitlines()
    if len(rows) != len(objects):
        raise IngestionError('incomplete candidate object census')
    size = 0
    for expected, row in zip(objects, rows):
        fields = row.split()
        if len(fields) != 3 or fields[0] != expected or fields[1] not in (b'blob', b'tree', b'commit'):
            raise IngestionError('missing or unsupported candidate object')
        value = int(fields[2])
        size += value
        if value > OBJECT_BYTES or size > GRAPH_BYTES:
            raise IngestionError('candidate uncompressed object budget exceeded')
    return len(objects), size


def _remove_staging(path):
    # Fixed child under the private, locked root, never a request path. Python's
    # fd-based rmtree refuses a substituted root symlink.
    if path.is_symlink():
        raise IngestionError('quarantine path is a symlink')
    if path.exists():
        shutil.rmtree(path)


def _safe_ancestors(path):
    """The private-root lock must not sit below a renameable ancestor."""
    system_owner = Path('/').stat().st_uid  # also correct in a mapped user namespace
    private_barrier = False
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (system_owner, os.geteuid()):
            raise IngestionError('unsafe quarantine ancestor identity')
        sticky_system = info.st_uid == system_owner and info.st_mode & stat.S_ISVTX
        # Default umask-002 Git directories under an owner-only directory are
        # not reachable by another UID. An exposed group-writable ancestor is.
        if info.st_mode & 0o022 and not sticky_system and not (
                private_barrier and not info.st_mode & 0o002):
            raise IngestionError('writable quarantine ancestor')
        private_barrier |= info.st_uid == os.geteuid() and not info.st_mode & 0o077


def _promote(repo, exported, pack_id, destination, tip):
    odb = repo/'objects'
    packdir = odb/'pack'
    packdir.mkdir(exist_ok=True)
    if packdir.is_symlink():
        raise IngestionError('object pack directory is a symlink')
    pairs = [(exported.with_suffix(suffix), packdir/f'pack-{pack_id}{suffix}')
             for suffix in ('.pack', '.idx')]
    addition = sum(src.stat().st_size + 4096 for src, dst in pairs if not dst.exists())
    new_files = sum(not dst.exists() for _, dst in pairs)
    if storage(odb, extra_files=new_files) + addition > PERSISTENT_BYTES:
        raise IngestionError('persistent object budget exceeded; explicit maintenance required')
    # Each rename is atomic. Crash after pack/before index leaves only bounded,
    # verified bytes, no ref installation. Next run reuses/verifies them. There
    # is no copy-in-progress file accumulating in the persistent ODB.
    for src, dst in pairs:
        if dst.exists():
            if dst.read_bytes() != src.read_bytes():
                raise IngestionError('existing pack identity collision/corruption')
        else:
            with src.open('rb') as handle:
                os.fsync(handle.fileno())
            os.replace(src, dst)
    fd = os.open(packdir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    command(repo, 'update-ref', destination, tip)


def fetch_verified(workdir, remote, ref, destination, verify):
    """Only trusted code supplies verify; no request can choose it or budgets."""
    workdir = Path(workdir)
    try:
        if not ref.startswith('refs/heads/') or not destination.startswith('refs/heads/'):
            raise IngestionError('only exact branch refs may be ingested')
        command(workdir, 'check-ref-format', ref)
        command(workdir, 'check-ref-format', destination)
        repo = Path(command(workdir, 'rev-parse', '--path-format=absolute', '--git-common-dir').decode().strip())
        _safe_ancestors(repo)
        # Historical overrides/incomplete ODBs are not ingestion authorities.
        if (repo/'shallow').exists() or (repo/'objects/info/alternates').exists() or (repo/'info/grafts').exists():
            raise IngestionError('incomplete/alternate/grafted local object store')
        if command(workdir, 'for-each-ref', '--format=%(refname)', 'refs/replace/').strip():
            raise IngestionError('replacement history is forbidden')
        if command(workdir, 'config', '--local', '--list').lower().find(b'promisor=') >= 0:
            raise IngestionError('promisor object store is forbidden')
        root = repo/'agent-room-quarantine'
        with private_directory(root), private_lock(root, STATE_LOCK):
            storage(repo/'objects')
            staging = root/'attempt'
            _remove_staging(staging)
            staging.mkdir(mode=0o700)
            try:
                remotes = command(workdir, 'remote').decode().splitlines()
                url = (command(workdir, 'remote', 'get-url', remote).decode().strip()
                       if remote in remotes else remote)
                if not isinstance(url, str) or not url or url.startswith('-') or any(ord(c) < 32 for c in url):
                    raise IngestionError('invalid configured remote locator')
                # Relative local remote URLs are relative to the original
                # checkout, not the temporary verification repository.
                if not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://|^[^/]+:', url):
                    url = str((workdir/url).resolve())
                quarantine = staging/'repo'
                quarantine.mkdir(mode=0o700)
                object_format = command(workdir, 'rev-parse', '--show-object-format').decode().strip()
                if object_format not in ('sha1', 'sha256'):
                    raise IngestionError('unsupported object format')
                command(quarantine, 'init', '-q', '--template=', '--initial-branch=unborn',
                        '--object-format='+object_format)
                command(quarantine, 'fetch', '--keep', '--no-tags', '--no-write-fetch-head',
                        '--no-auto-maintenance', '--no-recurse-submodules', '--no-write-commit-graph',
                        '--refmap=', '--', url, f'{ref}:refs/heads/candidate')
                tip = command(quarantine, 'rev-parse', '--verify', 'refs/heads/candidate').decode().strip()
                if not OID.fullmatch(tip):
                    raise IngestionError('invalid fetched tip')
                census(quarantine, tip)
                command(quarantine, 'fsck', '--strict', '--no-reflogs', '--no-dangling')
                verify(quarantine, 'candidate', tip)
                packed = command(quarantine, 'pack-objects', '--stdout', '--revs', '--window=0',
                                 input=(tip+'\n').encode())
                exported = staging/'verified.pack'
                exported.write_bytes(packed)
                pack_id = command(quarantine, 'index-pack', '--strict', str(exported)).decode().strip()
                if not OID.fullmatch(pack_id):
                    raise IngestionError('invalid exported pack identity')
                _promote(repo, exported, pack_id, destination, tip)
                return tip
            finally:
                _remove_staging(staging)
    except (OSError, ValueError, UnicodeError) as exc:
        raise IngestionError(f'Git ingestion unavailable: {exc}') from exc
