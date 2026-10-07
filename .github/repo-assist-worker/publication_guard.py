#!/usr/bin/env python3
"""Exact-token gate for stopped workers and their final publication artifacts.

Run again after native bundle generation. Every upload must require this gate's
success, including always() uploads. This is additional to native detection and
Gitleaks. It is not a detector for encoded or transformed credentials.
"""
import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time

GIT = '/usr/bin/git'
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILES = 100_000
MAX_OBJECTS = 100_000
MAX_DEPTH = 64
MAX_SECONDS = 180
CHUNK_BYTES = 128 * 1024
FAILURE = 'Unsafe publication inputs; publishing blocked'


class PublicationBlocked(ValueError):
    """Contains only a fixed diagnostic, never untrusted paths or Git output."""


@dataclass
class Budget:
    deadline: float
    files: int = 0
    size: int = 0

    def check(self, size: int = 0) -> None:
        self.size += size
        if self.size > MAX_TOTAL_BYTES or time.monotonic() > self.deadline:
            raise PublicationBlocked(FAILURE)


def contains_token(data: bytes, needle: bytes) -> None:
    if needle in data:
        raise PublicationBlocked(FAILURE)


def scan_file(path: Path, needle: bytes, budget: Budget, maximum: int) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise PublicationBlocked(FAILURE)
        tail = b''
        total = 0
        while chunk := source.read(CHUNK_BYTES):
            total += len(chunk)
            budget.check(len(chunk))
            if total > maximum:
                raise PublicationBlocked(FAILURE)
            data = tail + chunk
            contains_token(data, needle)
            tail = data[-(len(needle) - 1):] if len(needle) > 1 else b''
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or total != before.st_size:
            raise PublicationBlocked(FAILURE)


def scan_tree(root: Path, needle: bytes, budget: Budget, *, workspace: bool) -> list[Path]:
    bundles: list[Path] = []

    def visit(path: Path, depth: int, in_git: bool) -> None:
        budget.check()
        budget.files += 1
        if depth > MAX_DEPTH or budget.files > MAX_FILES:
            raise PublicationBlocked(FAILURE)
        contains_token(os.fsencode(path), needle)
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            if not workspace or in_git or depth == 0:
                raise PublicationBlocked(FAILURE)
            contains_token(os.fsencode(os.readlink(path)), needle)
        elif stat.S_ISDIR(status.st_mode):
            for child in sorted(path.iterdir()):
                visit(child, depth + 1, in_git or (depth == 0 and child.name == '.git'))
        elif stat.S_ISREG(status.st_mode):
            scan_file(path, needle, budget, MAX_FILE_BYTES)
            if path.suffix == '.bundle':
                bundles.append(path)
        else:
            raise PublicationBlocked(FAILURE)

    visit(root, 0, False)
    return bundles


def git_environment(scratch: Path) -> dict[str, str]:
    return {
        'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'XDG_CONFIG_HOME': str(scratch),
        'LANG': 'C', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
        'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': '',
        'GIT_OPTIONAL_LOCKS': '0',
    }


def run_git(repo: Path, scratch: Path, budget: Budget, *arguments: str,
            output_limit: int = 16 * 1024 * 1024) -> Path:
    budget.check()
    output = scratch / 'git-output'

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    with output.open('wb') as destination:
        result = subprocess.run([
            GIT, '--no-pager', '--git-dir=' + str(repo),
            '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
            '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0',
            *arguments,
        ], cwd=scratch, env=git_environment(scratch), stdin=subprocess.DEVNULL,
            stdout=destination, stderr=subprocess.DEVNULL,
            timeout=max(0.001, min(30, budget.deadline - time.monotonic())),
            check=False, preexec_fn=limits)
    if result.returncode != 0 or output.stat().st_size > output_limit:
        raise PublicationBlocked(FAILURE)
    return output


def copy_object_store(workspace: Path, repo: Path) -> None:
    source = workspace / '.git'
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise PublicationBlocked(FAILURE)
    for name in ('commondir', 'gitdir', 'objects/info/alternates', 'objects/info/http-alternates'):
        if os.path.lexists(source / name):
            raise PublicationBlocked(FAILURE)
    objects = source / 'objects'
    if not objects.is_dir() or objects.is_symlink():
        raise PublicationBlocked(FAILURE)
    # Only actual loose objects and pack/index files are needed. Do not import
    # config, refs, hooks, alternates, replacement refs, grafts or graph caches.
    for path in objects.rglob('*'):
        if path.is_symlink():
            raise PublicationBlocked(FAILURE)
        relative = path.relative_to(objects)
        if path.is_file():
            name = relative.as_posix()
            actual_object = (re.fullmatch(r'[0-9a-f]{2}/[0-9a-f]{38}', name)
                or re.fullmatch(r'pack/pack-[0-9a-f]{40}\.(pack|idx)', name))
            cache = (name in ('info/packs', 'info/commit-graph', 'pack/multi-pack-index')
                or re.fullmatch(r'pack/pack-[0-9a-f]{40}\.(rev|bitmap|keep|promisor)', name)
                or re.fullmatch(r'info/commit-graphs/(commit-graph-chain|graph-[0-9a-f]{40}\.graph)', name))
            if not actual_object and not cache:
                raise PublicationBlocked(FAILURE)
            if actual_object:
                destination = repo / 'objects' / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination, follow_symlinks=False)



def scan_objects(repo: Path, scratch: Path, needle: bytes, budget: Budget) -> None:
    packs = repo / 'objects/pack'
    for path in packs.iterdir():
        if path.suffix in ('.pack', '.idx'):
            partner = path.with_suffix('.idx' if path.suffix == '.pack' else '.pack')
            if not partner.is_file():
                raise PublicationBlocked(FAILURE)
        if path.suffix == '.idx':
            # cat-file can silently ignore a malformed pack index. Verify each
            # pair before trusting its object enumeration.
            run_git(repo, scratch, budget, 'verify-pack', str(path))
    catalogue = run_git(repo, scratch, budget, 'cat-file', '--batch-all-objects',
        '--batch-check=%(objectname) %(objecttype) %(objectsize)')
    total = count = 0
    with catalogue.open('rb') as objects:
        for line in objects:
            fields = line.split()
            if len(fields) != 3 or not re.fullmatch(rb'[0-9a-f]{40}', fields[0]) or fields[1] not in (
                    b'blob', b'tree', b'commit', b'tag') or not fields[2].isdigit():
                raise PublicationBlocked(FAILURE)
            size = int(fields[2])
            count += 1
            total += size
            if count > MAX_OBJECTS or size > MAX_OBJECT_BYTES or total > MAX_TOTAL_BYTES:
                raise PublicationBlocked(FAILURE)
    decoded = run_git(repo, scratch, budget, 'cat-file', '--batch-all-objects', '--batch',
        output_limit=MAX_TOTAL_BYTES + MAX_OBJECTS * 128)
    scan_file(decoded, needle, budget, MAX_TOTAL_BYTES + MAX_OBJECTS * 128)


def remove_artifacts(roots: list[Path]) -> None:
    # shutil.rmtree's fd-based implementation does not follow symlink attacks.
    if not shutil.rmtree.avoids_symlink_attacks:
        raise PublicationBlocked('Artifact cleanup unavailable; publishing blocked')
    failed = False
    for root in roots:
        try:
            status = root.lstat()
            if stat.S_ISDIR(status.st_mode):
                shutil.rmtree(root)
            else:
                root.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            failed = True
    if failed:
        raise PublicationBlocked('Artifact cleanup failed; publishing blocked')



def validate_roots(workspace: Path, roots: list[Path], scratch_parent: Path) -> None:
    # Validate caller-supplied deletion targets before entering the cleanup path.
    paths = [workspace, scratch_parent, *roots]
    if any(not path.is_absolute() or '..' in path.parts for path in paths):
        raise PublicationBlocked(FAILURE)
    for path in paths:
        if any(parent.is_symlink() for parent in path.parents):
            raise PublicationBlocked(FAILURE)
    if scratch_parent.is_symlink():
        raise PublicationBlocked(FAILURE)
    for root in roots:
        if root == workspace or root in workspace.parents or workspace in root.parents:
            raise PublicationBlocked(FAILURE)
        if root == scratch_parent or root in scratch_parent.parents:
            raise PublicationBlocked(FAILURE)


def enforce_publication(secret: str, workspace: Path, artifact_roots: list[Path],
                        scratch_parent: Path) -> None:
    """Check trusted paths after producers stop; remove upload roots on failure.

    Callers must supply absolute, disjoint upload roots outside the workspace and
    scratch directory. This API must not accept model-provided paths. An upload
    condition must independently require success, even if cleanup itself fails.
    """
    validate_roots(workspace, artifact_roots, scratch_parent)
    try:
        if not secret or len(secret.encode()) > 16 * 1024:
            raise PublicationBlocked(FAILURE)
        needle = secret.encode()
        budget = Budget(time.monotonic() + MAX_SECONDS)
        bundles = scan_tree(workspace, needle, budget, workspace=True)
        for root in artifact_roots:
            if os.path.lexists(root):
                bundles.extend(scan_tree(root, needle, budget, workspace=False))
        with tempfile.TemporaryDirectory(prefix='publication-guard-', dir=scratch_parent) as directory:
            scratch = Path(directory)
            repo = scratch / 'objects.git'
            run_git(repo, scratch, budget, 'init', '--bare', '--template=', str(repo))
            copy_object_store(workspace, repo)
            scan_objects(repo, scratch, needle, budget)
            for bundle in bundles:
                budget.check()
                # Import a checked copy; neither repo config nor arbitrary Git
                # commands from the worker are consulted when decoding a bundle.
                copied = scratch / 'input.bundle'
                shutil.copyfile(bundle, copied, follow_symlinks=False)
                run_git(repo, scratch, budget, 'bundle', 'unbundle', str(copied),
                        output_limit=MAX_FILE_BYTES)
                scan_objects(repo, scratch, needle, budget)
    except Exception:
        remove_artifacts(artifact_roots)
        raise PublicationBlocked(FAILURE) from None



def native_artifact_roots(ghaw: Path, safeoutputs: Path) -> list[Path]:
    """Match the frozen native agent uploads without nonuploaded skill/TLS links.

    Expand after ingestion as well as before it, so new patch/bundle files are
    checked. The transform separately fingerprints the native upload manifest.
    """
    roots = [safeoutputs]
    if ghaw.is_symlink() or (os.path.lexists(ghaw) and not ghaw.is_dir()):
        return [ghaw, *roots]
    if ghaw.exists():
        roots.extend(path for path in ghaw.iterdir()
                     if path.is_symlink() or path.is_file()
                     or (path.name.startswith('aw-') and path.suffix in ('.bundle', '.patch')))
    roots.extend(ghaw / name for name in (
        'aw-prompts/prompt.txt', 'mcp-logs',
        'sandbox/firewall/logs', 'sandbox/firewall/audit',
        'sandbox/firewall/awf-reflect.json',
        'sandbox/firewall-audit-logs/api-proxy-logs/token-usage.jsonl',
    ))
    proxy = ghaw / 'proxy-logs'
    if proxy.is_symlink() or (os.path.lexists(proxy) and not proxy.is_dir()):
        roots.append(proxy)
    elif proxy.is_dir():
        roots.extend(path for path in proxy.iterdir() if path.name != 'proxy-tls')
    return list(dict.fromkeys(roots))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--artifact-root', type=Path, action='append', default=[])
    parser.add_argument('--native-artifact-dir', type=Path)
    parser.add_argument('--safeoutputs', type=Path)
    parser.add_argument('--scratch-parent', type=Path, required=True)
    args = parser.parse_args()
    try:
        roots = args.artifact_root
        if args.native_artifact_dir is not None:
            if args.safeoutputs is None:
                raise PublicationBlocked(FAILURE)
            roots += native_artifact_roots(args.native_artifact_dir, args.safeoutputs)
        if not roots:
            raise PublicationBlocked(FAILURE)
        enforce_publication(os.environ.get('SECRET_CLAUDE_CODE_OAUTH_TOKEN', ''),
            args.workspace, roots, args.scratch_parent)
    except (PublicationBlocked, OSError):
        print('Subscription publication gate failed; publishing blocked', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
