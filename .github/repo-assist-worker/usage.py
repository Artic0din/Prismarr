#!/usr/bin/env python3
"""Claude subscription token receipts for native gh-aw operational accounting.

The legacy token-usage path is a compatibility transport, not evidence of a
firewall API proxy. Native gh-aw prices these measured token counts into AIC.
Neither that estimate nor Claude's client-side cost fields are API charges or
subscription quota. An incomplete component leaves a nonempty unknown marker,
so native coverage rejects it and the daily scanner applies its run fallback.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MAX_CAPTURE_BYTES = 32 * 1024 * 1024
# Intentional nonempty JSON null, not a numeric-zero receipt. Native strict
# daily coverage rejects it, while the permissive summary parser ignores it.
# An object marker would be misread by that parser as a zero-token request.
# The detector summary must also set GH_AW_WRITE_EMPTY_USAGE=false.
UNKNOWN = None
TOKEN_FIELDS = {'inputTokens': 'input_tokens', 'outputTokens': 'output_tokens',
                'cacheReadInputTokens': 'cache_read_tokens',
                'cacheCreationInputTokens': 'cache_write_tokens'}


def usage_records(text: str) -> list[dict]:
    """Read final cumulative modelUsage, including any auxiliary model work.

    Input is one fresh, single-prompt CLI invocation, never a resumed session.
    Assistant usage and result.usage are not complete whole-tree accounting.
    Error results can still contain complete consumed-token receipts.
    """
    if len(text.encode('utf-8')) > MAX_CAPTURE_BYTES:
        raise ValueError('Usage capture exceeds limit')
    result = None
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            if line.lstrip().startswith('{'):
                result = None
            continue
        if isinstance(value, dict) and value.get('type') == 'result':
            result = value
    if not isinstance(result, dict) or type(result.get('is_error')) is not bool:
        raise ValueError('Complete final usage is unavailable')
    models = result.get('modelUsage')
    if not isinstance(models, dict) or not 1 <= len(models) <= 16:
        raise ValueError('Complete per-model usage is unavailable')
    records = []
    for model, usage in models.items():
        if not re.fullmatch(r'claude-[a-z0-9][a-z0-9.-]{0,95}', model) or not isinstance(usage, dict):
            raise ValueError('Invalid model usage')
        row = {'source': 'claude_subscription_result', 'provider': 'anthropic', 'model': model}
        for name, destination in TOKEN_FIELDS.items():
            value = usage.get(name)
            if type(value) is not int or not 0 <= value < 2**53:
                raise ValueError('Incomplete token usage')
            row[destination] = value
        # Explicitly disjoint counts: native pricing must not subtract cache
        # tokens a second time. Client costUSD/total_cost_usd are not copied.
        row['input_tokens_include_cache'] = False
        records.append(row)
    if not any(row[field] for row in records for field in TOKEN_FIELDS.values()):
        raise ValueError('No positive complete usage observation')
    return records


def write_records(path: Path, records: list[dict | None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            for row in records:
                output.write(json.dumps(row, separators=(',', ':')) + '\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def begin_usage(path: Path) -> None:
    """Call immediately before starting a component, including the detector.

    Empty detection accounting means zero to the native collector. A nonempty
    marker keeps killed, timed-out, and missing-result executions unknown.
    """
    write_records(path, [UNKNOWN])


def record_usage(captures: list[str], path: Path) -> bool:
    begin_usage(path)
    try:
        if not 1 <= len(captures) <= 8:
            raise ValueError('Complete invocation capture is unavailable')
        records = [row for capture in captures for row in usage_records(capture)]
    except ValueError:
        return False
    write_records(path, records)
    return True


def record_captures(directory: Path, path: Path) -> bool:
    begin_usage(path)
    try:
        if directory.is_symlink() or not directory.is_dir():
            return False
        files = list(directory.iterdir())
        if not 1 <= len(files) <= 8:
            return False
        captures = []
        for file in sorted(files):
            if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_CAPTURE_BYTES:
                return False
            captures.append(file.read_text())
        return record_usage(captures, path)
    except (OSError, UnicodeError):
        return False


def capture_cli(directory: Path, command: list[str]) -> int:
    """Tee direct detector CLI stdout, preserving each invocation and its exit.

    Captures are durable while streaming because the native result-sink watcher
    may kill this entire process group before Claude emits a final result.
    The runner reads them after the detector exits; no partial receipt is used.
    """
    directory.mkdir(parents=True, exist_ok=True)
    fd, _ = tempfile.mkstemp(prefix='claude-', suffix='.jsonl', dir=directory)
    with os.fdopen(fd, 'wb', buffering=0) as capture:
        with subprocess.Popen(command, stdout=subprocess.PIPE) as child:
            size = 0
            try:
                while data := os.read(child.stdout.fileno(), 65536):
                    size += len(data)
                    if size > MAX_CAPTURE_BYTES:
                        # A complete result in an earlier chunk must not make a
                        # truncated invocation look fully accounted for.
                        capture.seek(0)
                        capture.truncate()
                        raise ValueError('Usage capture exceeds limit')
                    capture.write(data)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                return child.wait()
            finally:
                if child.poll() is None:
                    child.kill()


if __name__ == '__main__':
    try:
        if len(sys.argv) < 4 or sys.argv[1] != 'capture':
            raise ValueError('Expected capture directory and command')
        raise SystemExit(capture_cli(Path(sys.argv[2]), sys.argv[3:]))
    except (OSError, ValueError):
        print('Subscription usage capture failed', file=sys.stderr)
        raise SystemExit(1)
