#!/usr/bin/env python3
"""Stage verified repository tools before starting either model controller."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import tempfile
from urllib.request import urlopen


JQ_VERSION = '1.8.1'
JQ_URL = f'https://github.com/jqlang/jq/releases/download/jq-{JQ_VERSION}/jq-linux-amd64'
# https://github.com/jqlang/jq/releases/download/jq-1.8.1/sha256sum.txt
JQ_SHA256 = '020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d'
MAX_JQ_BYTES = 8 * 1024 * 1024


def require_jq(cache: Path) -> Path:
    directory = cache / 'repo-assist/bin'
    binary = directory / 'jq'
    if (binary.is_symlink() or not binary.is_file()
            or binary.stat().st_size > MAX_JQ_BYTES or not os.access(binary, os.X_OK)
            or hashlib.sha256(binary.read_bytes()).hexdigest() != JQ_SHA256):
        raise ValueError('Pinned repository jq installation is missing or invalid')
    return directory


def install_jq(cache: Path) -> None:
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        raise ValueError('Repository jq requires the Linux x86_64 runner')
    directory = cache / 'repo-assist/bin'
    directory.mkdir(parents=True, exist_ok=True)
    with urlopen(JQ_URL, timeout=60) as response:
        payload = response.read(MAX_JQ_BYTES + 1)
    if len(payload) > MAX_JQ_BYTES or hashlib.sha256(payload).hexdigest() != JQ_SHA256:
        raise ValueError('Pinned repository jq download failed SHA-256 verification')
    descriptor, name = tempfile.mkstemp(prefix='.jq-', dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload)
        temporary.chmod(0o555)
        temporary.replace(directory / 'jq')
    finally:
        temporary.unlink(missing_ok=True)
    require_jq(cache)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cache', type=Path)
    install_jq(parser.parse_args().cache)
