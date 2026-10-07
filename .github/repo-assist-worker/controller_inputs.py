"""Stage untrusted detector data without giving it controller filesystem access."""
import os
from pathlib import Path
import stat
import time

MAX_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 100_000
MAX_DEPTH = 32
MAX_SECONDS = 180


def snapshot_inputs(source: Path, destination: Path) -> None:
    """Copy regular bytes through directory descriptors; never follow links."""
    budget = [0, 0]
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    destination.mkdir(mode=0o700)
    try:
        _copy_directory(descriptor, destination, budget, 0, time.monotonic() + MAX_SECONDS)
    finally:
        os.close(descriptor)


def _copy_directory(descriptor: int, destination: Path, budget: list[int], depth: int, deadline: float) -> None:
    if depth > MAX_DEPTH:
        raise ValueError('Detector input depth exceeded')
    with os.scandir(descriptor) as entries:
        for entry in entries:
            budget[0] += 1
            if budget[0] > MAX_FILES or time.monotonic() > deadline:
                raise ValueError('Detector input count or time exceeded')
            info = entry.stat(follow_symlinks=False)
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError('Detector input must contain only regular files and directories')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(info.st_mode):
                flags |= os.O_DIRECTORY
            child = os.open(entry.name, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino, opened.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
                    raise ValueError('Detector input changed during staging')
                target = destination / entry.name
                if stat.S_ISDIR(opened.st_mode):
                    target.mkdir(mode=0o700)
                    _copy_directory(child, target, budget, depth + 1, deadline)
                else:
                    _copy_file(child, target, budget, deadline)
            finally:
                os.close(child)


def _copy_file(descriptor: int, destination: Path, budget: list[int], deadline: float) -> None:
    size = 0
    with destination.open('xb') as output:
        while data := os.read(descriptor, 128 * 1024):
            size += len(data)
            budget[1] += len(data)
            if size > MAX_FILE_BYTES or budget[1] > MAX_BYTES or time.monotonic() > deadline:
                raise ValueError('Detector input size exceeded')
            output.write(data)
