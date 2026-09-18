"""Crash-safe file primitives shared by keygen's trust registry and the Section 10 audit floor.

- `atomic_write_bytes`: temp file in the same directory -> write -> fsync -> `os.replace` ->
  parent-directory fsync, preserving the existing file's permissions.
- `sidecar_lock`: an exclusive, OS-released cross-process lock on `<path>.lock` (fcntl on POSIX,
  msvcrt on Windows), so read -> validate -> merge -> replace is serialized across processes.
"""

from __future__ import annotations

import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager


def atomic_write_bytes(path: str, data: bytes, prefix: str = ".portmark-") -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        mode: int | None = os.stat(path).st_mode & 0o777
    except OSError:
        mode = None
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Durability: fsync the parent directory so the rename itself survives a crash, not
    # just the file contents (finding #4). Not all platforms permit opening a directory
    # for fsync (Windows); best-effort there.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _acquire_exclusive_lock(fd: int, timeout: float = 30.0) -> None:
    """Take an exclusive, OS-released lock on `fd` (finding #4).

    fcntl (POSIX) and msvcrt (Windows) locks are both released by the kernel when the
    holding process dies, so neither can leave a stale lock the way an O_EXCL lock FILE
    would. POSIX flock blocks; msvcrt has no blocking whole-file primitive, so we spin on
    the non-blocking variant until we win or the timeout elapses (then surface the error).
    On a platform offering neither primitive the lock is a documented no-op.
    """
    try:
        import fcntl
    except ImportError:
        fcntl = None  # type: ignore[assignment]
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    try:
        import msvcrt
    except ImportError:
        return  # neither fcntl nor msvcrt: documented no-op (write stays crash-atomic)
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]  # Windows-only; stubs absent on POSIX
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _release_exclusive_lock(fd: int) -> None:
    # Closing the fd releases either lock, but release explicitly and match the msvcrt
    # locked range (offset 0, 1 byte) so the unlock is well-formed.
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    except ImportError:
        pass
    try:
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]  # Windows-only; stubs absent on POSIX
    except (ImportError, OSError):
        pass


@contextmanager
def sidecar_lock(path: str) -> Iterator[None]:
    """Serialize read -> validate -> merge -> replace across concurrent writers (finding #4).

    Locks a SIDE-CAR file (`<path>.lock`) that is never renamed. Locking `path` itself is
    defeated by the atomic `os.replace`: it swaps the inode, so a second writer locks the
    NEW inode and proceeds concurrently, silently discarding the first writer's rotation
    entry. POSIX uses fcntl.flock, Windows uses msvcrt.locking; on a platform offering
    neither, the write stays crash-atomic but concurrent merges are not serialized.
    """
    lock_path = path + ".lock"
    directory = os.path.dirname(os.path.abspath(lock_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        _acquire_exclusive_lock(fd)
        yield
    finally:
        try:
            _release_exclusive_lock(fd)
        finally:
            os.close(fd)


