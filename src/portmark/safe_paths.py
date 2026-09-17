"""Capability-based safe-path helper for isolated tools (Section 7 PR 3).

An isolated tool that must touch the filesystem does so ONLY through a
:class:`SafeRoot` capability. The runtime pre-opens a private directory and hands
the tool the open *directory descriptor* (see ``ToolRegistry.filesystem_root`` and
the ``PORTMARK_ROOT_FD`` the isolated worker inherits). The tool never names the
root: it calls :meth:`SafeRoot.from_runtime`, which reads exactly that one
inherited descriptor and refuses if none was handed in. There is deliberately **no
public constructor that takes a path** -- a tool cannot widen its own authority by
choosing a different root.

Every open goes through ``openat2(2)`` with ``RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
| RESOLVE_NO_MAGICLINKS``: the kernel resolves the path *beneath* the root
descriptor and refuses any symlink, absolute component or ``..`` escape **race-free**.
A userspace ``resolve()``-then-prefix-compare is forbidden (Section 7 adjustment #2):
it is TOCTOU-vulnerable -- a component can be swapped for a symlink between the
check and the open. The component-wise ``O_NOFOLLOW`` + ``dir_fd`` walk is also
strictly weaker than ``RESOLVE_BENEATH`` (a directory opened mid-walk can be renamed
out of the root by a concurrent process), so it is **not** shipped as a fallback.

Claim boundary (do not overstate): ``SafeRoot`` is the *supported, race-free* way to
touch the filesystem. It does NOT stop a tool from calling ``open("/etc/passwd")``
directly -- the tool is ordinary Python. The deployment's mount namespace / read-only
rootfs (see ``deploy/`` and ``DEPLOYMENT.md``) is what makes the SafeRoot the *only*
reachable path. SafeRoot removes the accidental escape; containment removes the
deliberate one.

When ``openat2`` is unavailable -- an old kernel (pre-5.6), a non-Linux platform, or
a seccomp policy that blocks the syscall -- :meth:`SafeRoot.from_runtime` **refuses**
rather than silently falling back to a weaker mechanism. Usability is decided by
*attempting the syscall and reading errno*, never by parsing a version string.

Nothing in this module runs at import time: no syscall, no descriptor operation, no
C-library load. Import executes only definitions.
"""

from __future__ import annotations

import ctypes
import os
from typing import IO, Any

# The environment variable the isolated worker inherits, naming the pre-opened root
# directory descriptor. Set by ToolRegistry when a filesystem_root is configured.
ROOT_FD_ENV = "PORTMARK_ROOT_FD"

# openat2(2) resolve flags (uapi/linux/openat2.h). Combined, they forbid symlinks,
# magic-links (/proc/*/fd style) and any escape above the root descriptor.
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_SAFE_RESOLVE = _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS

# openat2 syscall number, restricted to the arches whose number we have verified: 437 on x86_64 and
# on aarch64 (which uses asm-generic/unistd.h). Every other arch returns None -> ENOSYS -> refuse,
# rather than guess a number that could invoke a DIFFERENT syscall on an arch we did not check (whose
# success the usability probe would misread as "openat2 works"). This matches the no-silent-degradation
# stance: an unverified arch fails closed, it does not fall through to a wrong syscall.
_SYS_OPENAT2 = {
    "x86_64": 437,
    "aarch64": 437,
}


class SafePathError(Exception):
    """Base class for safe-path failures."""


class SafePathUnavailable(SafePathError):
    """The safe-path capability is not available in this process.

    Raised when no runtime root descriptor was handed in, or when ``openat2`` is
    not usable here (old kernel, non-Linux, or blocked by seccomp).
    """


class SafePathEscape(SafePathError):
    """The requested path would escape the root, or crossed a symlink."""


class _OpenHow(ctypes.Structure):
    # struct open_how { __u64 flags; __u64 mode; __u64 resolve; };
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _syscall_number() -> int | None:
    return _SYS_OPENAT2.get(os.uname().machine) if hasattr(os, "uname") else None


def _libc() -> ctypes.CDLL:
    # Loaded lazily -- never at import time. use_errno so we can read the real errno.
    # argtypes are MANDATORY: without them ctypes marshals every argument as a 32-bit C int,
    # which truncates the 64-bit &how pointer and yields nondeterministic EINVAL. Declaring the
    # signature makes the pointer pass at full width.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [
        ctypes.c_long,  # syscall number
        ctypes.c_int,  # dirfd
        ctypes.c_char_p,  # pathname
        ctypes.c_void_p,  # struct open_how *
        ctypes.c_size_t,  # sizeof(struct open_how)
    ]
    return libc


def _raw_openat2(dirfd: int, path: bytes, flags: int, mode: int) -> int:
    """Invoke openat2(dirfd, path, &how, sizeof(how)); raise OSError(errno) on failure.

    Raises OSError with the real errno so callers can distinguish "not available"
    (ENOSYS/EPERM) from "escape" (EXDEV/ELOOP) from ordinary I/O errors.
    """
    number = _syscall_number()
    if number is None:
        raise OSError(38, os.strerror(38))  # ENOSYS: unknown arch, treat as absent
    how = _OpenHow(flags=flags, mode=mode, resolve=_SAFE_RESOLVE)
    libc = _libc()
    ctypes.set_errno(0)
    # Pass the struct pointer as an explicit integer address. byref()/from_param coercion into a
    # c_void_p argument marshals unreliably across ASLR layouts (intermittent EINVAL: the kernel
    # reads a truncated/garbage open_how). addressof() is an unambiguous full-width address, and
    # `how` stays referenced by this frame for the duration of the call.
    fd = libc.syscall(number, dirfd, path, ctypes.addressof(how), ctypes.sizeof(how))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(fd)


def _openat2_usable(dirfd: int) -> bool:
    """Decide usability by ATTEMPTING the syscall and reading errno -- never by version.

    Opens "." beneath the given directory descriptor. ENOSYS (no such syscall,
    old kernel) or EPERM (blocked by seccomp) mean unusable. EINVAL on the resolve
    flags likewise. Any other outcome (a real fd, or an unrelated errno) proves the
    syscall itself is reachable.
    """
    try:
        fd = _raw_openat2(dirfd, b".", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY, 0)
    except OSError as error:
        # ENOSYS(38): syscall absent. EPERM(1): blocked by seccomp. EINVAL(22):
        # resolve flags unsupported. All three => not usable here.
        return error.errno not in (1, 22, 38)
    os.close(fd)
    return True


# Text/binary open modes we translate to O_* flags. Kept small and explicit -- a tool
# that needs an exotic mode can layer it on the returned descriptor.
_MODE_FLAGS = {
    "r": os.O_RDONLY,
    "rb": os.O_RDONLY,
    "w": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    "wb": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    "ab": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    "r+": os.O_RDWR,
    "w+": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
}


class SafeRoot:
    """A capability to open files strictly beneath one runtime-provided directory.

    Construct only via :meth:`from_runtime`. The wrapped descriptor is close-on-exec,
    so files and the root itself do not leak to any process the tool spawns.
    """

    __slots__ = ("_dirfd",)

    def __init__(self, dirfd: int) -> None:
        # Internal: callers use from_runtime(). Kept minimal so tests can build one
        # around a descriptor they opened, but there is no path-taking constructor.
        self._dirfd = dirfd

    @classmethod
    def from_runtime(cls) -> "SafeRoot":
        """Return the SafeRoot for the descriptor the runtime handed this worker.

        Reads ``PORTMARK_ROOT_FD``, re-opens it close-on-exec (so grandchildren do
        not inherit it), closes the raw inherited descriptor, and verifies openat2
        is usable. Raises :class:`SafePathUnavailable` if no descriptor was handed
        in or openat2 is not usable here.
        """
        raw = os.environ.get(ROOT_FD_ENV)
        if not raw:
            raise SafePathUnavailable(
                "no runtime filesystem root was provided "
                "(set ToolRegistry(filesystem_root=...) to grant one)"
            )
        try:
            inherited = int(raw)
        except ValueError as error:
            raise SafePathUnavailable(f"invalid {ROOT_FD_ENV}: {raw!r}") from error
        # Re-open as a fresh close-on-exec descriptor, then drop the inherited one so
        # anything this tool spawns cannot inherit filesystem authority.
        try:
            owned = os.open(".", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY, dir_fd=inherited)
        except OSError as error:
            raise SafePathUnavailable(f"runtime root descriptor is not usable: {error}") from error
        finally:
            try:
                os.close(inherited)
            except OSError:
                pass
        os.set_inheritable(owned, False)
        if not _openat2_usable(owned):
            os.close(owned)
            raise SafePathUnavailable(
                "openat2(RESOLVE_BENEATH) is not usable here "
                "(needs Linux >= 5.6 and a seccomp policy that permits it); "
                "the safe-path capability refuses rather than degrade to a race-vulnerable check"
            )
        return cls(owned)

    def mechanism(self) -> str:
        """The live path-resolution mechanism, for the audit trail. Always 'openat2'
        for a constructed SafeRoot -- construction refuses if it is not usable."""
        return "openat2"

    def open_beneath(self, relpath: str, mode: str = "r", *, encoding: str | None = None) -> IO[Any]:
        """Open ``relpath`` strictly beneath the root, race-free.

        ``relpath`` must be relative and stay within the root. Absolute paths, ``..``
        traversal and any symlink crossing are refused by the kernel. Raises
        :class:`SafePathEscape` on an escape/symlink attempt, :class:`ValueError` on a
        malformed mode, and OSError for ordinary I/O failures (missing file, EROFS).
        """
        try:
            flags = _MODE_FLAGS[mode]
        except KeyError as error:
            raise ValueError(f"unsupported mode: {mode!r}") from error
        if relpath.startswith("/") or relpath == "":
            raise SafePathEscape(f"path must be relative and non-empty: {relpath!r}")
        # openat2 requires how.mode == 0 unless O_CREAT/O_TMPFILE is set (EINVAL otherwise), so a
        # create-mode gets 0o600 and a read/existing-file mode gets 0.
        create_mode = 0o600 if flags & os.O_CREAT else 0
        try:
            fd = _raw_openat2(self._dirfd, os.fsencode(relpath), flags | os.O_CLOEXEC, create_mode)
        except OSError as error:
            # EXDEV(18): escape blocked by RESOLVE_BENEATH. ELOOP(40): symlink blocked
            # by RESOLVE_NO_SYMLINKS. Both mean the path tried to leave the root.
            if error.errno in (18, 40):
                raise SafePathEscape(f"path escapes the root or crosses a symlink: {relpath!r}") from error
            raise
        binary = mode.endswith("b")
        if binary:
            return os.fdopen(fd, mode, closefd=True)
        return os.fdopen(fd, mode, encoding=encoding or "utf-8", closefd=True)

    def close(self) -> None:
        try:
            os.close(self._dirfd)
        except OSError:
            pass

    def __enter__(self) -> "SafeRoot":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
