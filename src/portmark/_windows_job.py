"""Windows Job Object primitives for the isolated-tool hard-kill executor.

A Job Object is the Windows equivalent of the POSIX session/process group the
runtime uses elsewhere: a child assigned to the job -- and every descendant it
spawns -- can be terminated as one unit, and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
reaps the whole tree if the last job handle closes (e.g. an unexpected host exit).

This module is import-safe on every platform: the ctypes bindings load lazily and
only on Windows. `available()` reports whether the hard-kill primitive can be used
here; the executor refuses side-effecting isolated tools when it cannot.

Race-free launch (see the standalone validation harness): the worker is created
SUSPENDED, assigned to the job while it still cannot have spawned anything, then
its primary thread is resumed. There is no window in which a descendant could
escape the job before assignment.
"""
from __future__ import annotations

import sys

# CreateProcess creation flags the executor combines with the pipe setup.
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000

_JobObjectExtendedLimitInformation = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_THREAD_SUSPEND_RESUME = 0x0002
_TH32CS_SNAPTHREAD = 0x00000004

_k32 = None  # bound once, on Windows


def available() -> bool:
    """True when Windows Job Object hard-kill can be used in this process."""
    return sys.platform == "win32" and _kernel32() is not None


def _kernel32():
    global _k32
    if sys.platform != "win32":
        return None
    if _k32 is not None:
        return _k32
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    # A HANDLE is a pointer; ctypes' default c_int restype truncates it to 32 bits on
    # 64-bit Windows and corrupts every later handle use. Pin the handle-valued calls.
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.OpenThread.restype = wintypes.HANDLE
    k.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.ResumeThread.restype = wintypes.DWORD
    k.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32 = k
    return _k32


def _structs():
    import ctypes
    from ctypes import wintypes

    class _Basic(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(wintypes.ULONG)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("r_ops", "w_ops", "o_ops", "r_xfer", "w_xfer", "o_xfer")]

    class _Extended(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _Basic),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD), ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    return _Extended, _ThreadEntry


def _check(result, name):
    import ctypes
    if not result:
        raise OSError(f"{name} failed: {ctypes.WinError(ctypes.get_last_error())}")
    return result


def create_kill_on_close_job() -> int:
    """Create a Job Object that kills its whole tree when the last handle closes."""
    import ctypes
    k = _kernel32()
    extended, _ = _structs()
    handle = _check(k.CreateJobObjectW(None, None), "CreateJobObjectW")
    info = extended()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    _check(
        k.SetInformationJobObject(handle, _JobObjectExtendedLimitInformation,
                                  ctypes.byref(info), ctypes.sizeof(info)),
        "SetInformationJobObject",
    )
    return handle


def assign_process(job_handle: int, process_handle: int) -> None:
    """Assign a (suspended) process to the job. Fails closed; no breakaway."""
    _check(_kernel32().AssignProcessToJobObject(job_handle, process_handle),
           "AssignProcessToJobObject")


def resume_process_main_thread(pid: int) -> int:
    """Resume the suspended worker. Returns how many threads were resumed (>=1)."""
    import ctypes
    k = _kernel32()
    _, thread_entry = _structs()
    snapshot = _check(k.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0), "CreateToolhelp32Snapshot")
    resumed = 0
    try:
        entry = thread_entry()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                thread = k.OpenThread(_THREAD_SUSPEND_RESUME, False, entry.th32ThreadID)
                if thread:
                    k.ResumeThread(thread)
                    k.CloseHandle(thread)
                    resumed += 1
            ok = k.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        k.CloseHandle(snapshot)
    return resumed


def terminate_job(job_handle: int, exit_code: int = 1) -> None:
    k = _kernel32()
    try:
        k.TerminateJobObject(job_handle, exit_code)
    except OSError:
        pass


def close_handle(job_handle: int) -> None:
    _kernel32().CloseHandle(job_handle)
