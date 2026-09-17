"""In-container probe for the Portmark hardened deployment profile (Section 7 PR 3).

Runs INSIDE the container and reports, as one JSON object on stdout, whether each hardening
property actually holds -- by attempting the operation the property forbids/permits, not by trusting
configuration. The test harness (tests/test_runtime.py) runs this with the full hardening flags and
asserts every property is present, then re-runs with ONE flag removed and asserts that property flips
(calibration), so a passing result cannot be decorative.

Each value is True when the property HOLDS (the deployment is hardened on that axis). Deliberately
dependency-free (stdlib only) so it runs in the minimal runtime image.
"""

from __future__ import annotations

import errno
import json
import os


def _readonly_rootfs() -> bool:
    # A read-only root filesystem refuses writes outside the private writable dir. Attempt to create
    # a file under /app (the app root, mounted read-only) and expect EROFS.
    try:
        fd = os.open("/app/.probe_write", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError as error:
        return error.errno == errno.EROFS
    os.close(fd)
    os.unlink("/app/.probe_write")
    return False


def _private_writable_dir() -> bool:
    # The one private writable working directory (a tmpfs mount) must accept writes.
    path = os.environ.get("PORTMARK_WORKDIR", "/work")
    try:
        probe = os.path.join(path, ".probe_write")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.unlink(probe)
        return True
    except OSError:
        return False


def _non_root() -> bool:
    return os.getuid() != 0


def _no_new_privileges() -> bool:
    # no-new-privileges is reflected in /proc/self/status as NoNewPrivs: 1.
    for line in _proc_status():
        if line.startswith("NoNewPrivs:"):
            return line.split()[1] == "1"
    return False


def _dropped_capabilities() -> bool:
    # Check the BOUNDING set (CapBnd), not the effective set: a non-root process already has an empty
    # effective set regardless of --cap-drop, so CapEff would be a decorative always-true check.
    # --cap-drop ALL empties the bounding set; the default Docker bounding set is non-empty.
    for line in _proc_status():
        if line.startswith("CapBnd:"):
            return int(line.split()[1], 16) == 0
    return False


# The profile commits to a small PID cap. A container INHERITS a large finite pids.max from its
# parent cgroup even without --pids-limit (measured: 67472), so "is it finite?" cannot demonstrate a
# bound -- and comparing to the exact requested value would only prove the flag was applied, not that
# the count is bounded low enough to constrain a fork bomb. Assert the effective cap is at or below a
# ceiling the profile owns: the inherited default fails it, a real --pids-limit passes it.
PIDS_CEILING = 1024


def _pids_limited() -> bool:
    for candidate in ("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"):
        try:
            with open(candidate, encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError:
            continue
        return value.isdigit() and int(value) <= PIDS_CEILING
    return False


def _memory_limited() -> bool:
    # --memory sets a finite cgroup v2 memory.max; without it the value is "max" (unlimited). Unlike
    # pids, a container does NOT inherit a finite memory.max by default, so finiteness is a real signal.
    for candidate in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(candidate, encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError:
            continue
        return value.isdigit()
    return False


def _cpu_limited() -> bool:
    # --cpus sets cgroup v2 cpu.max to "<quota> <period>"; without it the quota field is "max".
    for candidate in ("/sys/fs/cgroup/cpu.max",):
        try:
            with open(candidate, encoding="utf-8") as handle:
                quota = handle.read().split()[0]
        except (OSError, IndexError):
            continue
        return quota != "max"
    # cgroup v1: a finite cfs_quota_us is > 0 (unlimited is -1).
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", encoding="utf-8") as handle:
            return int(handle.read().strip()) > 0
    except (OSError, ValueError):
        return False


def _egress_denied() -> bool:
    # Checked by network-interface PRESENCE, not reachability: with `--network none` the container has
    # only loopback, so no outbound path exists. Reachability would false-green on a CI runner that
    # itself has no egress (identical result to a correctly denied one); interface presence does not.
    return not _has_non_loopback_interface()


def _has_non_loopback_interface() -> bool:
    # /proc/net/dev lists every network device. With `--network none` the only device is `lo`;
    # a normal container also has `eth0`. Device presence is a deterministic signal that does not
    # depend on actual outbound reachability (which would false-green on an egress-less CI runner).
    try:
        with open("/proc/net/dev", encoding="utf-8") as handle:
            devices = [line.split(":", 1)[0].strip() for line in handle.readlines()[2:] if ":" in line]
    except OSError:
        return False
    return any(device and device != "lo" for device in devices)


def _proc_status() -> list[str]:
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            return handle.readlines()
    except OSError:
        return []


PROPERTIES = {
    "readonly_rootfs": _readonly_rootfs,
    "private_writable_dir": _private_writable_dir,
    "non_root": _non_root,
    "no_new_privileges": _no_new_privileges,
    "dropped_capabilities": _dropped_capabilities,
    "pids_limited": _pids_limited,
    "memory_limited": _memory_limited,
    "cpu_limited": _cpu_limited,
    "egress_denied": _egress_denied,
}


def main() -> None:
    print(json.dumps({name: probe() for name, probe in PROPERTIES.items()}))


if __name__ == "__main__":
    main()
