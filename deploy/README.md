# Portmark hardened deployment profile

Section 7 of the threat model draws a hard line: Portmark's isolated executor is a
**resource-bounded, hard-deadline worker, not a hostile-code sandbox**. Portmark guarantees
authorization, argument constraints, deadlines, durable effect identity + reconciliation, bounded
output, safe paths, and truthful auditing. **Containment of a hostile tool is the deployment's job.**

This directory is the *executable, tested* form of that deployment side. When you register a
side-effecting isolated tool, Portmark's startup gate (Section 7 PR 2b) requires you to acknowledge
an `IsolationProfile` whose `mechanism` is `EXTERNAL_CONTAINER`. **This profile is what that
acknowledgement means** — the concrete container settings that make `EXTERNAL_CONTAINER` true.

The properties below are verified by `deploy/verify_profile.py`, which runs *inside* the container
and checks each one by attempting the operation it forbids or permits — not by trusting the flags.
`tests/test_runtime.py::SafePathCapabilityTests`-adjacent deployment tests run the probe with the
full flag set (every property must hold) and then re-run with one flag removed (that property must
flip), so a green result cannot be decorative.

## Run (Docker)

```sh
docker run --rm \
  --read-only \
  --tmpfs /work:rw,noexec,nosuid,nodev,size=64m \
  --env PORTMARK_WORKDIR=/work \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1.0 \
  --network none \
  portmark:latest \
  python -m portmark ...        # your entrypoint
```

| Flag | Property it enforces | Probe |
| --- | --- | --- |
| `--read-only` | read-only root filesystem | write under `/app` → `EROFS` |
| `--tmpfs /work:...` + `PORTMARK_WORKDIR` | one private writable dir | write to `/work` → succeeds |
| `--user 1000:1000` | non-root | `getuid() != 0` |
| `--security-opt no-new-privileges` | no privilege escalation | `/proc/self/status` `NoNewPrivs: 1` |
| `--cap-drop ALL` | no Linux capabilities | `/proc/self/status` `CapEff: 0000000000000000` |
| `--pids-limit 128` | bounded process count | cgroup `pids.max` is finite **and ≤ 1024** (a container inherits a large finite `pids.max`, so the ceiling — not mere finiteness — is what proves a bound) |
| `--network none` | default-deny egress | only the `lo` interface exists |

`--network none` is the strictest egress stance. If the tool legitimately needs outbound access,
replace it with a dedicated network namespace behind an **egress proxy / firewall that default-denies
and allowlists** only the required destinations — do not fall back to the host network.

The image already runs as a non-root user (`USER portmark`) and writes nothing outside `/work`, so
`--read-only` holds without app changes. `deploy/verify_profile.py` is baked into the image so you
can confirm a live deployment:

```sh
docker run --rm --read-only --tmpfs /work:rw --env PORTMARK_WORKDIR=/work \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --network none portmark:latest python /app/deploy/verify_profile.py
# -> {"readonly_rootfs": true, "private_writable_dir": true, "non_root": true,
#     "no_new_privileges": true, "dropped_capabilities": true, "pids_limited": true,
#     "egress_denied": true}
```

## Compose

`deploy/docker-compose.hardened.yml` encodes the same properties declaratively:

```sh
docker compose -f deploy/docker-compose.hardened.yml run --rm runner
```

## Kubernetes

The equivalent `securityContext` / `Pod` spec:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault          # keeps openat2 available; see the caveat below
resources:
  limits:
    memory: 512Mi
    cpu: "1"
    # pids limit is set cluster-side via the kubelet `podPidsLimit` / a LimitRange
volumes:
  - name: work
    emptyDir:
      medium: Memory
      sizeLimit: 64Mi
# NetworkPolicy: default-deny egress, allowlist only what the tool needs.
```

## Interaction with the safe-path capability (important)

The capability-based safe-path helper (`portmark.safe_paths.SafeRoot`) resolves paths with
`openat2(RESOLVE_BENEATH)`, which a **seccomp policy can block**. Docker's and Kubernetes'
`RuntimeDefault` seccomp profiles *allow* `openat2`, so the settings above keep it working. If you
install a custom seccomp profile, it **must allow `openat2`** — otherwise `SafeRoot.from_runtime()`
refuses (it never degrades to a race-vulnerable check), and any tool that needs a safe root fails
closed. `deploy/verify_profile.py` does not itself exercise `openat2`; run the Portmark test suite
inside your candidate profile if you customize seccomp.
