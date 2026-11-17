"""Where the untrusted process actually runs: the local isolation backends.

Keyhole's guarantee is the exit gate, and the gate only means something if the code has no other
way out. This module picks the box:

* ``bwrap`` — Linux bubblewrap: no network, a private PID namespace, a read-only view of the
  system, the user's home and Keyhole's own state (signing key, datasets, ledger) hidden, and
  only the run's working directory writable. The default wherever ``bwrap`` is installed.
* ``docker`` — a throwaway container (``KEYHOLE_DOCKER_IMAGE``, default ``python:3.12-slim``):
  no network, read-only root, every capability dropped, no privilege escalation, memory and PID
  limits, running as the invoking user with only the run directory mounted. Opt-in, for hosts
  without bubblewrap (macOS) or when code needs packages that are baked into an image.
* ``none`` — a plain subprocess with rlimits. The code can reach the network and read the
  user's files, so the exit gate is the *only* thing being demonstrated. Used when nothing better
  is available, and says so loudly.

Select with ``KEYHOLE_SANDBOX=bwrap|docker|none``; unset means bwrap if installed, else none. The
backend that ran is recorded in the audit record and signed into the attestation, so a receipt
from an unsandboxed run cannot pass for a sandboxed one. Hosted sandboxes (Fargate today) plug in
at the same seam: anything that turns a request into an ``ExecResult``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

from keyhole.common.config import home_dir
from keyhole.common.models import Limits

DEFAULT_DOCKER_IMAGE = "python:3.12-slim"

MAX_PROCESSES = 256

# Runs inside the box, before the untrusted code: cap process creation, then become the code.
# Inside bwrap's user namespace the count covers only the sandbox, so this bounds a fork bomb
# without being tripped by whatever else the user happens to be running.
_TRAMPOLINE = (
    "import os, resource, sys\n"
    f"resource.setrlimit(resource.RLIMIT_NPROC, ({MAX_PROCESSES}, {MAX_PROCESSES}))\n"
    "os.execv(sys.executable, [sys.executable, '-I', sys.argv[1]])\n"
)


def choose_backend() -> str:
    wanted = os.environ.get("KEYHOLE_SANDBOX", "").strip().lower()
    if wanted not in ("", "bwrap", "docker", "none"):
        raise ValueError(f"KEYHOLE_SANDBOX must be 'bwrap', 'docker' or 'none', got {wanted!r}")
    if wanted == "none":
        return "none"
    if wanted == "docker":
        if not shutil.which("docker"):
            raise RuntimeError("KEYHOLE_SANDBOX=docker but the docker CLI is not installed")
        return "docker"
    if shutil.which("bwrap"):
        return "bwrap"
    if wanted == "bwrap":
        raise RuntimeError("KEYHOLE_SANDBOX=bwrap but bubblewrap is not installed")
    warnings.warn(
        "keyhole: bubblewrap (bwrap) not found; running untrusted code as a plain subprocess "
        "with network and file access. Only the exit gate is enforced.",
        RuntimeWarning,
        stacklevel=2,
    )
    return "none"


def command(
    backend: str, work: Path, code_path: Path, limits: Limits, name: str = "keyhole-run"
) -> list[str]:
    """The argv that runs ``code_path`` under ``backend``. ``name`` names a docker container."""
    if backend == "none":
        return [sys.executable, "-I", str(code_path)]
    if backend == "docker":
        image = os.environ.get("KEYHOLE_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)
        fsize = max(limits.max_output_bytes * 4, 1024 * 1024)
        return [
            "docker", "run", "--rm", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(MAX_PROCESSES),
            "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
            "--ulimit", f"fsize={fsize}:{fsize}",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:size=16m",
            # :z lets SELinux hosts mount the run directory; it relabels only that temp dir.
            "-v", f"{work}:{work}:z", "-w", str(work),
            "-e", "KEYHOLE_OUTPUT", "-e", "PYTHONDONTWRITEBYTECODE=1",
            image, "python", "-I", str(code_path),
        ]

    hidden = {str(Path.home()), str(home_dir()), "/tmp", "/var/tmp", "/root"}
    argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for path in sorted(hidden):
        if os.path.isdir(path):
            argv += ["--tmpfs", path]
    # The interpreter (and its venv) may live under a hidden directory: put it back, read-only.
    for prefix in sorted({sys.prefix, sys.base_prefix}):
        argv += ["--ro-bind", prefix, prefix]
    argv += ["--bind", str(work), str(work), "--chdir", str(work),
             "--", sys.executable, "-I", "-c", _TRAMPOLINE, str(code_path)]
    return argv


def stop(backend: str, name: str) -> None:
    """Leave nothing of a timed-out run behind: killing the docker CLI leaves the container."""
    if backend == "docker":
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)
