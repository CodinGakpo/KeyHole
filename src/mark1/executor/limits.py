"""Resource limits applied to the untrusted child process.

These are POSIX ``rlimit`` caps set in the child just before ``exec`` (a defense-in-depth layer;
the primary resource ceiling is the Fargate task sizing). On non-POSIX platforms this degrades
to a no-op preexec function and the wall-clock timeout still applies.
"""

from __future__ import annotations

from collections.abc import Callable

from mark1.common.models import Limits

try:
    import resource  # POSIX only
except ImportError:  # pragma: no cover - non-POSIX fallback
    resource = None  # type: ignore[assignment]


def build_preexec(limits: Limits) -> Callable[[], None] | None:
    """Return a preexec_fn that applies rlimits, or None if unsupported."""
    if resource is None:  # pragma: no cover
        return None

    def _apply() -> None:
        # Address space (memory) cap.
        mem_bytes = limits.memory_mb * 1024 * 1024
        _set(resource.RLIMIT_AS, mem_bytes)
        # CPU-seconds cap (SIGXCPU on breach); defaults to the wall-clock timeout if unset.
        cpu = limits.cpu_seconds if limits.cpu_seconds is not None else limits.timeout_seconds
        _set(resource.RLIMIT_CPU, cpu)
        # Cap the size of any file the code writes.
        _set(resource.RLIMIT_FSIZE, max(limits.max_output_bytes * 4, 1024 * 1024))
        # Limit process/thread creation to blunt fork bombs.
        _set(resource.RLIMIT_NPROC, 256)

    return _apply


def _set(which: int, value: int) -> None:
    assert resource is not None
    try:
        soft, hard = resource.getrlimit(which)
        new_hard = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(which, (min(value, new_hard), new_hard))
    except (ValueError, OSError):  # pragma: no cover - platform-dependent
        pass
