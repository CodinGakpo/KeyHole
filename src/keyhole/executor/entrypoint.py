"""Run untrusted code against supplied data and capture one typed output.

Contract with user code:
  * Supplied data files are written into the working directory (read via their filenames).
  * The environment variable ``KEYHOLE_OUTPUT`` names a path; user code writes its single result
    there as JSON. Whatever is at that path when the process exits is the candidate output.
  * stdout/stderr are captured but are NOT the exit channel — only ``KEYHOLE_OUTPUT`` is.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from keyhole.common.models import DataFlowEvent, DataFlowEventKind, Limits, RunRequest
from keyhole.executor import sandbox
from keyhole.executor.limits import build_preexec

OUTPUT_FILENAME = "__keyhole_output__.json"
_LOG_TAIL = 64 * 1024  # bytes of stdout/stderr kept for the owner's audit


@dataclass
class ExecResult:
    """Raw result of running the code — before the exit gate inspects it."""

    exit_code: int | None
    output_raw: str | None  # contents of KEYHOLE_OUTPUT, or None if not written
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    output_bytes: int
    events: list[DataFlowEvent] = field(default_factory=list)
    isolation: str = "none"  # which box ran the code: "bwrap", "none", "fargate", ...


def run_code(request: RunRequest, workdir: str | Path | None = None) -> ExecResult:
    """Execute ``request.code`` locally in a subprocess and capture its typed output."""
    if workdir is None:
        with tempfile.TemporaryDirectory(prefix="keyhole-run-") as tmp:
            return _run_in(request, Path(tmp))
    return _run_in(request, Path(workdir))


def _run_in(request: RunRequest, work: Path) -> ExecResult:
    limits: Limits = request.limits
    events: list[DataFlowEvent] = []

    # Materialize supplied data files.
    for name, contents in request.data.items():
        safe = work / Path(name).name  # flatten; never let a name escape the workdir
        safe.write_text(contents)
        events.append(
            DataFlowEvent(kind=DataFlowEventKind.FILE_ACCESS, detail=f"supplied:{safe.name}")
        )

    code_path = work / "__keyhole_code__.py"
    code_path.write_text(request.code)
    output_path = work / OUTPUT_FILENAME

    env = {
        "KEYHOLE_OUTPUT": str(output_path),
        "PATH": "/usr/bin:/bin",
        # Deliberately no AWS/credential env; strip metadata hints as a belt-and-suspenders.
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    backend = sandbox.choose_backend()
    name = f"keyhole-{uuid.uuid4().hex[:12]}"
    # rlimits apply to the process we start: for docker that is the CLI, which the container's own
    # limits replace (an address-space cap would break the Go binary, not the code).
    preexec = (
        None if backend == "docker"
        else build_preexec(limits, limit_processes=backend == "none")
    )
    start = time.monotonic()
    timed_out = False
    # stdout/stderr go to files, not pipes: the child's RLIMIT_FSIZE then bounds them (a pipe
    # would be read into our memory without limit), and a stray grandchild cannot hold us open.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(
            sandbox.command(backend, work, code_path, limits, name),
            cwd=str(work),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            preexec_fn=preexec,
            start_new_session=True,  # its own process group, so a timeout can kill the lot
        )
        try:
            exit_code: int | None = proc.wait(timeout=limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            sandbox.stop(backend, name)
            timed_out = True
            exit_code = None
            events.append(
                DataFlowEvent(
                    kind=DataFlowEventKind.LIMIT_HIT, detail="wall-clock timeout", denied=True
                )
            )
        stdout, stderr = _tail(out), _tail(err)

    duration_ms = int((time.monotonic() - start) * 1000)

    output_raw: str | None = None
    output_bytes = 0
    if output_path.exists():
        data = output_path.read_bytes()
        output_bytes = len(data)
        output_raw = data.decode("utf-8", errors="replace")
        events.append(
            DataFlowEvent(
                kind=DataFlowEventKind.OUTPUT_WRITTEN, detail=f"{output_bytes} bytes"
            )
        )

    return ExecResult(
        exit_code=exit_code,
        output_raw=output_raw,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        timed_out=timed_out,
        output_bytes=output_bytes,
        events=events,
        isolation=backend,
    )


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the child and everything it spawned (under bwrap the namespace dies with it)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError):
        proc.kill()
    proc.wait()


def _tail(f) -> str:
    """The last ``_LOG_TAIL`` bytes of a captured stream, decoded leniently (it is untrusted)."""
    size = f.seek(0, 2)
    f.seek(max(0, size - _LOG_TAIL))
    return f.read().decode("utf-8", errors="replace")
