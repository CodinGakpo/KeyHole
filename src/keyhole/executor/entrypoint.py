"""Run untrusted code against supplied data and capture one typed output.

Contract with user code:
  * Supplied data files are written into the working directory (read via their filenames).
  * The environment variable ``KEYHOLE_OUTPUT`` names a path; user code writes its single result
    there as JSON. Whatever is at that path when the process exits is the candidate output.
  * stdout/stderr are captured but are NOT the exit channel — only ``KEYHOLE_OUTPUT`` is.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from keyhole.common.models import DataFlowEvent, DataFlowEventKind, Limits, RunRequest
from keyhole.executor.limits import build_preexec

OUTPUT_FILENAME = "__keyhole_output__.json"


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

    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(code_path)],
            cwd=str(work),
            env=env,
            capture_output=True,
            text=True,
            timeout=limits.timeout_seconds,
            preexec_fn=build_preexec(limits),
            check=False,
        )
        exit_code: int | None = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = None
        stdout = e.stdout or "" if isinstance(e.stdout, str) else ""
        stderr = e.stderr or "" if isinstance(e.stderr, str) else ""
        events.append(
            DataFlowEvent(
                kind=DataFlowEventKind.LIMIT_HIT, detail="wall-clock timeout", denied=True
            )
        )

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
    )
