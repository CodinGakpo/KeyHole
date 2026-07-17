"""In-container runner for the sandbox image (standard library only, no credentials, no network).

Contract (kept identical to the local executor):
  * Inputs are placed at ``/sandbox/inputs/`` by a scoped loader sidecar BEFORE this runs. The
    sandbox container itself has the EMPTY task role and no network, so it never touches S3 — the
    loader (with a read-only, this-run-only role) fetches inputs; an uploader sidecar ships the
    output back. This preserves the no-reachable-credentials guarantee.
  * ``/sandbox/inputs/code.py`` is the untrusted program; other files there are supplied data.
  * The program writes its single result to ``$MARK1_OUTPUT`` as JSON. That file is the only
    thing the uploader returns; stdout/stderr go to CloudWatch and are NOT an exit channel.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

INPUTS = Path("/sandbox/inputs")
WORK = Path("/sandbox/work")


def main() -> int:
    output_path = os.environ.get("MARK1_OUTPUT", "/sandbox/__mark1_output__.json")
    WORK.mkdir(parents=True, exist_ok=True)

    # Copy supplied data files next to the code, flattening names into the work dir.
    for item in INPUTS.iterdir():
        if item.name == "code.py":
            continue
        shutil.copy(item, WORK / item.name)

    code = INPUTS / "code.py"
    if not code.exists():
        print("no code.py supplied", file=sys.stderr)
        return 2

    env = {"MARK1_OUTPUT": output_path, "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-I", str(code)],
        cwd=str(WORK),
        env=env,
        check=False,
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
