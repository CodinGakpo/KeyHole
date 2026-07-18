"""In-container runner for the sandbox image (standard library only; no credentials, no boto3).

The sandbox has an EMPTY task role and no internet route. It receives its inputs and returns its
output through two *presigned* S3 URLs passed in the environment — pre-authorized by the control
plane, so the container itself needs no AWS credentials. It can reach only our bucket (the S3
gateway endpoint policy enforces that), and only these two keys in practice.

Contract:
  * MARK1_INPUT_URL   - presigned GET for a JSON bundle {code, data:{name:contents}, timeout}.
  * MARK1_OUTPUT_URL  - presigned PUT; we upload a JSON envelope describing the run's raw result.
  * The user program writes its single result to $MARK1_OUTPUT (a file). That file's contents are
    the only exit the caller ever receives (after the control-plane exit gate validates them).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

WORK = Path("/sandbox/work")
OUTPUT_FILE = WORK / "__mark1_output__.json"
_TAIL = 4096  # cap stdout/stderr we echo back to logs


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - presigned S3 URL
        return resp.read()


def _put(url: str, body: bytes) -> None:
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30):  # noqa: S310 - presigned S3 URL
        pass


def main() -> int:
    input_url = os.environ["MARK1_INPUT_URL"]
    output_url = os.environ["MARK1_OUTPUT_URL"]

    bundle = json.loads(_get(input_url))
    WORK.mkdir(parents=True, exist_ok=True)

    for name, contents in bundle.get("data", {}).items():
        (WORK / Path(name).name).write_text(contents)
    code_path = WORK / "__mark1_code__.py"
    code_path.write_text(bundle["code"])
    timeout = int(bundle.get("timeout", 60))

    env = {
        "MARK1_OUTPUT": str(OUTPUT_FILE),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(code_path)],
            cwd=str(WORK),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        exit_code: int | None = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = None
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""

    duration_ms = int((time.monotonic() - start) * 1000)

    output_raw: str | None = None
    output_bytes = 0
    if OUTPUT_FILE.exists():
        data = OUTPUT_FILE.read_bytes()
        output_bytes = len(data)
        output_raw = data.decode("utf-8", errors="replace")

    envelope = {
        "output_raw": output_raw,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output_bytes": output_bytes,
        "duration_ms": duration_ms,
        "stdout_tail": stdout[-_TAIL:],
        "stderr_tail": stderr[-_TAIL:],
    }
    _put(output_url, json.dumps(envelope).encode("utf-8"))
    print(f"mark1: run complete, exit={exit_code}, output_bytes={output_bytes}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
