"""In-container runner for the sandbox image (standard library only; no credentials, no boto3).

The sandbox has an EMPTY task role and no internet route. It receives its inputs and returns its
output through two *presigned* S3 URLs passed in the environment — pre-authorized by the control
plane, so the container itself needs no AWS credentials. The S3 gateway endpoint policy limits the
whole subnet to the artifacts bucket's ``runs/`` prefix (plus ECR's layer bucket for image pulls),
so a presigned URL for someone else's bucket leads nowhere.

The untrusted code runs as a separate user (uid 10002) in its own run directory, with a scrubbed
environment: it cannot read this runner's environment (the URLs), signal it, or touch the output
envelope. The runner stays root (with only the capabilities the task definition leaves it) so it
can always kill the child's whole process group at the deadline.

Contract:
  * KEYHOLE_INPUT_URL   - presigned GET for a JSON bundle {code, data:{name:contents}, timeout}.
  * KEYHOLE_OUTPUT_URL  - presigned PUT; we upload a JSON envelope describing the run's raw result.
  * The user program writes its single result to $KEYHOLE_OUTPUT (a file). That file's contents are
    the only exit the caller ever receives (after the control-plane exit gate validates them).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

WORK = Path("/sandbox/work")
RUN_DIR = WORK / "run"  # the only place the untrusted code can write
OUTPUT_FILE = RUN_DIR / "__keyhole_output__.json"
CODE_UID = 10002
_TAIL = 4096  # cap stdout/stderr we echo back to logs


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - presigned S3 URL
        return resp.read()


def _put(url: str, body: bytes) -> None:
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30):  # noqa: S310 - presigned S3 URL
        pass


def _tail(f) -> str:
    size = f.seek(0, 2)
    f.seek(max(0, size - _TAIL))
    return f.read().decode("utf-8", errors="replace")


def main() -> int:
    input_url = os.environ.pop("KEYHOLE_INPUT_URL")
    output_url = os.environ.pop("KEYHOLE_OUTPUT_URL")

    bundle = json.loads(_get(input_url))
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    for name, contents in bundle.get("data", {}).items():
        (RUN_DIR / Path(name).name).write_text(contents)
    code_path = RUN_DIR / "__keyhole_code__.py"
    code_path.write_text(bundle["code"])
    timeout = int(bundle.get("timeout", 60))

    env = {
        "KEYHOLE_OUTPUT": str(OUTPUT_FILE),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    separate = os.getuid() == 0  # in the task: yes; when run by hand: same user, no isolation
    if separate:
        os.chown(RUN_DIR, CODE_UID, CODE_UID)
        for path in RUN_DIR.iterdir():
            os.chown(path, CODE_UID, CODE_UID)

    start = time.monotonic()
    timed_out = False
    out = tempfile.TemporaryFile(dir=WORK)  # opened by the runner; the child only inherits the fd
    err = tempfile.TemporaryFile(dir=WORK)
    proc = subprocess.Popen(
        [sys.executable, "-I", str(code_path)],
        cwd=str(RUN_DIR),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=out,
        stderr=err,
        user=CODE_UID if separate else None,
        group=CODE_UID if separate else None,
        extra_groups=[] if separate else None,
        start_new_session=True,
    )
    try:
        exit_code: int | None = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = None
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # the child and anything it forked
        except ProcessLookupError:
            pass
        proc.wait()
    stdout, stderr = _tail(out), _tail(err)

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
    print(f"keyhole: run complete, exit={exit_code}, output_bytes={output_bytes}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
