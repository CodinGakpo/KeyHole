"""Assemble dist/controlplane.zip for the control-plane Lambda.

The Lambda handler is `mark1.controlplane.app.lambda_handler`. It needs the `mark1` package plus its
runtime deps (pydantic, cryptography) as **Lambda-compatible (manylinux) wheels** — building on a
non-Lambda host would otherwise bundle wheels for the wrong platform. boto3 is provided by the
Lambda runtime, so it is intentionally excluded to keep the zip small.

Usage:  python scripts/build_lambda.py   (or: make lambda-zip)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "lambda"
DIST = ROOT / "dist"
ZIP = DIST / "controlplane"  # shutil.make_archive appends .zip
RUNTIME_DEPS = ["pydantic", "cryptography"]
LAMBDA_PY = "3.12"


def main() -> int:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)
    DIST.mkdir(exist_ok=True)

    # Vendored deps as manylinux wheels for the Lambda runtime (not this host's platform).
    subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--platform", "manylinux2014_x86_64",
            "--python-version", LAMBDA_PY,
            "--implementation", "cp",
            "--only-binary=:all:",
            "--target", str(BUILD),
            *RUNTIME_DEPS,
        ],
        check=True,
    )

    # The mark1 package itself (source; pure Python).
    shutil.copytree(ROOT / "src" / "mark1", BUILD / "mark1")

    if (DIST / "controlplane.zip").exists():
        (DIST / "controlplane.zip").unlink()
    shutil.make_archive(str(ZIP), "zip", root_dir=BUILD)
    size_mb = (DIST / "controlplane.zip").stat().st_size / 1e6
    print(f"built {DIST / 'controlplane.zip'} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
