"""M3 containment: the sandbox has no side exit (Docker-based, gated).

Runs the two-container harness (sandbox-posture probe on an internal-only network + egress-proxy
sidecar bridging to the internet) and asserts the probe proves containment: direct egress blocked,
proxy denies unlisted hosts, proxy permits only the allowlisted one.

Gated behind MARK1_DOCKER=1 (and needs Docker + internet), so it stays out of the default/offline
CI run. Enable with:  MARK1_DOCKER=1 python -m pytest tests/integration -q
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_COMPOSE = Path(__file__).resolve().parents[2] / "harness" / "egress" / "docker-compose.yml"

pytestmark = pytest.mark.skipif(
    not os.environ.get("MARK1_DOCKER") or shutil.which("docker") is None,
    reason="requires Docker + internet; set MARK1_DOCKER=1 to run",
)


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(_COMPOSE), *args],
        capture_output=True,
        text=True,
        timeout=360,
    )


def test_no_side_exit():
    try:
        result = _compose(
            "up", "--build", "--abort-on-container-exit", "--exit-code-from", "probe"
        )
        assert result.returncode == 0, (
            "containment probe failed:\n" + result.stdout + result.stderr
        )
        assert "CONTAINMENT: PROVEN" in result.stdout + result.stderr
    finally:
        _compose("down", "--remove-orphans")
