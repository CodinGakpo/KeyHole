"""Local orchestration: execute a request and run it through the exit gate.

This is the in-process path used by ``sbx run --local`` and by tests. The cloud path (Fargate)
reuses the very same exit gate; only the execution substrate differs.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from mark1.attest.sign import Signer
from mark1.common.models import RunRequest
from mark1.controlplane.gate import GateOutcome, run_exit_gate
from mark1.executor.entrypoint import run_code


def run_local(
    request: RunRequest,
    signer: Signer,
    run_id: str | None = None,
    workdir: str | Path | None = None,
) -> GateOutcome:
    """Run ``request`` locally and return the gated, attested outcome."""
    rid = run_id or f"run-{uuid.uuid4().hex}"
    exec_result = run_code(request, workdir=workdir)
    return run_exit_gate(rid, request, exec_result, signer)
