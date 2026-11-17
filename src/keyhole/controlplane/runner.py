"""Local orchestration: execute a request and run it through the exit gate.

This is the in-process path used by ``sbx run --local`` and by tests. The cloud path (Fargate)
reuses the very same exit gate; only the execution substrate differs.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from keyhole.attest.sign import Signer
from keyhole.common.models import RunRequest
from keyhole.controlplane.budget import BudgetPolicy, Ledger, check_budget
from keyhole.controlplane.gate import GateOutcome, run_exit_gate
from keyhole.executor.entrypoint import ExecResult, run_code
from keyhole.schema.bandwidth import run_channel_bits


def _not_run(detail: str) -> ExecResult:
    return ExecResult(exit_code=None, output_raw=None, stdout="", stderr=detail,
                      duration_ms=0, timed_out=False, output_bytes=0, isolation="not-run")


def run_local(
    request: RunRequest,
    signer: Signer,
    run_id: str | None = None,
    workdir: str | Path | None = None,
    ledger: Ledger | None = None,
    budget: BudgetPolicy | None = None,
    budget_key: str | None = None,
) -> GateOutcome:
    """Run ``request`` locally and return the gated, attested outcome."""
    rid = run_id or f"run-{uuid.uuid4().hex}"
    channel = run_channel_bits(request.output_schema)
    if (
        ledger is not None
        and budget is not None
        and not check_budget(budget, ledger, budget_key or request.principal, channel).allowed
    ):
        # Out of budget: the code does not run at all, so it has nothing to signal with.
        exec_result = _not_run("not executed: budget exhausted")
    else:
        try:
            exec_result = run_code(request, workdir=workdir)
        except Exception as exc:  # noqa: BLE001 - a crash must still be gated, charged, attested
            exec_result = _not_run(f"executor error: {type(exc).__name__}")
    return run_exit_gate(
        rid, request, exec_result, signer, ledger=ledger, budget=budget, budget_key=budget_key
    )
