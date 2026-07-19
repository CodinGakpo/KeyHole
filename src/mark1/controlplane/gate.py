"""The exit gate.

This is where a run's raw output is turned into either a released, attested answer or a
withheld run. The ordering encodes the whole thesis:

    validate against the declared schema  →  (nothing conforming ⇒ release nothing)
    compute the exit bandwidth
    run the secondary DLP backstop
    build and sign the attestation (whether released or withheld)

The bandwidth bound is the guarantee; the DLP scan is a secondary backstop. The gate is pure
logic with no cloud dependency, so it is fully unit-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from mark1.attest.record import Attestation
from mark1.attest.sign import Signer, sign_attestation
from mark1.controlplane.budget import BudgetPolicy, Ledger, check_budget
from mark1.common.hashing import (
    canonical_json_bytes,
    sha256_hex,
    sha256_of_json,
    sha256_of_mapping,
)
from mark1.common.models import (
    AuditRecord,
    DataFlowEventKind,
    RunRequest,
    RunResult,
    RunStatus,
    utcnow,
)
from mark1.dlp import scan_pii, scan_secrets
from mark1.executor.entrypoint import ExecResult
from mark1.schema.bandwidth import bandwidth_bits
from mark1.schema.validate import validate_output


@dataclass
class GateOutcome:
    result: RunResult
    attestation: Attestation
    audit: AuditRecord


def run_exit_gate(
    run_id: str,
    request: RunRequest,
    exec_result: ExecResult,
    signer: Signer,
    task_arn: str | None = None,
    ledger: Ledger | None = None,
    budget: BudgetPolicy | None = None,
    now: datetime | None = None,
) -> GateOutcome:
    """Inspect a run's output and produce a released-or-withheld, attested outcome.

    When both ``ledger`` and ``budget`` are supplied, a conforming output is additionally checked
    against the caller's cumulative exit-bandwidth budget and withheld if releasing it would exceed
    the cap (see :mod:`mark1.controlplane.budget`). With either unset, behavior is unchanged.
    """
    schema = request.output_schema
    bandwidth = bandwidth_bits(schema)
    cumulative_exit_bits: float | None = None

    code_sha = sha256_hex(request.code)
    data_sha = sha256_of_mapping(request.data)
    schema_sha = sha256_of_json(schema.model_dump(mode="json"))

    egress_attempts = sum(
        1 for e in exec_result.events if e.kind is DataFlowEventKind.EGRESS_ATTEMPT
    )
    egress_denied = sum(
        1
        for e in exec_result.events
        if e.kind is DataFlowEventKind.EGRESS_ATTEMPT and e.denied
    )

    released = False
    output_value = None
    output_sha: str | None = None
    dlp_findings = 0
    status: RunStatus
    withheld_reason: str | None = None

    if exec_result.timed_out:
        status = RunStatus.TIMEOUT
        withheld_reason = "run exceeded its time limit"
    elif exec_result.exit_code not in (0, None):
        status = RunStatus.FAILED
        withheld_reason = f"code exited with status {exec_result.exit_code}"
    elif exec_result.output_raw is None:
        status = RunStatus.FAILED
        withheld_reason = "code produced no output at MARK1_OUTPUT"
    elif exec_result.output_bytes > request.limits.max_output_bytes:
        status = RunStatus.WITHHELD
        withheld_reason = (
            f"output {exec_result.output_bytes} bytes exceeds limit "
            f"{request.limits.max_output_bytes}"
        )
    else:
        try:
            candidate = json.loads(exec_result.output_raw)
        except json.JSONDecodeError:
            status = RunStatus.WITHHELD
            withheld_reason = "output is not valid JSON"
        else:
            validation = validate_output(candidate, schema)
            if not validation.ok:
                status = RunStatus.WITHHELD
                withheld_reason = "output does not conform to the declared schema: " + "; ".join(
                    validation.errors
                )
            else:
                serialized = canonical_json_bytes(candidate).decode("utf-8")
                findings = scan_secrets(serialized) + scan_pii(serialized)
                dlp_findings = len(findings)
                if findings:
                    status = RunStatus.WITHHELD
                    withheld_reason = (
                        "secondary DLP backstop flagged the output "
                        f"({dlp_findings} finding(s))"
                    )
                elif ledger is not None and budget is not None and not (
                    decision := check_budget(budget, ledger, request.principal, bandwidth, now)
                ).allowed:
                    status = RunStatus.WITHHELD
                    withheld_reason = decision.reason
                    cumulative_exit_bits = decision.spent_before
                else:
                    status = RunStatus.SUCCEEDED
                    released = True
                    output_value = candidate
                    output_sha = sha256_hex(canonical_json_bytes(candidate))
                    if ledger is not None and budget is not None:
                        ledger.record(request.principal, bandwidth, now or utcnow())
                        cumulative_exit_bits = ledger.spent(
                            request.principal, budget.window_seconds, now or utcnow()
                        )

    attestation = Attestation(
        run_id=run_id,
        code_sha256=code_sha,
        data_sha256=data_sha,
        schema_sha256=schema_sha,
        output_sha256=output_sha,
        output=output_value,
        exit_bandwidth_bits=bandwidth,
        egress_attempts=egress_attempts,
        egress_denied=egress_denied,
        exit_code=exec_result.exit_code,
        released=released,
    )
    attestation = sign_attestation(attestation, signer)

    result = RunResult(
        run_id=run_id,
        status=status,
        output=output_value,
        withheld_reason=withheld_reason,
        exit_bandwidth_bits=bandwidth,
        cumulative_exit_bits=cumulative_exit_bits,
        exit_code=exec_result.exit_code,
        duration_ms=exec_result.duration_ms,
        attestation_id=attestation.attestation_id,
    )

    audit = AuditRecord(
        run_id=run_id,
        status=status,
        code_sha256=code_sha,
        data_sha256=data_sha,
        schema_sha256=schema_sha,
        output_sha256=output_sha,
        exit_bandwidth_bits=bandwidth,
        cumulative_exit_bits=cumulative_exit_bits,
        egress_attempts=egress_attempts,
        egress_denied=egress_denied,
        dlp_findings=dlp_findings,
        events=list(exec_result.events),
        attestation_id=attestation.attestation_id,
        task_arn=task_arn,
    )

    return GateOutcome(result=result, attestation=attestation, audit=audit)
