"""The exit gate.

This is where a run's raw output is turned into either a released, attested answer or a
withheld run. The ordering encodes the whole thesis:

    check the caller's cumulative budget  →  (exhausted ⇒ withhold, whatever the code did)
    validate against the declared schema  →  (nothing conforming ⇒ release nothing)
    compute the exit bandwidth
    run the secondary DLP backstop
    charge the budget for the run (released or not)
    build and sign the attestation (whether released or withheld)

The caller sees only "released + value" or one opaque "withheld": timeouts, crashes, exit codes
and validation details go to the data owner's audit record, never to the caller, so code cannot
signal through *how* it fails. A run therefore reveals at most log2(N + 1) bits (see
:func:`keyhole.schema.bandwidth.run_channel_bits`), and that is what the budget charges.

The bandwidth bound is the guarantee; the DLP scan is a secondary backstop. The gate is pure
logic with no cloud dependency, so it is fully unit-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from keyhole.attest.record import Attestation
from keyhole.attest.sign import Signer, sign_attestation
from keyhole.common.hashing import (
    canonical_json_bytes,
    sha256_hex,
    sha256_of_json,
    sha256_of_mapping,
)
from keyhole.common.models import (
    AuditRecord,
    DataFlowEventKind,
    RunRequest,
    RunResult,
    RunStatus,
    utcnow,
)
from keyhole.controlplane.budget import BudgetPolicy, Ledger, check_budget
from keyhole.dlp import scan_pii, scan_secrets
from keyhole.executor.entrypoint import ExecResult
from keyhole.schema.bandwidth import bandwidth_bits, run_channel_bits
from keyhole.schema.validate import validate_output

# The one reason a caller ever sees for a non-release outcome.
NOT_RELEASED = "not released (the data owner's audit log has the details)"


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

    When both ``ledger`` and ``budget`` are supplied, every run is charged
    ``run_channel_bits(schema)`` against the principal's cumulative budget, and once the budget
    cannot cover a run, the run is withheld regardless of what the code did (see
    :mod:`keyhole.controlplane.budget`). With either unset, no budget applies.
    """
    schema = request.output_schema
    bandwidth = bandwidth_bits(schema)
    channel = run_channel_bits(schema)
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

    # Budget first: an exhausted caller learns nothing from the run, so the decision must not depend
    # on the code's behavior. The decision itself depends only on the caller's own run history.
    decision = (
        check_budget(budget, ledger, request.principal, channel, now)
        if ledger is not None and budget is not None
        else None
    )
    if decision is not None and not decision.allowed:
        status = RunStatus.WITHHELD
        withheld_reason = decision.reason
        cumulative_exit_bits = decision.spent_before
    elif exec_result.timed_out:
        status = RunStatus.TIMEOUT
        withheld_reason = "run exceeded its time limit"
    elif exec_result.exit_code not in (0, None):
        status = RunStatus.FAILED
        withheld_reason = f"code exited with status {exec_result.exit_code}"
    elif exec_result.output_raw is None:
        status = RunStatus.FAILED
        withheld_reason = "code produced no output at KEYHOLE_OUTPUT"
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
                else:
                    status = RunStatus.SUCCEEDED
                    released = True
                    output_value = candidate
                    output_sha = sha256_hex(canonical_json_bytes(candidate))

    # Charge every run the budget admitted — a non-release outcome is information too.
    if ledger is not None and budget is not None and decision is not None and decision.allowed:
        ledger.record(request.principal, channel, now or utcnow())
        cumulative_exit_bits = ledger.spent(
            request.principal, budget.window_seconds, now or utcnow()
        )

    # Caller-visible fields: released + value, or one opaque "withheld". An exhausted budget is
    # reported as such — it follows from the caller's own history, not from the code.
    budget_refused = decision is not None and not decision.allowed
    caller_status = RunStatus.SUCCEEDED if released else RunStatus.WITHHELD
    caller_reason = None if released else (withheld_reason if budget_refused else NOT_RELEASED)
    caller_exit_code = exec_result.exit_code if released else None

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
        exit_code=caller_exit_code,
        released=released,
        data_owner=request.data_owner,
        code_provider=request.principal,
        dataset_id=request.dataset_id,
    )
    attestation = sign_attestation(attestation, signer)

    result = RunResult(
        run_id=run_id,
        status=caller_status,
        output=output_value,
        withheld_reason=caller_reason,
        exit_bandwidth_bits=bandwidth,
        cumulative_exit_bits=cumulative_exit_bits,
        exit_code=caller_exit_code,
        duration_ms=exec_result.duration_ms,
        attestation_id=attestation.attestation_id,
    )

    audit = AuditRecord(
        run_id=run_id,
        status=status,
        withheld_reason=withheld_reason,
        exit_code=exec_result.exit_code,
        code_sha256=code_sha,
        data_sha256=data_sha,
        schema_sha256=schema_sha,
        output_sha256=output_sha,
        data_owner=request.data_owner,
        code_provider=request.principal,
        dataset_id=request.dataset_id,
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
