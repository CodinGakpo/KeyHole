"""Control-plane request handling.

Framework-agnostic handlers that map cleanly onto a Lambda + API Gateway HTTP API deployment
(the base hosting choice: scales to zero, ~$0 idle). Each handler takes a parsed request and a
:class:`~mark1.controlplane.store.Store`, so the same logic is exercised in unit tests with the
in-memory store and in the cloud with DynamoDB.

The cloud execution path (submit → Fargate → poll → gate) is wired in M5; this module currently
provides the request/response shapes and the in-memory synchronous path used for local serving.
"""

from __future__ import annotations

import json
import os

from mark1.attest.sign import Signer
from mark1.common.models import RunRequest, RunResult, RunStatus
from mark1.controlplane.cloud_runner import (
    CloudConfig,
    SubmitResult,
    finalize_cloud,
    submit_cloud,
    task_is_stopped,
)
from mark1.controlplane.gate import GateOutcome
from mark1.controlplane.quotas import QuotaPolicy, check_quota
from mark1.controlplane.runner import run_local
from mark1.controlplane.store import Store

_TERMINAL = {RunStatus.SUCCEEDED, RunStatus.WITHHELD, RunStatus.FAILED, RunStatus.TIMEOUT}


def handle_create_run_local(request: RunRequest, store: Store, signer: Signer) -> RunResult:
    """Synchronous local run: execute, gate, persist, return the result.

    In the cloud this splits into an async submit (returns PENDING + run_id) and a later
    finalize step after the Fargate task completes; both reuse the same exit gate.
    """
    outcome: GateOutcome = run_local(request, signer)
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)
    return outcome.result


def handle_get_run(run_id: str, store: Store) -> RunResult | None:
    return store.get_result(run_id)


# --- Async cloud lifecycle (used by the Lambda handler) ---------------------------------------

def submit_run(request: RunRequest, store: Store, config: CloudConfig) -> RunResult:
    """POST /runs: quota-check, launch the Fargate task, persist PENDING + finalize context."""
    quota = check_quota(
        QuotaPolicy(), request.limits, current_concurrency=0,
        total_data_bytes=sum(len(v) for v in request.data.values()),
    )
    if not quota.allowed:
        return RunResult(
            run_id="run-rejected", status=RunStatus.FAILED, withheld_reason=quota.reason
        )

    submit = submit_cloud(request, config)
    result = RunResult(run_id=submit.run_id, status=RunStatus.PENDING)
    store.put_result(result)
    store.put_pending(submit.run_id, {
        "request": request.model_dump(mode="json"),
        "task_arn": submit.task_arn,
        "input_key": submit.input_key,
        "output_key": submit.output_key,
    })
    return result


def get_run(run_id: str, store: Store, config: CloudConfig, signer: Signer) -> RunResult | None:
    """GET /runs/{id}: return a terminal result, or finalize the run if its task has stopped."""
    result = store.get_result(run_id)
    if result is None or result.status in _TERMINAL:
        return result

    ctx = store.get_pending(run_id)
    if ctx is None or not task_is_stopped(config, ctx["task_arn"]):
        return result  # still PENDING

    request = RunRequest.model_validate(ctx["request"])
    submit = SubmitResult(
        run_id=run_id, task_arn=ctx["task_arn"],
        input_key=ctx["input_key"], output_key=ctx["output_key"],
    )
    outcome = finalize_cloud(request, config, signer, submit)
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)
    return outcome.result


# --- API Gateway v2 (HTTP API) entry point ----------------------------------------------------

def lambda_handler(event: dict, context: object | None = None) -> dict:  # pragma: no cover - AWS
    """Route API Gateway v2 HTTP events. Deps are built from Terraform-set environment variables."""
    from mark1.attest.kms_signer import KmsSigner
    from mark1.controlplane.store import DynamoStore

    config = _config_from_env()
    store = DynamoStore(
        runs_table=os.environ["MARK1_RUNS_TABLE"],
        audit_table=os.environ["MARK1_AUDIT_TABLE"],
        region=config.region,
    )
    signer = KmsSigner(key_id=os.environ["MARK1_KMS_KEY_ID"], region=config.region)

    method = event["requestContext"]["http"]["method"]
    path = event["requestContext"]["http"]["path"].rstrip("/")
    parts = [p for p in path.split("/") if p]

    try:
        if method == "POST" and parts == ["runs"]:
            request = RunRequest.model_validate(_body(event))
            return _json(202, submit_run(request, store, config).model_dump(mode="json"))
        if method == "GET" and len(parts) == 2 and parts[0] == "runs":
            return _found(get_run(parts[1], store, config, signer))
        if method == "GET" and len(parts) == 3 and parts[0] == "runs" and parts[2] == "audit":
            return _found(store.get_audit(parts[1]))
        if method == "GET" and len(parts) == 3 and parts[0] == "runs" and parts[2] == "attestation":
            result = store.get_result(parts[1])
            aid = result.attestation_id if result else None
            return _found(store.get_attestation(aid) if aid else None)
        return _json(404, {"error": "no such route"})
    except Exception as exc:  # noqa: BLE001 - surface a clean 500, never a stack trace
        return _json(500, {"error": str(exc)})


def _config_from_env() -> CloudConfig:
    return CloudConfig(
        region=os.environ.get("AWS_REGION", "us-east-1"),
        cluster=os.environ["MARK1_CLUSTER"],
        task_definition=os.environ["MARK1_TASK_DEF"],
        subnet_id=os.environ["MARK1_SUBNET"],
        security_group_id=os.environ["MARK1_SG"],
        bucket=os.environ["MARK1_BUCKET"],
    )


def _body(event: dict) -> dict:
    import base64

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    return json.loads(raw)


def _found(model) -> dict:
    """200 with the model's JSON, or 404 if it is None."""
    return _json(200, model.model_dump(mode="json")) if model else _json(404, {"error": "not found"})


def _json(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }
