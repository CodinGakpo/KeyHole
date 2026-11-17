"""Control-plane request handling.

Framework-agnostic handlers that map cleanly onto a Lambda + API Gateway HTTP API deployment
(the base hosting choice: scales to zero, ~$0 idle). Each handler takes a parsed request and a
:class:`~keyhole.controlplane.store.Store`, so the same logic is exercised in unit tests with the
in-memory store and in the cloud with DynamoDB.

Cloud lifecycle: POST /runs submits (launches Fargate, returns pending); GET /runs/{id}
finalizes once the task stops, through the same exit gate as the local path.
"""

from __future__ import annotations

import hmac
import json
import os
import time
import traceback

from keyhole.attest.sign import Signer
from keyhole.common.hashing import sha256_hex, sha256_of_mapping
from keyhole.common.models import RunRequest, RunResult, RunStatus
from keyhole.controlplane.cloud_datasets import DynamoDatasetStore
from keyhole.controlplane.cloud_runner import (
    CloudConfig,
    SubmitResult,
    finalize_cloud,
    stop_task,
    submit_cloud,
    task_is_stopped,
)
from keyhole.controlplane.gate import GateOutcome
from keyhole.controlplane.quotas import QuotaPolicy, check_quota
from keyhole.controlplane.runner import run_local
from keyhole.controlplane.store import Store
from keyhole.schema.bandwidth import run_channel_bits

_TERMINAL = {RunStatus.SUCCEEDED, RunStatus.WITHHELD, RunStatus.FAILED, RunStatus.TIMEOUT}
_START_GRACE_SECONDS = 300  # image pull + cold start, on top of the run's own timeout


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

class Refused(Exception):
    """A run refused before anything launched (HTTP 403). The reason never depends on the data."""


def submit_run(
    request: RunRequest,
    store: Store,
    config: CloudConfig,
    datasets: DynamoDatasetStore | None = None,
    grant: str | None = None,
) -> RunResult:
    """POST /runs: admit, quota-check, launch the Fargate task, persist PENDING + context.

    With ``request.dataset_id`` the run is a clean-room run: the data comes from the owner's
    registry (never from the caller), the owner's per-run cap applies, and the dataset's budget is
    charged before anything launches. Without it, the caller supplies the data and is its owner.
    """
    cumulative: float | None = None
    if request.dataset_id is not None:
        if datasets is None:
            raise Refused("datasets are not configured on this deployment")
        ds = datasets.get(request.dataset_id)
        if ds is None:
            raise Refused("no such dataset")
        admission = datasets.admit(
            ds, grant or "", request.principal, run_channel_bits(request.output_schema)
        )
        if not admission.allowed:
            raise Refused(admission.reason or "not authorized")
        cumulative = admission.spent_after
        request = request.model_copy(update={
            "data": datasets.load_files(ds.dataset_id), "data_owner": ds.owner,
        })
    else:
        request = request.model_copy(update={"data_owner": None})

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
    # Keep what finalize needs — schema, limits, identities, and the input *hashes* — but not the
    # code or the data: the only copy of those is the S3 bundle, deleted when the run finalizes.
    store.put_pending(submit.run_id, {
        "request": request.model_copy(update={"code": "", "data": {}}).model_dump(mode="json"),
        "code_sha256": sha256_hex(request.code),
        "data_sha256": sha256_of_mapping(request.data),
        "deadline": time.time() + request.limits.timeout_seconds + _START_GRACE_SECONDS,
        "cumulative_exit_bits": cumulative,
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
    if ctx is None:
        return result
    if not task_is_stopped(config, ctx["task_arn"]):
        if time.time() > float(ctx.get("deadline", float("inf"))):
            stop_task(config, ctx["task_arn"])  # finalized as "no output" on a later poll
        return result  # still PENDING

    request = RunRequest.model_validate(ctx["request"])
    submit = SubmitResult(
        run_id=run_id, task_arn=ctx["task_arn"],
        input_key=ctx["input_key"], output_key=ctx["output_key"],
    )
    outcome = finalize_cloud(
        request, config, signer, submit,
        input_hashes=(ctx["code_sha256"], ctx["data_sha256"]),
        precharged_cumulative_bits=ctx.get("cumulative_exit_bits"),
    )
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)
    store.delete_pending(run_id)
    return outcome.result


def authorized(
    headers: dict, owner_route: bool, api_key: str | None, owner_key: str | None
) -> bool:
    """Bearer-token check. Fails closed: with no key configured, nothing is allowed.

    Owner routes — the audit (the real outcome of a run, which the caller must not see) and
    registering datasets and grants — take a different key from the one callers hold.
    """
    expected = owner_key if owner_route else api_key
    if not expected:
        return False
    supplied = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
    return hmac.compare_digest(supplied.encode(), f"Bearer {expected}".encode())


# --- API Gateway v2 (HTTP API) entry point ----------------------------------------------------

def lambda_handler(event: dict, context: object | None = None) -> dict:  # pragma: no cover - AWS
    """Route API Gateway v2 HTTP events. Deps are built from Terraform-set environment variables."""
    import boto3

    from keyhole.attest.kms_signer import KmsSigner
    from keyhole.controlplane.store import DynamoStore

    config = _config_from_env()
    store = DynamoStore(
        runs_table=os.environ["KEYHOLE_RUNS_TABLE"],
        audit_table=os.environ["KEYHOLE_AUDIT_TABLE"],
        region=config.region,
    )
    datasets = DynamoDatasetStore(
        boto3.resource("dynamodb", region_name=config.region).Table(
            os.environ["KEYHOLE_RUNS_TABLE"]
        ),
        boto3.client("s3", region_name=config.region),
        config.bucket,
    )
    signer = KmsSigner(key_id=os.environ["KEYHOLE_KMS_KEY_ID"], region=config.region)

    method = event["requestContext"]["http"]["method"]
    path = event["requestContext"]["http"]["path"].rstrip("/")
    parts = [p for p in path.split("/") if p]

    try:
        body = _body(event)
    except ValueError:  # includes json.JSONDecodeError and bad base64
        return _json(400, {"error": "request body is not valid JSON"})
    return route(method, parts, event.get("headers") or {}, body, store, datasets, config, signer)


def route(
    method: str,
    parts: list[str],
    headers: dict,
    body: dict,
    store: Store,
    datasets: DynamoDatasetStore,
    config: CloudConfig,
    signer: Signer,
) -> dict:
    """Dispatch one API request. Separate from ``lambda_handler`` so it is testable without AWS."""
    owner_route = (len(parts) == 3 and parts[0] == "runs" and parts[2] == "audit") or (
        method == "POST" and parts[:1] == ["datasets"]
    )
    if not authorized(headers, owner_route,
                      os.environ.get("KEYHOLE_API_KEY"), os.environ.get("KEYHOLE_OWNER_KEY")):
        return _json(401, {"error": "unauthorized"})

    try:
        if method == "POST" and parts == ["runs"]:
            grant = body.pop("grant", None)
            request = RunRequest.model_validate(body)
            try:
                result = submit_run(request, store, config, datasets, grant)
            except Refused as refusal:
                return _json(403, {"error": str(refusal)})
            return _json(202, result.model_dump(mode="json"))
        if method == "POST" and parts == ["datasets"]:
            ds = datasets.add(
                body["owner"], body["files"],
                max_bits_per_run=float(body["max_bits_per_run"]),
                budget_bits=float(body["budget_bits"]),
                description=body.get("description", ""), mock=body.get("mock"),
            )
            return _json(201, ds.model_dump(mode="json"))
        if method == "POST" and len(parts) == 3 and parts[0] == "datasets" and parts[2] == "grants":
            if datasets.get(parts[1]) is None:
                return _json(404, {"error": "no such dataset"})
            return _json(201, datasets.grant(parts[1], body["grantee"]).model_dump(mode="json"))
        if method == "GET" and len(parts) == 2 and parts[0] == "datasets":
            # What a caller needs to write code: description, file names, mock rows, policy.
            found = datasets.get(parts[1])
            if found is None:
                return _json(404, {"error": "no such dataset"})
            return _json(200, {
                **found.model_dump(mode="json", exclude={"data_sha256"}),
                "mock": datasets.load_mock(found.dataset_id),
                "bits_spent": datasets.bits_spent(found.dataset_id),
            })
        if method == "GET" and len(parts) == 2 and parts[0] == "runs":
            return _found(get_run(parts[1], store, config, signer))
        if method == "GET" and len(parts) == 3 and parts[0] == "runs" and parts[2] == "audit":
            return _found(store.get_audit(parts[1]))
        if method == "GET" and len(parts) == 3 and parts[0] == "runs" and parts[2] == "attestation":
            stored = store.get_result(parts[1])
            aid = stored.attestation_id if stored else None
            return _found(store.get_attestation(aid) if aid else None)
        return _json(404, {"error": "no such route"})
    except Exception:  # noqa: BLE001 - the detail goes to the logs, never to the caller:
        traceback.print_exc()  # exception text can quote values the untrusted code chose
        return _json(500, {"error": "internal error"})


def _config_from_env() -> CloudConfig:
    return CloudConfig(
        region=os.environ.get("AWS_REGION", "us-east-1"),
        cluster=os.environ["KEYHOLE_CLUSTER"],
        task_definition=os.environ["KEYHOLE_TASK_DEF"],
        subnet_id=os.environ["KEYHOLE_SUBNET"],
        security_group_id=os.environ["KEYHOLE_SG"],
        bucket=os.environ["KEYHOLE_BUCKET"],
    )


def _body(event: dict) -> dict:
    import base64

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    return json.loads(raw)


def _found(model) -> dict:
    """200 with the model's JSON, or 404 if it is None."""
    if model is None:
        return _json(404, {"error": "not found"})
    return _json(200, model.model_dump(mode="json"))


def _json(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }
