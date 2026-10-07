"""Cloud orchestration: run a request on real Fargate and gate the result.

Flow (control-plane side, runs with AWS credentials):
  1. Upload the input bundle {code, data, timeout} to S3.
  2. Presign a GET (input) and a PUT (output) URL — the sandbox uses these, so it needs no
     credentials and the task role stays EMPTY.
  3. ecs.run_task in the private subnet with the run security group (endpoints only, no internet).
  4. Wait for the task to stop; download the output envelope from S3.
  5. Run the SAME exit gate as the local path (validate -> bandwidth -> DLP -> attest).
  6. Clean up the run's S3 objects.

Requires the ``cloud`` extra (boto3). The exit gate itself is provider-agnostic and shared with
``sbx run --local``, so the confidentiality guarantee is identical in the cloud.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

from mark1.attest.sign import Signer
from mark1.common.models import DataFlowEvent, DataFlowEventKind, RunRequest
from mark1.controlplane.budget import BudgetPolicy, Ledger
from mark1.controlplane.gate import GateOutcome, run_exit_gate
from mark1.controlplane.launcher import LauncherConfig, launch
from mark1.executor.entrypoint import ExecResult

_PRESIGN_TTL = 1200  # seconds; must comfortably exceed cold start + run time


@dataclass(frozen=True)
class CloudConfig:
    region: str
    cluster: str
    task_definition: str
    subnet_id: str
    security_group_id: str
    bucket: str
    sandbox_container_name: str = "sandbox"
    prefix: str = "runs"


@dataclass(frozen=True)
class SubmitResult:
    run_id: str
    task_arn: str
    input_key: str
    output_key: str


def submit_cloud(
    request: RunRequest,
    config: CloudConfig,
    run_id: str | None = None,
) -> SubmitResult:
    """Upload the input bundle, presign I/O, and launch the Fargate task. Does not wait.

    Returns the coordinates a later :func:`finalize_cloud` needs. Splitting submit from finalize is
    what lets the Lambda control plane fit inside API Gateway's request timeout: POST launches and
    returns ``pending``; a later GET finalizes once the task has stopped.
    """
    import boto3

    rid = run_id or f"run-{uuid.uuid4().hex}"
    s3 = boto3.client("s3", region_name=config.region)
    ecs = boto3.client("ecs", region_name=config.region)

    base = f"{config.prefix}/{rid}"
    input_key, output_key = f"{base}/input.json", f"{base}/output.json"

    bundle = json.dumps(
        {"code": request.code, "data": request.data, "timeout": request.limits.timeout_seconds}
    ).encode("utf-8")
    s3.put_object(Bucket=config.bucket, Key=input_key, Body=bundle, ContentType="application/json")

    input_url = s3.generate_presigned_url(
        "get_object", Params={"Bucket": config.bucket, "Key": input_key}, ExpiresIn=_PRESIGN_TTL
    )
    output_url = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": config.bucket, "Key": output_key, "ContentType": "application/json"},
        ExpiresIn=_PRESIGN_TTL,
    )

    launcher = LauncherConfig(
        cluster=config.cluster,
        task_definition=config.task_definition,
        private_subnet_id=config.subnet_id,
        security_group_id=config.security_group_id,
        sandbox_container_name=config.sandbox_container_name,
    )
    task_arn = launch(
        launcher,
        rid,
        env={"MARK1_INPUT_URL": input_url, "MARK1_OUTPUT_URL": output_url},
        ecs_client=ecs,
    )
    return SubmitResult(run_id=rid, task_arn=task_arn, input_key=input_key, output_key=output_key)


def task_is_stopped(config: CloudConfig, task_arn: str, ecs_client=None) -> bool:
    """Whether the task has reached STOPPED (safe to finalize)."""
    ecs = ecs_client or _boto("ecs", config.region)
    tasks = ecs.describe_tasks(cluster=config.cluster, tasks=[task_arn]).get("tasks", [])
    return bool(tasks) and tasks[0].get("lastStatus") == "STOPPED"


def finalize_cloud(
    request: RunRequest,
    config: CloudConfig,
    signer: Signer,
    submit: SubmitResult,
    ledger: Ledger | None = None,
    budget: BudgetPolicy | None = None,
) -> GateOutcome:
    """Fetch the stopped task's output, run the exit gate, and clean up its S3 objects."""
    s3 = _boto("s3", config.region)
    ecs = _boto("ecs", config.region)

    stopped_reason = _describe_stop(ecs, config.cluster, submit.task_arn)
    exec_result = _fetch_result(s3, config.bucket, submit.output_key, stopped_reason)
    outcome = run_exit_gate(
        submit.run_id, request, exec_result, signer,
        task_arn=submit.task_arn, ledger=ledger, budget=budget,
    )

    # Best-effort cleanup (the bucket lifecycle also expires these).
    for key in (submit.input_key, submit.output_key):
        try:
            s3.delete_object(Bucket=config.bucket, Key=key)
        except Exception:  # noqa: BLE001 - cleanup must not mask the result
            pass

    return outcome


def run_cloud(
    request: RunRequest,
    config: CloudConfig,
    signer: Signer,
    run_id: str | None = None,
    ledger: Ledger | None = None,
    budget: BudgetPolicy | None = None,
) -> tuple[GateOutcome, str]:
    """Submit, wait for the task to stop, and finalize — the synchronous convenience path."""
    submit = submit_cloud(request, config, run_id=run_id)
    ecs = _boto("ecs", config.region)
    ecs.get_waiter("tasks_stopped").wait(
        cluster=config.cluster,
        tasks=[submit.task_arn],
        WaiterConfig={"Delay": 6, "MaxAttempts": 100},
    )
    outcome = finalize_cloud(request, config, signer, submit, ledger=ledger, budget=budget)
    return outcome, submit.task_arn


def _boto(service: str, region: str):
    import boto3

    return boto3.client(service, region_name=region)


def _describe_stop(ecs, cluster: str, task_arn: str) -> str | None:
    resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
    tasks = resp.get("tasks", [])
    if not tasks:
        return "task not found after stop"
    return tasks[0].get("stoppedReason")


def _fetch_result(s3, bucket: str, output_key: str, stopped_reason: str | None) -> ExecResult:
    """Download the sandbox's output envelope, or synthesize a failure if none was written."""
    events: list[DataFlowEvent] = []
    try:
        body = s3.get_object(Bucket=bucket, Key=output_key)["Body"].read()
    except Exception:  # noqa: BLE001 - no output object => the task produced nothing
        events.append(
            DataFlowEvent(
                kind=DataFlowEventKind.LIMIT_HIT,
                detail=f"no output produced (stopped: {stopped_reason})",
                denied=True,
            )
        )
        return ExecResult(
            exit_code=None,
            output_raw=None,
            stdout="",
            stderr=stopped_reason or "",
            duration_ms=0,
            timed_out=False,
            output_bytes=0,
            events=events,
        )

    env = json.loads(body)
    events.append(
        DataFlowEvent(
            kind=DataFlowEventKind.OUTPUT_WRITTEN, detail=f"{env.get('output_bytes', 0)} bytes"
        )
    )
    return ExecResult(
        exit_code=env.get("exit_code"),
        output_raw=env.get("output_raw"),
        stdout=env.get("stdout_tail", ""),
        stderr=env.get("stderr_tail", ""),
        duration_ms=env.get("duration_ms", 0),
        timed_out=env.get("timed_out", False),
        output_bytes=env.get("output_bytes", 0),
        events=events,
    )
