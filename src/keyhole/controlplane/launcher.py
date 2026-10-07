"""Build and issue the hardened ``ecs.run_task`` call for a sandbox run.

The parameter construction is a pure function (``build_run_task_params``) so the security-
critical choices — private subnet, no public IP, the run security group, the empty task role
baked into the task definition — are unit-testable without AWS. The actual API call lives in
``launch`` and lazily imports boto3 (the ``cloud`` extra).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LauncherConfig:
    cluster: str
    task_definition: str  # its task role is the EMPTY role (enforced in Terraform)
    private_subnet_id: str  # a subnet with NO route to a NAT gateway
    security_group_id: str  # egress limited to the S3/ECR/Logs endpoints; no internet
    sandbox_container_name: str = "sandbox"
    assign_public_ip: bool = False  # MUST stay False: no public IP, no direct internet path


def build_run_task_params(
    config: LauncherConfig,
    run_id: str,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return kwargs for ``ecs.run_task`` encoding every containment choice."""
    environment = [{"name": "KEYHOLE_RUN_ID", "value": run_id}]
    for key, value in (env or {}).items():
        environment.append({"name": key, "value": value})

    return {
        "cluster": config.cluster,
        "taskDefinition": config.task_definition,
        "launchType": "FARGATE",
        "count": 1,
        "networkConfiguration": {
            "awsvpcConfiguration": {
                "subnets": [config.private_subnet_id],
                "securityGroups": [config.security_group_id],
                # DISABLED: the task gets no public IP, so no direct internet path.
                "assignPublicIp": "ENABLED" if config.assign_public_ip else "DISABLED",
            }
        },
        "overrides": {
            "containerOverrides": [
                {"name": config.sandbox_container_name, "environment": environment}
            ]
        },
        "propagateTags": "TASK_DEFINITION",
        "tags": [{"key": "keyhole:run-id", "value": run_id}],
    }


def launch(
    config: LauncherConfig,
    run_id: str,
    env: dict[str, str],
    region: str | None = None,
    ecs_client: Any = None,
) -> str:
    """Call ``ecs.run_task`` and return the task ARN. Requires the ``cloud`` extra (boto3)."""
    if ecs_client is None:
        import boto3  # lazy import: only needed on the cloud path

        ecs_client = boto3.client("ecs", region_name=region)

    params = build_run_task_params(config, run_id, env)
    response = ecs_client.run_task(**params)
    tasks = response.get("tasks", [])
    if not tasks:
        failures = response.get("failures", [])
        raise RuntimeError(f"run_task launched no task: {failures}")
    return tasks[0]["taskArn"]
