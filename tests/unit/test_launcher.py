"""Launcher param construction: the containment choices are encoded correctly."""

from mark1.controlplane.launcher import LauncherConfig, build_run_task_params


def _config(**kw) -> LauncherConfig:
    base = dict(
        cluster="mark1",
        task_definition="mark1-sandbox:1",
        private_subnet_id="subnet-private",
        security_group_id="sg-run",
    )
    base.update(kw)
    return LauncherConfig(**base)


def test_no_public_ip_by_default():
    params = build_run_task_params(_config(), "run-1")
    vpc = params["networkConfiguration"]["awsvpcConfiguration"]
    assert vpc["assignPublicIp"] == "DISABLED"


def test_uses_private_subnet_and_run_sg():
    params = build_run_task_params(_config(), "run-1")
    vpc = params["networkConfiguration"]["awsvpcConfiguration"]
    assert vpc["subnets"] == ["subnet-private"]
    assert vpc["securityGroups"] == ["sg-run"]


def test_single_fargate_task():
    params = build_run_task_params(_config(), "run-1")
    assert params["launchType"] == "FARGATE"
    assert params["count"] == 1


def test_run_id_and_env_are_injected():
    params = build_run_task_params(
        _config(),
        "run-42",
        env={"MARK1_INPUT_URL": "https://s3/in", "MARK1_OUTPUT_URL": "https://s3/out"},
    )
    env = params["overrides"]["containerOverrides"][0]["environment"]
    as_map = {e["name"]: e["value"] for e in env}
    assert as_map["MARK1_RUN_ID"] == "run-42"
    assert as_map["MARK1_INPUT_URL"] == "https://s3/in"
    assert as_map["MARK1_OUTPUT_URL"] == "https://s3/out"
