"""The async cloud lifecycle: submit returns PENDING, finalize-on-GET runs the exit gate.

Exercises `submit_run`/`get_run` with an InMemoryStore and fake ECS/S3 (the cloud_runner helpers
are monkeypatched), so the routing + persistence logic is tested without AWS.
"""

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.common.models import Limits, RunRequest, RunStatus
from keyhole.controlplane import app as app_mod
from keyhole.controlplane.app import get_run, submit_run
from keyhole.controlplane.cloud_runner import CloudConfig, SubmitResult
from keyhole.controlplane.gate import run_exit_gate
from keyhole.controlplane.store import InMemoryStore
from keyhole.executor.entrypoint import ExecResult
from keyhole.schema.spec import OutputSchema, SchemaType

_CONFIG = CloudConfig(
    region="us-east-1", cluster="c", task_definition="td",
    subnet_id="s", security_group_id="sg", bucket="b",
)


def _request(output="spam") -> RunRequest:
    return RunRequest(
        code="print()", data={"d.txt": "secret"},
        output_schema=OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"]),
        limits=Limits(timeout_seconds=10),
    )


@pytest.fixture
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def _patch_cloud(monkeypatch, *, produced_output, stopped: dict):
    """Fake the three boto3-backed helpers; `stopped` toggles when a task appears STOPPED."""
    def fake_submit(request, config, run_id=None):
        return SubmitResult(run_id="run-abc", task_arn="arn:task/abc",
                            input_key="runs/run-abc/in.json", output_key="runs/run-abc/out.json")

    def fake_stopped(config, task_arn, ecs_client=None):
        return stopped["value"]

    def fake_finalize(request, config, signer, submit, ledger=None, budget=None):
        ex = ExecResult(0, produced_output, "", "", 5, False,
                        len(produced_output) if produced_output else 0, [])
        return run_exit_gate(submit.run_id, request, ex, signer, task_arn=submit.task_arn)

    monkeypatch.setattr(app_mod, "submit_cloud", fake_submit)
    monkeypatch.setattr(app_mod, "task_is_stopped", fake_stopped)
    monkeypatch.setattr(app_mod, "finalize_cloud", fake_finalize)


def test_submit_returns_pending_and_persists_context(monkeypatch):
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped={"value": False})
    store = InMemoryStore()
    result = submit_run(_request(), store, _CONFIG)

    assert result.status is RunStatus.PENDING
    assert store.get_result("run-abc").status is RunStatus.PENDING
    assert store.get_pending("run-abc")["task_arn"] == "arn:task/abc"


def test_get_while_running_stays_pending(monkeypatch, signer):
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped={"value": False})
    store = InMemoryStore()
    submit_run(_request(), store, _CONFIG)

    result = get_run("run-abc", store, _CONFIG, signer)
    assert result.status is RunStatus.PENDING


def test_get_after_stop_finalizes_and_releases(monkeypatch, signer):
    stopped = {"value": False}
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped=stopped)
    store = InMemoryStore()
    submit_run(_request(), store, _CONFIG)

    stopped["value"] = True  # the Fargate task has now stopped
    result = get_run("run-abc", store, _CONFIG, signer)
    assert result.status is RunStatus.SUCCEEDED
    assert result.output == "spam"
    assert store.get_attestation(result.attestation_id) is not None
    # A second GET returns the stored terminal result without re-finalizing.
    assert get_run("run-abc", store, _CONFIG, signer).status is RunStatus.SUCCEEDED


def test_get_after_stop_withholds_exfiltration(monkeypatch, signer):
    stopped = {"value": True}
    _patch_cloud(monkeypatch, produced_output='"the whole dataset"', stopped=stopped)
    store = InMemoryStore()
    submit_run(_request(), store, _CONFIG)

    result = get_run("run-abc", store, _CONFIG, signer)
    assert result.status is RunStatus.WITHHELD
    assert result.output is None


def test_oversized_data_is_rejected_by_quota(monkeypatch):
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped={"value": False})
    store = InMemoryStore()
    req = RunRequest(
        code="x", data={"big.csv": "x" * (11 * 1024 * 1024)},
        output_schema=OutputSchema(type=SchemaType.BOOLEAN),
    )
    result = submit_run(req, store, _CONFIG)
    assert result.status is RunStatus.FAILED
    assert "exceeds" in result.withheld_reason
