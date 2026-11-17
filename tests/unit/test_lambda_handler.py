"""The async cloud lifecycle: submit returns PENDING, finalize-on-GET runs the exit gate.

Exercises `submit_run`/`get_run` with an InMemoryStore and fake ECS/S3 (the cloud_runner helpers
are monkeypatched), so the routing + persistence logic is tested without AWS.
"""

import io
import json
from decimal import Decimal

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.hashing import sha256_of_mapping
from keyhole.common.models import Limits, RunRequest, RunStatus
from keyhole.controlplane import app as app_mod
from keyhole.controlplane.app import authorized, get_run, submit_run
from keyhole.controlplane.cloud_runner import CloudConfig, SubmitResult, _fetch_result
from keyhole.controlplane.gate import run_exit_gate
from keyhole.controlplane.store import DynamoStore, InMemoryStore
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

    def fake_finalize(request, config, signer, submit, ledger=None, budget=None,
                      input_hashes=None, precharged_cumulative_bits=None):
        ex = ExecResult(0, produced_output, "", "", 5, False,
                        len(produced_output) if produced_output else 0, [])
        return run_exit_gate(submit.run_id, request, ex, signer, task_arn=submit.task_arn,
                             input_hashes=input_hashes)

    monkeypatch.setattr(app_mod, "submit_cloud", fake_submit)
    monkeypatch.setattr(app_mod, "task_is_stopped", fake_stopped)
    monkeypatch.setattr(app_mod, "finalize_cloud", fake_finalize)
    monkeypatch.setattr(app_mod, "stop_task", lambda config, arn: stopped.update(stop_called=True))


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


def test_private_data_is_not_persisted_and_pending_is_cleaned_up(monkeypatch, signer):
    stopped = {"value": False}
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped=stopped)
    store = InMemoryStore()
    submit_run(_request(), store, _CONFIG)

    # The pending record must not hold the caller's code or data — only their hashes.
    assert "secret" not in str(store.get_pending("run-abc"))

    stopped["value"] = True
    get_run("run-abc", store, _CONFIG, signer)
    att = store.get_attestation(store.get_result("run-abc").attestation_id)
    assert att.data_sha256 == sha256_of_mapping({"d.txt": "secret"})  # still bound to the inputs
    assert store.get_pending("run-abc") is None


def test_a_task_past_its_deadline_is_stopped(monkeypatch, signer):
    stopped = {"value": False}
    _patch_cloud(monkeypatch, produced_output='"spam"', stopped=stopped)
    store = InMemoryStore()
    submit_run(_request(), store, _CONFIG)
    store.get_pending("run-abc")["deadline"] = 0  # long past

    assert get_run("run-abc", store, _CONFIG, signer).status is RunStatus.PENDING
    assert stopped.get("stop_called")


def test_api_auth_fails_closed_and_separates_owner_from_caller():
    caller, owner = {"Authorization": "Bearer c-key"}, {"authorization": "Bearer o-key"}
    assert authorized(caller, False, "c-key", "o-key")
    assert authorized(owner, True, "c-key", "o-key")
    assert not authorized(caller, True, "c-key", "o-key")  # a caller cannot read the audit
    assert not authorized({}, False, "c-key", "o-key")
    assert not authorized(caller, False, None, None)  # no key configured: nothing is allowed


class _FakeTable:
    """Mimics boto3's Table: every number read back is a Decimal."""

    def __init__(self):
        self.items = {}

    def put_item(self, Item):  # noqa: N803 - boto3's spelling
        self.items[Item["run_id"]] = json.loads(json.dumps(Item), parse_float=Decimal,
                                                parse_int=Decimal)

    def get_item(self, Key):  # noqa: N803
        item = self.items.get(Key["run_id"])
        return {"Item": item} if item else {}


def test_numeric_output_still_verifies_after_the_dynamodb_round_trip(signer):
    store = DynamoStore.__new__(DynamoStore)
    store._runs, store._audit = _FakeTable(), _FakeTable()
    request = RunRequest(code="x", output_schema=OutputSchema.from_dict(
        {"type": "object", "properties": {"n": {"type": "integer", "minimum": 0, "maximum": 100},
                                          "score": {"type": "number"}}}))
    ex = ExecResult(0, '{"n": 42, "score": 0.5}', "", "", 5, False, 20, [])
    outcome = run_exit_gate("run-n", request, ex, signer)
    store.put_result(outcome.result)
    store.put_attestation(outcome.attestation)
    store.put_audit(outcome.audit)

    assert store.get_result("run-n").output == {"n": 42, "score": 0.5}
    back = store.get_attestation(outcome.attestation.attestation_id)
    assert verify_attestation(back, signer.public_key_pem())
    assert store.get_audit("run-n").status is RunStatus.SUCCEEDED


@pytest.mark.parametrize("body", [
    b"not json", b"[1, 2]", b'{"duration_ms": "SECRET-ROW"}', b'{"duration_ms": 1e99}',
    b'{"exit_code": 99999999999999999999}', b'{"output_raw": 5}',
])
def test_forged_result_envelope_is_just_a_failed_run(body):
    class S3:
        def get_object(self, Bucket, Key):  # noqa: N803
            return {"Body": io.BytesIO(body)}

    ex = _fetch_result(S3(), "b", "k", None)
    assert ex.output_raw is None and ex.duration_ms == 0
