"""Cloud clean room: owner-registered datasets, grants, the per-run cap and an atomic budget.

Drives the real API router (``app.route``) with in-memory fakes for DynamoDB and S3 and the
cloud launch helpers patched out, so routing, auth, admission and the receipt are tested without
AWS.
"""

from __future__ import annotations

import io
import json
from decimal import Decimal

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.controlplane import app as app_mod
from keyhole.controlplane.cloud_datasets import DynamoDatasetStore
from keyhole.controlplane.cloud_runner import CloudConfig, SubmitResult
from keyhole.controlplane.gate import run_exit_gate
from keyhole.controlplane.store import InMemoryStore
from keyhole.executor.entrypoint import ExecResult
from keyhole.schema.bandwidth import run_channel_bits
from keyhole.schema.spec import OutputSchema

CONFIG = CloudConfig(region="us-east-1", cluster="c", task_definition="td",
                     subnet_id="s", security_group_id="sg", bucket="b")
CALLER = {"Authorization": "Bearer caller-key"}
OWNER = {"Authorization": "Bearer owner-key"}
FILES = {"customers.csv": "alice,123-45-6789\nbob,987-65-4321\n"}
LABEL = {"type": "enum", "choices": ["spam", "ham", "other"]}  # 2 bits per run
HONEST = 'import os,json;json.dump("spam",open(os.environ["KEYHOLE_OUTPUT"],"w"))'


class ConditionFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    """Just enough of boto3's Table: numbers come back as Decimal; the ledger update is atomic."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    def put_item(self, Item):  # noqa: N803 - boto3's spelling
        self.items[Item["run_id"]] = json.loads(json.dumps(Item), parse_float=Decimal)

    def get_item(self, Key):  # noqa: N803
        item = self.items.get(Key["run_id"])
        return {"Item": item} if item else {}

    def update_item(self, Key, UpdateExpression, ConditionExpression,  # noqa: N803
                    ExpressionAttributeValues, ReturnValues):  # noqa: N803
        assert UpdateExpression == "ADD spent :b"
        item = self.items.setdefault(Key["run_id"], {"run_id": Key["run_id"]})
        values = ExpressionAttributeValues
        if "spent" in item and not item["spent"] <= values[":room"]:
            raise ConditionFailed()
        item["spent"] = item.get("spent", Decimal(0)) + values[":b"]
        return {"Attributes": {"spent": item["spent"]}}


class FakeS3:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put_object(self, Bucket, Key, Body, ContentType=None):  # noqa: N803
        self.objects[Key] = Body

    def get_object(self, Bucket, Key):  # noqa: N803
        return {"Body": io.BytesIO(self.objects[Key])}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("KEYHOLE_API_KEY", "caller-key")
    monkeypatch.setenv("KEYHOLE_OWNER_KEY", "owner-key")
    launched: list = []

    def fake_submit(request, config, run_id=None):
        launched.append(request)
        rid = f"run-{len(launched)}"
        return SubmitResult(run_id=rid, task_arn=f"arn:task/{rid}",
                            input_key=f"runs/{rid}/in", output_key=f"runs/{rid}/out")

    def fake_finalize(request, config, signer, submit, ledger=None, budget=None,
                      input_hashes=None, precharged_cumulative_bits=None):
        ex = ExecResult(0, '"spam"', "", "", 5, False, 6, [], isolation="fargate")
        return run_exit_gate(submit.run_id, request, ex, signer, task_arn=submit.task_arn,
                             input_hashes=input_hashes,
                             precharged_cumulative_bits=precharged_cumulative_bits)

    monkeypatch.setattr(app_mod, "submit_cloud", fake_submit)
    monkeypatch.setattr(app_mod, "task_is_stopped", lambda config, arn: True)
    monkeypatch.setattr(app_mod, "finalize_cloud", fake_finalize)
    signer = Ed25519Signer.generate()
    store, datasets = InMemoryStore(), DynamoDatasetStore(FakeTable(), FakeS3(), "b")

    def call(method, path, headers, body=None):
        parts = [p for p in path.split("/") if p]
        resp = app_mod.route(method, parts, headers, dict(body or {}), store, datasets,
                             CONFIG, signer)
        return resp["statusCode"], json.loads(resp["body"])

    return call, launched, store, datasets, signer


def _register(call, **policy):
    body = {"owner": "acme", "files": FILES, "description": "customers",
            "mock": {"customers.csv": "mock,000-00-0000\n"},
            "max_bits_per_run": 4, "budget_bits": 5, **policy}
    status, ds = call("POST", "/datasets", OWNER, body)
    assert status == 201
    status, grant = call("POST", f"/datasets/{ds['dataset_id']}/grants", OWNER,
                         {"grantee": "*"})
    assert status == 201
    return ds["dataset_id"], grant["grant_id"]


def _run(call, ds_id, grant, principal="agent", schema=LABEL, **extra):
    return call("POST", "/runs", CALLER, {"code": HONEST, "output_schema": schema,
                                          "principal": principal, "dataset_id": ds_id,
                                          "grant": grant, **extra})


def test_registering_data_needs_the_owner_key(env):
    call, *_ = env
    status, _ = call("POST", "/datasets", CALLER, {"owner": "x", "files": {},
                                                   "max_bits_per_run": 1, "budget_bits": 1})
    assert status == 401


def test_caller_sees_description_mock_and_policy_but_never_the_data(env):
    call, *_ = env
    ds_id, _ = _register(call)
    status, view = call("GET", f"/datasets/{ds_id}", CALLER)
    assert status == 200
    assert view["mock"] == {"customers.csv": "mock,000-00-0000\n"}
    assert view["max_bits_per_run"] == 4 and view["bits_spent"] == 0
    assert "123-45-6789" not in json.dumps(view)


def test_dataset_run_uses_the_owners_bytes_and_identity(env):
    call, launched, store, _, signer = env
    ds_id, grant = _register(call)
    # A caller trying to inject its own data, or claim to be the owner, is ignored.
    status, pending = _run(call, ds_id, grant, data={"customers.csv": "fake"},
                           data_owner="mallory")
    assert status == 202 and pending["status"] == "pending"
    assert launched[0].data == FILES and launched[0].data_owner == "acme"
    assert "123-45-6789" not in json.dumps(store.get_pending(pending["run_id"]))

    status, done = call("GET", f"/runs/{pending['run_id']}", CALLER)
    assert done["status"] == "succeeded" and done["output"] == "spam"
    att = store.get_attestation(done["attestation_id"])
    assert att.data_owner == "acme" and att.dataset_id == ds_id
    per_run = run_channel_bits(OutputSchema.from_dict(LABEL))
    assert att.cumulative_exit_bits == pytest.approx(per_run)
    assert verify_attestation(att, signer.public_key_pem())


def test_schema_wider_than_the_owner_allows_is_refused_before_launch(env):
    call, launched, *_ = env
    ds_id, grant = _register(call)
    status, body = _run(call, ds_id, grant, schema={"type": "string", "max_length": 60000})
    assert status == 403 and "allows at most" in body["error"]
    assert launched == []


def test_budget_is_atomic_per_dataset_and_identity_switching_does_not_help(env):
    call, launched, _, datasets, _ = env
    ds_id, grant = _register(call)  # 5-bit budget, 2-bit runs: two runs
    codes = [_run(call, ds_id, grant, principal=p)[0]
             for p in ("mallory", "mallory", "mallory-2", "someone-else")]
    assert codes == [202, 202, 403, 403]
    assert len(launched) == 2
    assert datasets.bits_spent(ds_id) <= 5


def test_wrong_grant_or_grantee_is_refused(env):
    call, launched, *_ = env
    ds_id, _ = _register(call)
    _, named = call("POST", f"/datasets/{ds_id}/grants", OWNER, {"grantee": "partner"})
    assert _run(call, ds_id, "grant-forged")[0] == 403
    assert _run(call, ds_id, named["grant_id"], principal="intruder")[0] == 403
    assert _run(call, ds_id, named["grant_id"], principal="partner")[0] == 202
    assert len(launched) == 1


def test_audit_route_is_owner_only(env):
    call, *_ = env
    ds_id, grant = _register(call)
    _, pending = _run(call, ds_id, grant)
    call("GET", f"/runs/{pending['run_id']}", CALLER)
    assert call("GET", f"/runs/{pending['run_id']}/audit", CALLER)[0] == 401
    assert call("GET", f"/runs/{pending['run_id']}/audit", OWNER)[0] == 200


def test_patched_helpers_match_the_real_signatures():
    # The router tests patch the cloud helpers; make sure the real ones accept the same calls.
    import inspect

    from keyhole.controlplane import cloud_runner

    params = inspect.signature(cloud_runner.finalize_cloud).parameters
    assert {"input_hashes", "precharged_cumulative_bits"} <= set(params)
