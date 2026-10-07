"""Multi-party clean room: dataset registry, grants, authorization, and a two-principal run."""

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.hashing import sha256_of_mapping
from keyhole.controlplane.cleanroom import (
    DatasetStore,
    Refusal,
    authorize,
    run_in_cleanroom,
)
from keyhole.schema.spec import OutputSchema, SchemaType

_FILES = {"customers.csv": "a,spam\nb,ham\n"}
_SCHEMA = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"])
_CLASSIFY = 'import os,json;json.dump("spam",open(os.environ["KEYHOLE_OUTPUT"],"w"))'


@pytest.fixture
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def test_dataset_round_trip_and_hash(tmp_path):
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", _FILES)
    assert store.get(ds.dataset_id).owner == "acme"
    assert ds.data_sha256 == sha256_of_mapping(_FILES)
    assert store.load_files(ds.dataset_id) == _FILES
    assert [d.dataset_id for d in store.list()] == [ds.dataset_id]


def test_authorize_matrix(tmp_path):
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", _FILES)
    g_named = store.grant(ds.dataset_id, "partner-ai")
    g_any = store.grant(ds.dataset_id, "*")
    other = store.add("acme", {"x": "y"})
    g_other = store.grant(other.dataset_id, "partner-ai")

    assert authorize(ds, g_named, "partner-ai").allowed
    assert not authorize(ds, g_named, "intruder").allowed
    assert authorize(ds, g_any, "anyone").allowed
    assert not authorize(ds, g_other, "partner-ai").allowed  # grant is for a different dataset
    assert not authorize(None, g_named, "partner-ai").allowed
    assert not authorize(ds, None, "partner-ai").allowed


def test_run_in_cleanroom_binds_both_identities(tmp_path, signer):
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", _FILES)
    grant = store.grant(ds.dataset_id, "partner-ai")

    outcome = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "partner-ai",
                               _CLASSIFY, _SCHEMA, signer)
    assert not isinstance(outcome, Refusal)
    att = outcome.attestation
    assert att.data_owner == "acme"
    assert att.code_provider == "partner-ai"
    assert att.dataset_id == ds.dataset_id
    assert att.data_sha256 == ds.data_sha256  # bound to exactly the registered dataset
    assert verify_attestation(att, signer.public_key_pem())
    # The audit trail carries the identities too.
    assert outcome.audit.data_owner == "acme" and outcome.audit.code_provider == "partner-ai"


def test_ungranted_provider_is_refused_without_running(tmp_path, signer):
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", _FILES)
    grant = store.grant(ds.dataset_id, "partner-ai")

    outcome = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "intruder",
                               _CLASSIFY, _SCHEMA, signer)
    assert isinstance(outcome, Refusal)
    assert "intruder" in outcome.reason
