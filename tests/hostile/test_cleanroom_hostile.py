"""Clean-room adversaries: an ungranted provider, cross-principal exfiltration, and tampering.

The bandwidth guarantee must hold across principals: a code-provider running on someone else's
dataset can leak no more than the schema allows, and can only run at all with a matching grant.
"""

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.models import RunStatus
from keyhole.controlplane.cleanroom import DatasetStore, Refusal, run_in_cleanroom, run_on_mock
from keyhole.schema.spec import OutputSchema, SchemaType

# A stand-in sensitive dataset the provider may compute on but must not exfiltrate.
SECRET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(200))
FILES = {"customers.csv": SECRET}
ENUM = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
HONEST = 'import os,json;json.dump("spam",open(os.environ["KEYHOLE_OUTPUT"],"w"))'

POLICY = {"max_bits_per_run": 8.0, "budget_bits": 64.0}  # the owner's exit policy


@pytest.fixture
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def _fixture(tmp_path):
    store = DatasetStore(root=tmp_path)
    ds = store.add("data-owner-acme", FILES, **POLICY)
    grant = store.grant(ds.dataset_id, "partner-ai")
    return store, ds, grant


def test_ungranted_provider_cannot_run(tmp_path, signer):
    store, ds, grant = _fixture(tmp_path)
    # A provider with no matching grant is refused; nothing runs, nothing is released.
    out = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "rival-corp",
                           HONEST,
                           ENUM, signer)
    assert isinstance(out, Refusal)


def test_granted_provider_cannot_exfiltrate_the_owners_data(tmp_path, signer):
    store, ds, grant = _fixture(tmp_path)
    # Authorized to run, but tries to dump the whole dataset — the exit gate withholds it.
    exfil = ('import os,json\n'
             'json.dump(open("customers.csv").read(), open(os.environ["KEYHOLE_OUTPUT"],"w"))')
    out = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "partner-ai", exfil, ENUM, signer)
    assert not isinstance(out, Refusal)
    assert out.result.status is RunStatus.WITHHELD
    assert out.result.output is None
    # Still attested — proving the provider ran the owner's data and nothing left.
    assert out.attestation.data_owner == "data-owner-acme"
    assert verify_attestation(out.attestation, signer.public_key_pem())


def test_tampering_identities_breaks_the_signature(tmp_path, signer):
    store, ds, grant = _fixture(tmp_path)
    out = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "partner-ai",
                           HONEST,
                           ENUM, signer)
    att = out.attestation
    assert verify_attestation(att, signer.public_key_pem())

    for field, forged in (("data_owner", "attacker"), ("code_provider", "someone-else"),
                          ("dataset_id", "ds-forged")):
        original = getattr(att, field)
        setattr(att, field, forged)
        assert not verify_attestation(att, signer.public_key_pem()), f"{field} tamper undetected"
        setattr(att, field, original)  # restore for the next assertion


def test_provider_cannot_widen_the_exit_with_its_own_schema(tmp_path, signer):
    # Attack: hold a valid grant, declare a huge string schema, and carry the dataset out inside
    # a "conforming" answer (hex with spaces slips past the DLP backstop). The owner's per-run
    # cap refuses the schema before anything executes.
    store, ds, grant = _fixture(tmp_path)
    exfil = ('import os,json\nh=open("customers.csv").read().encode().hex()\n'
             'json.dump(" ".join(h[i:i+12] for i in range(0,len(h),12)),'
             ' open(os.environ["KEYHOLE_OUTPUT"],"w"))')
    wide = OutputSchema(type=SchemaType.STRING, max_length=60000)
    out = run_in_cleanroom(store, ds.dataset_id, grant.grant_id, "partner-ai", exfil, wide, signer)
    assert isinstance(out, Refusal)
    assert "allows at most" in out.reason
    assert store.bits_spent(ds) == 0  # refused on the schema alone; nothing ran


def test_budget_belongs_to_the_dataset_not_the_caller(tmp_path, signer):
    # Attack: when one identity runs out of budget, come back as another. The budget is the
    # dataset's, so every provider draws on the same total.
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", FILES, max_bits_per_run=2.5, budget_bits=5.0)  # two 2-bit runs
    grant = store.grant(ds.dataset_id, "*")
    statuses = [
        run_in_cleanroom(store, ds.dataset_id, grant.grant_id, who, HONEST, ENUM,
                         signer).result.status
        for who in ("mallory", "mallory", "mallory-2", "someone-else")
    ]
    assert statuses == [RunStatus.SUCCEEDED] * 2 + [RunStatus.WITHHELD] * 2
    assert store.bits_spent(ds) <= ds.budget_bits


def test_mock_run_shows_everything_and_touches_nothing_real(tmp_path, signer):
    store = DatasetStore(root=tmp_path)
    ds = store.add("acme", FILES, mock={"customers.csv": "mock-user,0@example.test,ssn=000"},
                   **POLICY)
    grant = store.grant(ds.dataset_id, "partner-ai")
    code = ('import os,json\nrows=open("customers.csv").read()\nprint(rows)\n'
            'json.dump("spam",open(os.environ["KEYHOLE_OUTPUT"],"w"))')
    out = run_on_mock(store, ds.dataset_id, grant.grant_id, "partner-ai", code, ENUM)
    assert out.conforms and "mock-user" in out.stdout
    assert "corp.example" not in out.stdout  # the real rows were never materialized
    assert store.bits_spent(ds) == 0  # and nothing was charged
    # Still needs a grant: the mock is the owner's to share.
    assert isinstance(
        run_on_mock(store, ds.dataset_id, grant.grant_id, "rival-corp", code, ENUM), Refusal)
