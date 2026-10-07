"""Clean-room adversaries: an ungranted provider, cross-principal exfiltration, and tampering.

The bandwidth guarantee must hold across principals: a code-provider running on someone else's
dataset can leak no more than the schema allows, and can only run at all with a matching grant.
"""

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.models import RunStatus
from keyhole.controlplane.cleanroom import DatasetStore, Refusal, run_in_cleanroom
from keyhole.schema.spec import OutputSchema, SchemaType

# A stand-in sensitive dataset the provider may compute on but must not exfiltrate.
SECRET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(200))
FILES = {"customers.csv": SECRET}
ENUM = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
HONEST = 'import os,json;json.dump("spam",open(os.environ["KEYHOLE_OUTPUT"],"w"))'


@pytest.fixture
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def _fixture(tmp_path):
    store = DatasetStore(root=tmp_path)
    ds = store.add("data-owner-acme", FILES)
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
