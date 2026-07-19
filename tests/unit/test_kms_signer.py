"""KMS signer + ECDSA verification — exercised with a local EC key standing in for KMS."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

from mark1.attest.kms_signer import KmsSigner
from mark1.attest.record import Attestation
from mark1.attest.sign import sign_attestation
from mark1.attest.verify import verify_attestation


class _FakeKmsClient:
    """Mimics the KMS Sign/GetPublicKey surface using a local EC P-256 key.

    KMS returns a DER-encoded ECDSA signature over the SHA-256 of the raw message, and the SPKI DER
    of the public key — exactly what the cryptography library produces here.
    """

    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.last_sign_kwargs = None

    def sign(self, **kwargs):
        self.last_sign_kwargs = kwargs
        assert kwargs["MessageType"] == "RAW"
        assert kwargs["SigningAlgorithm"] == "ECDSA_SHA_256"
        signature = self._key.sign(kwargs["Message"], ec.ECDSA(SHA256()))
        return {"Signature": signature}

    def get_public_key(self, **kwargs):
        der = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {"PublicKey": der}


def _attestation() -> Attestation:
    return Attestation(
        run_id="r1",
        code_sha256="a" * 64,
        data_sha256="b" * 64,
        schema_sha256="c" * 64,
        output_sha256=None,
        output="spam",
        exit_bandwidth_bits=1.58,
        egress_attempts=0,
        egress_denied=0,
        exit_code=0,
        released=True,
    )


def test_sign_uses_ecdsa_sha256_raw():
    signer = KmsSigner(key_id="alias/mark1", kms_client=_FakeKmsClient())
    sig = signer.sign(b"payload")
    assert isinstance(sig, bytes) and sig
    assert signer.algorithm == "ecdsa-p256-sha256"
    assert signer._kms.last_sign_kwargs["KeyId"] == "alias/mark1"


def test_kms_signed_attestation_verifies_and_tamper_fails():
    fake = _FakeKmsClient()
    signer = KmsSigner(key_id="alias/mark1", kms_client=fake)
    pubkey_pem = signer.public_key_pem()

    att = sign_attestation(_attestation(), signer)
    assert att.algorithm == "ecdsa-p256-sha256"
    assert verify_attestation(att, pubkey_pem) is True

    # Tampering with a signed claim invalidates the signature.
    att.output = "ham"
    assert verify_attestation(att, pubkey_pem) is False


def test_ecdsa_verify_rejects_a_garbage_signature():
    fake = _FakeKmsClient()
    signer = KmsSigner(key_id="k", kms_client=fake)
    att = sign_attestation(_attestation(), signer)
    att.signature = base64.b64encode(b"not a real signature").decode("ascii")
    assert verify_attestation(att, signer.public_key_pem()) is False
