"""Attestation: sign/verify round-trip and tamper detection."""

from mark1.attest.record import Attestation
from mark1.attest.sign import Ed25519Signer, sign_attestation
from mark1.attest.verify import verify_attestation


def _attestation(**overrides) -> Attestation:
    base = dict(
        run_id="run-1",
        code_sha256="c" * 64,
        data_sha256="d" * 64,
        schema_sha256="s" * 64,
        output_sha256="o" * 64,
        output={"category": "spam"},
        exit_bandwidth_bits=1.58,
        egress_attempts=0,
        egress_denied=0,
        exit_code=0,
        released=True,
    )
    base.update(overrides)
    return Attestation(**base)


def test_sign_and_verify_roundtrip():
    signer = Ed25519Signer.generate()
    att = sign_attestation(_attestation(), signer)
    assert verify_attestation(att, signer.public_key_pem())


def test_tampering_with_output_fails_verification():
    signer = Ed25519Signer.generate()
    att = sign_attestation(_attestation(), signer)
    att.output = {"category": "ham"}  # tamper after signing
    assert not verify_attestation(att, signer.public_key_pem())


def test_tampering_with_egress_verdict_fails():
    signer = Ed25519Signer.generate()
    att = sign_attestation(_attestation(egress_denied=3, egress_attempts=3), signer)
    att.egress_denied = 0  # pretend nothing was denied
    assert not verify_attestation(att, signer.public_key_pem())


def test_wrong_key_fails():
    signer = Ed25519Signer.generate()
    other = Ed25519Signer.generate()
    att = sign_attestation(_attestation(), signer)
    assert not verify_attestation(att, other.public_key_pem())


def test_key_save_load_roundtrip(tmp_path):
    signer = Ed25519Signer.generate()
    path = tmp_path / "dev.key"
    signer.save(path)
    reloaded = Ed25519Signer.load(path)
    att = sign_attestation(_attestation(), reloaded)
    assert verify_attestation(att, signer.public_key_pem())
