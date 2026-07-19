"""KMS-backed attestation signer (cloud).

Signs with an AWS KMS asymmetric key (ECC_NIST_P256, SIGN_VERIFY) so the private key never leaves
KMS — the strongest trust root available without a hardware enclave. It implements the same
:class:`~mark1.attest.sign.Signer` protocol as the local ed25519 signer, so ``sign_attestation``
and the exit gate are unchanged; only the ``algorithm``/``key_id`` envelope and signature bytes
differ. The signed claim set is identical, so any verifier works against either.

Requires the ``cloud`` extra (boto3). KMS returns a DER-encoded ECDSA signature; the verifier
(:mod:`mark1.attest.verify`) decodes it with the same public key exported via ``kms:GetPublicKey``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization

ALGORITHM = "ecdsa-p256-sha256"


class KmsSigner:
    """Signs attestation payloads with a KMS asymmetric key. The private key never leaves KMS."""

    algorithm = ALGORITHM

    def __init__(self, key_id: str, region: str | None = None, kms_client: object | None = None):
        # `key_id` may be a key id, alias, or ARN — whatever kms:Sign accepts.
        self.key_id = key_id
        if kms_client is not None:
            self._kms = kms_client
        else:
            import boto3  # lazy: only needed on the cloud path

            self._kms = boto3.client("kms", region_name=region)

    def sign(self, payload: bytes) -> bytes:
        """Return the DER-encoded ECDSA signature over ``payload`` (KMS hashes it with SHA-256)."""
        resp = self._kms.sign(
            KeyId=self.key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return resp["Signature"]

    def public_key_pem(self) -> bytes:
        """Fetch the key's public half from KMS and return it as SPKI PEM (for offline verify)."""
        der = self._kms.get_public_key(KeyId=self.key_id)["PublicKey"]
        key = serialization.load_der_public_key(der)
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
