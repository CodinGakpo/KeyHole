"""Standalone attestation verification.

Deliberately dependency-light and free of any Mark-1 runtime state: a third party can verify an
attestation given only the record and the signer's public key. Any tampering with a signed
claim (the output, a hash, the egress verdict) changes the canonical bytes and fails
verification.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mark1.attest.record import Attestation


def verify_attestation(att: Attestation, public_key_pem: bytes) -> bool:
    """Return True iff ``att``'s signature is valid for the given public key."""
    if att.algorithm != "ed25519":
        raise ValueError(f"unsupported attestation algorithm: {att.algorithm!r}")

    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("provided public key is not ed25519")

    try:
        signature = base64.b64decode(att.signature)
    except (ValueError, TypeError):
        return False

    try:
        public_key.verify(signature, att.signed_bytes())
        return True
    except InvalidSignature:
        return False
