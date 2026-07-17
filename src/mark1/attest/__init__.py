"""Verifiable attestation of a confidential run.

On completion the control plane emits a signed attestation binding the code, data, schema, and
the exact released output, plus the egress verdict. Anyone can later verify that this exact
code ran on this exact data with zero egress and only this bounded value came out — turning the
confidentiality claim from "trust us" into something checkable.
"""

from mark1.attest.record import Attestation, build_claims
from mark1.attest.sign import Ed25519Signer, Signer, sign_attestation
from mark1.attest.verify import verify_attestation

__all__ = [
    "Attestation",
    "build_claims",
    "Signer",
    "Ed25519Signer",
    "sign_attestation",
    "verify_attestation",
]
