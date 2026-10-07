"""Signing attestations.

Two backends share one interface:

* :class:`Ed25519Signer` — a local keypair, used for development and the local executor. Keys
  live outside the repo (see ``.gitignore``); never commit them.
* ``KmsSigner`` (in :mod:`keyhole.attest.kms_signer`, cloud extra) — signs with an AWS KMS
  asymmetric key so the private key never leaves KMS.

Swapping backends changes only the ``algorithm``/``key_id`` envelope and the signature bytes;
the signed claim set is identical, so any verifier works against either.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from keyhole.attest.record import Attestation


class Signer(Protocol):
    algorithm: str
    key_id: str

    def sign(self, payload: bytes) -> bytes: ...


class Ed25519Signer:
    """Local ed25519 signer. Generate once, persist the key, reuse."""

    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str = "local-dev") -> None:
        self._key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str = "local-dev") -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate(), key_id=key_id)

    @classmethod
    def load(cls, path: str | Path, key_id: str = "local-dev") -> Ed25519Signer:
        raw = Path(path).read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("key at path is not an ed25519 private key")
        return cls(key, key_id=key_id)

    def save(self, path: str | Path) -> None:
        pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p = Path(path)
        p.write_bytes(pem)
        p.chmod(0o600)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)


def sign_attestation(att: Attestation, signer: Signer) -> Attestation:
    """Return a copy of ``att`` with its signature envelope filled in."""
    att.algorithm = signer.algorithm
    att.key_id = signer.key_id
    signature = signer.sign(att.signed_bytes())
    att.signature = base64.b64encode(signature).decode("ascii")
    return att
