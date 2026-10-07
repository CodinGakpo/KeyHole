"""Load-or-create the local dev signing key.

A convenience around :class:`~keyhole.attest.sign.Ed25519Signer` so the CLI and local runs share a
single stable dev key (persisted under ``~/.keyhole``). Cloud signing uses KMS and does not touch
this.
"""

from __future__ import annotations

from keyhole.attest.sign import Ed25519Signer
from keyhole.common.config import dev_key_path, dev_pubkey_path


def load_or_create_dev_signer() -> Ed25519Signer:
    key_path = dev_key_path()
    if key_path.exists():
        return Ed25519Signer.load(key_path)
    signer = Ed25519Signer.generate(key_id="local-dev")
    signer.save(key_path)
    dev_pubkey_path().write_bytes(signer.public_key_pem())
    return signer
