"""The attestation record and its canonical signed form."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from keyhole.common.hashing import canonical_json_bytes
from keyhole.common.models import utcnow


class Attestation(BaseModel):
    """A signed, verifiable statement about exactly one run.

    The ``claims`` are what is signed; ``signature``, ``key_id``, and ``algorithm`` carry the
    signature itself and are therefore *not* part of the signed payload.
    """

    attestation_id: str = Field(default_factory=lambda: f"att-{uuid.uuid4().hex}")
    created_at: datetime = Field(default_factory=utcnow)

    # --- signed claims ---
    run_id: str
    code_sha256: str
    data_sha256: str
    schema_sha256: str
    output_sha256: str | None
    output: Any | None  # the exact released value, or None if nothing was released
    exit_bandwidth_bits: float
    egress_attempts: int
    egress_denied: int
    exit_code: int | None
    released: bool
    # Clean-room identities (who ran whose data). Single-principal runs leave owner/dataset None.
    data_owner: str | None = None
    code_provider: str | None = None
    dataset_id: str | None = None

    # --- signature envelope (not signed) ---
    algorithm: str = "unsigned"
    key_id: str = "none"
    signature: str = ""  # base64

    def claims(self) -> dict[str, Any]:
        """The exact, ordered set of fields the signature covers."""
        return build_claims(self)

    def signed_bytes(self) -> bytes:
        return canonical_json_bytes(self.claims())


def build_claims(att: Attestation) -> dict[str, Any]:
    """Canonical claim set. Changing any of these invalidates the signature."""
    return {
        "attestation_id": att.attestation_id,
        "created_at": att.created_at.isoformat(),
        "run_id": att.run_id,
        "code_sha256": att.code_sha256,
        "data_sha256": att.data_sha256,
        "schema_sha256": att.schema_sha256,
        "output_sha256": att.output_sha256,
        "output": att.output,
        "exit_bandwidth_bits": att.exit_bandwidth_bits,
        "egress_attempts": att.egress_attempts,
        "egress_denied": att.egress_denied,
        "exit_code": att.exit_code,
        "released": att.released,
        "data_owner": att.data_owner,
        "code_provider": att.code_provider,
        "dataset_id": att.dataset_id,
    }
