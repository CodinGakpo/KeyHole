"""Dashboard data layer — pure functions over a Store, independent of HTTP.

Keeping these HTTP-free makes the dashboard's logic directly unit-testable and lets the server be a
thin adapter. Attestation verification reuses the same ``verify_attestation`` as the CLI, so the
badge shown in the browser means exactly what `sbx verify` means.
"""

from __future__ import annotations

from typing import Any

from mark1.attest.record import Attestation
from mark1.attest.verify import verify_attestation
from mark1.controlplane.store import Store


def _verified(attestation: Attestation | None, pubkey_pem: bytes | None) -> bool | None:
    """True/False if we can check the signature, None if we cannot (no attestation or key)."""
    if attestation is None or not attestation.signature or pubkey_pem is None:
        return None
    try:
        return verify_attestation(attestation, pubkey_pem)
    except (ValueError, TypeError):
        return None


def list_summaries(
    store: Store, pubkey_pem: bytes | None, limit: int = 100
) -> list[dict[str, Any]]:
    """One row per run, newest first, with the signature checked when possible."""
    summaries: list[dict[str, Any]] = []
    for result in store.list_runs(limit):
        att = store.get_attestation(result.attestation_id) if result.attestation_id else None
        audit = store.get_audit(result.run_id)
        summaries.append({
            "run_id": result.run_id,
            "status": result.status.value,
            "released": result.status.value == "succeeded",
            "exit_bandwidth_bits": result.exit_bandwidth_bits,
            "attestation_id": result.attestation_id,
            "created_at": audit.created_at.isoformat() if audit else None,
            "verified": _verified(att, pubkey_pem),
        })
    return summaries


def run_detail(store: Store, run_id: str, pubkey_pem: bytes | None) -> dict[str, Any] | None:
    """Everything for one run: result, audit (hashes + data-flow events), attestation, verdict."""
    result = store.get_result(run_id)
    if result is None:
        return None
    audit = store.get_audit(run_id)
    att = store.get_attestation(result.attestation_id) if result.attestation_id else None
    return {
        "result": result.model_dump(mode="json"),
        "audit": audit.model_dump(mode="json") if audit else None,
        "attestation": att.model_dump(mode="json") if att else None,
        "verified": _verified(att, pubkey_pem),
    }


def verify_upload(attestation_json: dict[str, Any], pubkey_pem: bytes | None) -> dict[str, Any]:
    """Verify a supplied attestation (e.g. dragged into the page) against a public key."""
    try:
        att = Attestation.model_validate(attestation_json)
    except Exception as exc:  # noqa: BLE001 - report a clean message to the UI
        return {"valid": False, "error": f"not a valid attestation: {exc}"}
    if pubkey_pem is None:
        return {"valid": False, "error": "no public key available to verify against"}
    try:
        valid = verify_attestation(att, pubkey_pem)
    except (ValueError, TypeError) as exc:
        return {"valid": False, "error": str(exc), "algorithm": att.algorithm}
    return {"valid": valid, "algorithm": att.algorithm, "attestation_id": att.attestation_id}
