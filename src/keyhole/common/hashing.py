"""Canonical hashing and JSON serialization used across the contract and attestation.

Determinism matters: the attestation binds hashes of inputs and outputs, so two components must
compute byte-identical canonical forms. All canonicalization funnels through here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_of_json(value: Any) -> str:
    return sha256_hex(canonical_json_bytes(value))


def sha256_of_mapping(mapping: dict[str, str]) -> str:
    """Order-independent hash of a {name: contents} map (e.g. supplied data files)."""
    parts = sorted((name, sha256_hex(contents)) for name, contents in mapping.items())
    return sha256_of_json(parts)


def _json_default(obj: Any) -> Any:
    # Support datetimes and pydantic models in canonical encoding.
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    raise TypeError(f"cannot canonicalize object of type {type(obj).__name__}")
