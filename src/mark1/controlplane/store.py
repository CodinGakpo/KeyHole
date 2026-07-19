"""Run-state and audit persistence.

An abstract store with two implementations: an in-memory store (local/testing) and a DynamoDB
store (cloud, lazy boto3). The audit table is append-only by convention — the control-plane IAM
role is granted PutItem but not UpdateItem/DeleteItem on it.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from mark1.attest.record import Attestation
from mark1.common.config import home_dir
from mark1.common.models import AuditRecord, RunResult


def _to_dynamo(item: dict) -> dict:
    """DynamoDB's document client rejects Python floats — round-trip them to Decimal."""
    return json.loads(json.dumps(item), parse_float=Decimal)


class Store(Protocol):
    def put_result(self, result: RunResult) -> None: ...
    def get_result(self, run_id: str) -> RunResult | None: ...
    def put_audit(self, audit: AuditRecord) -> None: ...
    def get_audit(self, run_id: str) -> AuditRecord | None: ...
    def put_attestation(self, attestation: Attestation) -> None: ...
    def get_attestation(self, attestation_id: str) -> Attestation | None: ...
    # Context needed to finalize an async cloud run between submit (POST) and finalize (GET):
    # the serialized RunRequest, the task ARN, and the presigned output key.
    def put_pending(self, run_id: str, ctx: dict[str, Any]) -> None: ...
    def get_pending(self, run_id: str) -> dict[str, Any] | None: ...
    # Most-recent-first run results, for the dashboard.
    def list_runs(self, limit: int = 100) -> list[RunResult]: ...


class InMemoryStore:
    """Non-persistent store for local runs and tests."""

    def __init__(self) -> None:
        self._results: dict[str, RunResult] = {}
        self._audits: dict[str, AuditRecord] = {}
        self._attestations: dict[str, Attestation] = {}
        self._pending: dict[str, dict[str, Any]] = {}

    def put_result(self, result: RunResult) -> None:
        self._results[result.run_id] = result

    def get_result(self, run_id: str) -> RunResult | None:
        return self._results.get(run_id)

    def put_audit(self, audit: AuditRecord) -> None:
        self._audits[audit.run_id] = audit

    def get_audit(self, run_id: str) -> AuditRecord | None:
        return self._audits.get(run_id)

    def put_attestation(self, attestation: Attestation) -> None:
        self._attestations[attestation.attestation_id] = attestation

    def get_attestation(self, attestation_id: str) -> Attestation | None:
        return self._attestations.get(attestation_id)

    def put_pending(self, run_id: str, ctx: dict[str, Any]) -> None:
        self._pending[run_id] = ctx

    def get_pending(self, run_id: str) -> dict[str, Any] | None:
        return self._pending.get(run_id)

    def list_runs(self, limit: int = 100) -> list[RunResult]:
        return list(reversed(list(self._results.values())))[:limit]


class DynamoStore:
    """DynamoDB-backed store (cloud). Requires the ``cloud`` extra (boto3).

    Tables (provisioned by Terraform): ``mark1_runs`` (PK run_id) and ``mark1_audit``
    (PK run_id) — the latter append-only.
    """

    def __init__(self, runs_table: str, audit_table: str, region: str | None = None) -> None:
        import boto3  # lazy import

        ddb = boto3.resource("dynamodb", region_name=region)
        self._runs = ddb.Table(runs_table)
        self._audit = ddb.Table(audit_table)

    def put_result(self, result: RunResult) -> None:  # pragma: no cover - needs AWS
        self._runs.put_item(Item=_to_dynamo(result.model_dump(mode="json")))

    def get_result(self, run_id: str) -> RunResult | None:  # pragma: no cover - needs AWS
        item = self._runs.get_item(Key={"run_id": run_id}).get("Item")
        return RunResult.model_validate(item) if item else None

    def put_audit(self, audit: AuditRecord) -> None:  # pragma: no cover - needs AWS
        self._audit.put_item(Item=_to_dynamo(audit.model_dump(mode="json")))

    def get_audit(self, run_id: str) -> AuditRecord | None:  # pragma: no cover - needs AWS
        item = self._audit.get_item(Key={"run_id": run_id}).get("Item")
        return AuditRecord.model_validate(item) if item else None

    def put_attestation(self, attestation: Attestation) -> None:  # pragma: no cover - needs AWS
        # Wrap under "att" so the attestation's own run_id field cannot clobber the item's PK.
        self._runs.put_item(Item=_to_dynamo({
            "run_id": f"att#{attestation.attestation_id}",
            "att": attestation.model_dump(mode="json"),
        }))

    def get_attestation(self, attestation_id: str) -> Attestation | None:  # pragma: no cover
        item = self._runs.get_item(Key={"run_id": f"att#{attestation_id}"}).get("Item")
        return Attestation.model_validate(item["att"]) if item else None

    def put_pending(self, run_id: str, ctx: dict) -> None:  # pragma: no cover - needs AWS
        self._runs.put_item(Item=_to_dynamo({"run_id": f"pending#{run_id}", "ctx": ctx}))

    def get_pending(self, run_id: str) -> dict | None:  # pragma: no cover - needs AWS
        item = self._runs.get_item(Key={"run_id": f"pending#{run_id}"}).get("Item")
        return item.get("ctx") if item else None

    def list_runs(self, limit: int = 100) -> list[RunResult]:  # pragma: no cover - needs AWS
        # A bounded scan; the att#/pending# discriminator rows are not run results.
        items = self._runs.scan(Limit=limit * 3).get("Items", [])
        runs = [
            RunResult.model_validate(i)
            for i in items
            if not str(i["run_id"]).startswith(("att#", "pending#"))
        ]
        return runs[:limit]


class FileStore:
    """Persistent local store: JSON files under ``~/.mark1/store``.

    Backs the ``sbx run --local`` history that the dashboard reads. Deliberately simple and
    dependency-free (mirrors :class:`mark1.controlplane.budget.FileLedger`).
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root else home_dir() / "store"
        for sub in ("results", "audits", "attestations", "pending"):
            (self._root / sub).mkdir(parents=True, exist_ok=True)

    def _write(self, sub: str, name: str, payload: str) -> None:
        (self._root / sub / f"{name}.json").write_text(payload)

    def _read(self, sub: str, name: str) -> dict | None:
        path = self._root / sub / f"{name}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def put_result(self, result: RunResult) -> None:
        self._write("results", result.run_id, result.model_dump_json())

    def get_result(self, run_id: str) -> RunResult | None:
        item = self._read("results", run_id)
        return RunResult.model_validate(item) if item else None

    def put_audit(self, audit: AuditRecord) -> None:
        self._write("audits", audit.run_id, audit.model_dump_json())

    def get_audit(self, run_id: str) -> AuditRecord | None:
        item = self._read("audits", run_id)
        return AuditRecord.model_validate(item) if item else None

    def put_attestation(self, attestation: Attestation) -> None:
        self._write("attestations", attestation.attestation_id, attestation.model_dump_json())

    def get_attestation(self, attestation_id: str) -> Attestation | None:
        item = self._read("attestations", attestation_id)
        return Attestation.model_validate(item) if item else None

    def put_pending(self, run_id: str, ctx: dict[str, Any]) -> None:
        self._write("pending", run_id, json.dumps(ctx))

    def get_pending(self, run_id: str) -> dict[str, Any] | None:
        return self._read("pending", run_id)

    def list_runs(self, limit: int = 100) -> list[RunResult]:
        files = sorted(
            (self._root / "results").glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        runs = [RunResult.model_validate_json(p.read_text()) for p in files[:limit]]
        return runs
