"""Clean-room datasets on the cloud control plane: registry, grants and an atomic bit budget.

The cloud twin of :class:`keyhole.controlplane.cleanroom.DatasetStore`. The data owner registers a
dataset and its exit policy through the API (owner key); callers run code against it by id and
grant (caller key) and never receive the bytes. Metadata, grants and the ledger live in the runs
table under ``ds#`` / ``grant#`` / ``ledger#`` keys; the files live in the artifacts bucket under
``datasets/``, which the sandbox cannot read (the S3 endpoint policy admits only ``runs/``): the
control plane copies a dataset into a run's input bundle, deleted when the run finalizes.

The budget is charged when a run is **admitted**, with one conditional DynamoDB update, so
concurrent submissions cannot overspend it, and a run that is never finalized is still paid for.
Cloud budgets are cumulative; rolling windows are local-only for now.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from keyhole.common.hashing import sha256_of_mapping
from keyhole.controlplane.cleanroom import Dataset, Grant, authorize

DATASET_PREFIX = "datasets"


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: str | None = None
    spent_after: float | None = None  # the dataset's cumulative charge including this run


class DynamoDatasetStore:
    """Dataset registry over the runs table (``table``) and the artifacts bucket."""

    def __init__(self, table: Any, s3: Any, bucket: str) -> None:
        self._table = table
        self._s3 = s3
        self._bucket = bucket

    # --- owner side -----------------------------------------------------------------------------

    def add(
        self,
        owner: str,
        files: dict[str, str],
        *,
        max_bits_per_run: float,
        budget_bits: float,
        description: str = "",
        mock: dict[str, str] | None = None,
    ) -> Dataset:
        ds = Dataset(
            dataset_id=f"ds-{secrets.token_hex(6)}",
            owner=owner,
            data_sha256=sha256_of_mapping(files),
            filenames=sorted(files),
            max_bits_per_run=max_bits_per_run,
            budget_bits=budget_bits,
            description=description,
        )
        self._put_object(f"{ds.dataset_id}/files.json", files)
        self._put_object(f"{ds.dataset_id}/mock.json", mock or {})
        self._table.put_item(Item={"run_id": f"ds#{ds.dataset_id}", "json": ds.model_dump_json()})
        return ds

    def grant(self, dataset_id: str, grantee: str) -> Grant:
        g = Grant(grant_id=f"grant-{secrets.token_hex(16)}", dataset_id=dataset_id, grantee=grantee)
        self._table.put_item(Item={"run_id": f"grant#{g.grant_id}", "json": g.model_dump_json()})
        return g

    # --- control-plane side ---------------------------------------------------------------------

    def get(self, dataset_id: str) -> Dataset | None:
        item = self._table.get_item(Key={"run_id": f"ds#{dataset_id}"}).get("Item")
        return Dataset.model_validate_json(item["json"]) if item else None

    def get_grant(self, grant_id: str) -> Grant | None:
        item = self._table.get_item(Key={"run_id": f"grant#{grant_id}"}).get("Item")
        return Grant.model_validate_json(item["json"]) if item else None

    def load_files(self, dataset_id: str) -> dict[str, str]:
        return self._get_object(f"{dataset_id}/files.json")

    def load_mock(self, dataset_id: str) -> dict[str, str]:
        return self._get_object(f"{dataset_id}/mock.json")

    def bits_spent(self, dataset_id: str) -> float:
        item = self._table.get_item(Key={"run_id": f"ledger#{dataset_id}"}).get("Item")
        return float(item["spent"]) if item else 0.0

    def admit(self, ds: Dataset, grant_id: str, provider: str, bits: float) -> Admission:
        """Authorize ``provider``, check the per-run cap, and charge ``bits`` — or refuse.

        Every refusal depends only on the grant, the schema, the policy and the dataset's charge
        history, never on the data, so it is safe to explain to the caller.
        """
        decision = authorize(ds, self.get_grant(grant_id), provider)
        if not decision.allowed:
            return Admission(False, decision.reason)
        if bits > ds.max_bits_per_run:
            return Admission(
                False,
                f"schema could carry {bits:.2f} bits per run; the data owner allows at most "
                f"{ds.max_bits_per_run:.2f}",
            )
        exhausted = Admission(
            False, f"exit-bandwidth budget of dataset {ds.dataset_id} is spent "
                   f"({ds.budget_bits:.2f} bits)",
        )
        if bits > ds.budget_bits:
            return exhausted
        try:
            resp = self._table.update_item(
                Key={"run_id": f"ledger#{ds.dataset_id}"},
                UpdateExpression="ADD spent :b",
                # Atomic: only charge if the total stays within the budget after this run.
                ConditionExpression="attribute_not_exists(spent) OR spent <= :room",
                ExpressionAttributeValues={
                    ":b": _dec(bits), ":room": _dec(ds.budget_bits - bits),
                },
                ReturnValues="UPDATED_NEW",
            )
        except Exception as exc:  # noqa: BLE001 - boto raises a ClientError subclass
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == (
                "ConditionalCheckFailedException"
            ):
                return exhausted
            raise
        return Admission(True, spent_after=float(resp["Attributes"]["spent"]))

    # --- helpers --------------------------------------------------------------------------------

    def _put_object(self, key: str, value: dict[str, str]) -> None:
        self._s3.put_object(
            Bucket=self._bucket, Key=f"{DATASET_PREFIX}/{key}",
            Body=json.dumps(value).encode("utf-8"), ContentType="application/json",
        )

    def _get_object(self, key: str) -> dict[str, str]:
        body = self._s3.get_object(Bucket=self._bucket, Key=f"{DATASET_PREFIX}/{key}")["Body"]
        return json.loads(body.read())


def _dec(x: float) -> Decimal:
    # Exact enough for bit accounting and stable across the round trip DynamoDB requires.
    return Decimal(str(round(x, 9)))
