"""Multi-party clean room: a data-owner and a code-provider as distinct principals.

The owner registers a dataset once (the bytes live in the registry); a code-provider runs code
against it **by id + grant token, never receiving the bytes**. The resulting attestation binds both
identities plus the dataset, so the owner gets proof of exactly who ran what on their data and how
little came out.

Local-first and dependency-free: the registry is JSON + files under ``~/.mark1/datasets`` (mirrors
:class:`mark1.controlplane.store.FileStore`). Grant tokens are unguessable **bearer capabilities**
(``secrets.token_hex``) — a production grant would additionally be signed and time-boxed.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from mark1.attest.sign import Signer
from mark1.common.config import home_dir
from mark1.common.hashing import sha256_of_mapping
from mark1.common.models import Limits, RunRequest, utcnow
from mark1.controlplane.budget import BudgetPolicy, Ledger
from mark1.controlplane.gate import GateOutcome
from mark1.controlplane.runner import run_local
from mark1.schema.spec import OutputSchema


class Dataset(BaseModel):
    dataset_id: str
    owner: str
    data_sha256: str
    filenames: list[str]
    created_at: datetime = Field(default_factory=utcnow)


class Grant(BaseModel):
    grant_id: str  # an unguessable bearer token
    dataset_id: str
    grantee: str  # a code-provider principal, or "*" for anyone
    created_at: datetime = Field(default_factory=utcnow)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None = None


@dataclass(frozen=True)
class Refusal:
    """Returned instead of a run when authorization fails — nothing is executed or materialized."""

    reason: str


class DatasetStore:
    """File-backed dataset registry + grants under ``~/.mark1/datasets``."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root else home_dir() / "datasets"
        (self._root / "meta").mkdir(parents=True, exist_ok=True)
        (self._root / "data").mkdir(parents=True, exist_ok=True)
        (self._root / "grants").mkdir(parents=True, exist_ok=True)

    def add(self, owner: str, files: dict[str, str]) -> Dataset:
        dataset_id = f"ds-{secrets.token_hex(6)}"
        ds = Dataset(
            dataset_id=dataset_id,
            owner=owner,
            data_sha256=sha256_of_mapping(files),
            filenames=sorted(files),
        )
        (self._root / "meta" / f"{dataset_id}.json").write_text(ds.model_dump_json())
        (self._root / "data" / f"{dataset_id}.json").write_text(json.dumps(files))
        return ds

    def get(self, dataset_id: str) -> Dataset | None:
        path = self._root / "meta" / f"{dataset_id}.json"
        return Dataset.model_validate_json(path.read_text()) if path.exists() else None

    def list(self) -> list[Dataset]:
        metas = (self._root / "meta").glob("*.json")
        datasets = [Dataset.model_validate_json(p.read_text()) for p in metas]
        return sorted(datasets, key=lambda d: d.created_at, reverse=True)

    def load_files(self, dataset_id: str) -> dict[str, str]:
        """The dataset's actual bytes — resolved server-side only; never returned to a provider."""
        path = self._root / "data" / f"{dataset_id}.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def grant(self, dataset_id: str, grantee: str) -> Grant:
        g = Grant(grant_id=f"grant-{secrets.token_hex(16)}", dataset_id=dataset_id, grantee=grantee)
        (self._root / "grants" / f"{g.grant_id}.json").write_text(g.model_dump_json())
        return g

    def get_grant(self, grant_id: str) -> Grant | None:
        path = self._root / "grants" / f"{grant_id}.json"
        return Grant.model_validate_json(path.read_text()) if path.exists() else None


def authorize(dataset: Dataset | None, grant: Grant | None, provider: str) -> Decision:
    """Decide whether ``provider`` may run against ``dataset`` under ``grant``. Pure/testable."""
    if dataset is None:
        return Decision(False, "no such dataset")
    if grant is None:
        return Decision(False, "no such grant")
    if grant.dataset_id != dataset.dataset_id:
        return Decision(False, "grant is for a different dataset")
    if grant.grantee != "*" and grant.grantee != provider:
        return Decision(False, f"grant does not authorize provider '{provider}'")
    return Decision(True)


def run_in_cleanroom(
    store: DatasetStore,
    dataset_id: str,
    grant_id: str,
    provider: str,
    code: str,
    output_schema: OutputSchema,
    signer: Signer,
    limits: Limits | None = None,
    ledger: Ledger | None = None,
    budget: BudgetPolicy | None = None,
) -> GateOutcome | Refusal:
    """Authorize, then run the provider's code on the owner's dataset — or refuse without running.

    On refusal nothing is materialized or executed: the code-provider only ever learns 'denied'.
    """
    dataset = store.get(dataset_id)
    grant = store.get_grant(grant_id)
    decision = authorize(dataset, grant, provider)
    if not decision.allowed:
        return Refusal(decision.reason or "not authorized")

    assert dataset is not None  # guaranteed by a positive decision
    request = RunRequest(
        code=code,
        data=store.load_files(dataset_id),
        output_schema=output_schema,
        limits=limits or Limits(),
        principal=provider,
        data_owner=dataset.owner,
        dataset_id=dataset_id,
    )
    return run_local(request, signer, ledger=ledger, budget=budget)
