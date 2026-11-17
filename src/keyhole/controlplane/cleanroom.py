"""Multi-party clean room: a data-owner and a code-provider as distinct principals.

The owner registers a dataset once (the bytes live in the registry); a code-provider runs code
against it **by id + grant token, never receiving the bytes**. The resulting attestation binds both
identities plus the dataset, so the owner gets proof of exactly who ran what on their data and how
little came out.

The **data owner sets the exit policy**, on the dataset: the widest answer a single run may carry
(``max_bits_per_run``) and the total that may ever leave (``budget_bits``). The provider still
chooses a schema per run, but one wider than the cap is refused before anything executes, and the
budget is keyed on the dataset — shared by every provider, always on — so neither a wide schema
nor a fresh identity buys more of the data. Nobody reviews code: the owner approves the *size* of
the answer instead.

A dataset may carry owner-written **mock data** (same shape, nothing sensitive). A provider — or
an agent — develops against the mock with full stdout/tracebacks, then runs on the real data,
where only the bounded answer comes back.

Local-first and dependency-free: the registry is JSON + files under ``~/.keyhole/datasets`` (mirrors
:class:`keyhole.controlplane.store.FileStore`). Grant tokens are unguessable **bearer capabilities**
(``secrets.token_hex``) — a production grant would additionally be signed and time-boxed.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from keyhole.attest.sign import Signer
from keyhole.common.config import home_dir
from keyhole.common.hashing import sha256_of_mapping
from keyhole.common.models import Limits, RunRequest, utcnow
from keyhole.controlplane.budget import BudgetPolicy, FileLedger
from keyhole.controlplane.gate import GateOutcome
from keyhole.controlplane.runner import run_local
from keyhole.executor.entrypoint import run_code
from keyhole.schema.bandwidth import run_channel_bits
from keyhole.schema.spec import OutputSchema
from keyhole.schema.validate import validate_output


class Dataset(BaseModel):
    dataset_id: str
    owner: str
    data_sha256: str
    filenames: list[str]
    # The owner's exit policy. Required: a dataset with no policy cannot be run against.
    max_bits_per_run: float = Field(gt=0)
    budget_bits: float = Field(gt=0)
    budget_window_seconds: float | None = None  # None => cumulative for all time
    description: str = ""  # what the data is and how it is laid out, for whoever writes the code
    created_at: datetime = Field(default_factory=utcnow)

    def budget(self) -> BudgetPolicy:
        return BudgetPolicy(self.budget_bits, self.budget_window_seconds)


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


@dataclass(frozen=True)
class MockRun:
    """A run against the dataset's mock data: full debugging detail, nothing real involved."""

    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    output_raw: str | None
    conforms: bool  # would this output have passed the exit gate?
    errors: list[str]


class DatasetStore:
    """File-backed dataset registry + grants under ``~/.keyhole/datasets``."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root else home_dir() / "datasets"
        (self._root / "meta").mkdir(parents=True, exist_ok=True)
        (self._root / "data").mkdir(parents=True, exist_ok=True)
        (self._root / "grants").mkdir(parents=True, exist_ok=True)
        (self._root / "mock").mkdir(parents=True, exist_ok=True)

    def add(
        self,
        owner: str,
        files: dict[str, str],
        *,
        max_bits_per_run: float,
        budget_bits: float,
        budget_window_seconds: float | None = None,
        description: str = "",
        mock: dict[str, str] | None = None,
    ) -> Dataset:
        dataset_id = f"ds-{secrets.token_hex(6)}"
        ds = Dataset(
            dataset_id=dataset_id,
            owner=owner,
            data_sha256=sha256_of_mapping(files),
            filenames=sorted(files),
            max_bits_per_run=max_bits_per_run,
            budget_bits=budget_bits,
            budget_window_seconds=budget_window_seconds,
            description=description,
        )
        (self._root / "meta" / f"{dataset_id}.json").write_text(ds.model_dump_json())
        (self._root / "data" / f"{dataset_id}.json").write_text(json.dumps(files))
        (self._root / "mock" / f"{dataset_id}.json").write_text(json.dumps(mock or {}))
        return ds

    def load_mock(self, dataset_id: str) -> dict[str, str]:
        """The owner-written stand-in files. Safe to show to anyone holding a grant."""
        path = self._root / "mock" / f"{dataset_id}.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def ledger(self) -> FileLedger:
        """Bits charged per dataset — kept with the registry, on the owner's side."""
        return FileLedger(self._root / "ledger.json")

    def bits_spent(self, ds: Dataset) -> float:
        return self.ledger().spent(ds.dataset_id, ds.budget_window_seconds, utcnow())

    def grant_for(self, dataset_id: str, provider: str) -> Grant | None:
        """A grant letting ``provider`` use ``dataset_id``, if the owner issued one."""
        for path in (self._root / "grants").glob("*.json"):
            g = Grant.model_validate_json(path.read_text())
            if g.dataset_id == dataset_id and g.grantee in ("*", provider):
                return g
        return None

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
) -> GateOutcome | Refusal:
    """Authorize, then run the provider's code on the owner's dataset — or refuse without running.

    On refusal nothing is materialized or executed: the code-provider only ever learns 'denied'.
    A schema wider than the owner's per-run cap is such a refusal; it depends only on the schema
    and the policy, so it tells the provider nothing about the data.
    """
    dataset = store.get(dataset_id)
    grant = store.get_grant(grant_id)
    decision = authorize(dataset, grant, provider)
    if not decision.allowed:
        return Refusal(decision.reason or "not authorized")

    assert dataset is not None  # guaranteed by a positive decision
    channel = run_channel_bits(output_schema)
    if channel > dataset.max_bits_per_run:
        return Refusal(
            f"schema could carry {channel:.2f} bits per run; the data owner allows at most "
            f"{dataset.max_bits_per_run:.2f}"
        )

    request = RunRequest(
        code=code,
        data=store.load_files(dataset_id),
        output_schema=output_schema,
        limits=limits or Limits(),
        principal=provider,
        data_owner=dataset.owner,
        dataset_id=dataset_id,
    )
    return run_local(
        request, signer, ledger=store.ledger(), budget=dataset.budget(), budget_key=dataset_id
    )


def run_on_mock(
    store: DatasetStore,
    dataset_id: str,
    grant_id: str,
    provider: str,
    code: str,
    output_schema: OutputSchema,
    limits: Limits | None = None,
) -> MockRun | Refusal:
    """Run the code on the dataset's mock files and return everything, for debugging.

    Nothing real is read, so nothing is gated, charged or attested: this is where code gets
    written and fixed. The real run then returns only the bounded answer.
    """
    dataset = store.get(dataset_id)
    decision = authorize(dataset, store.get_grant(grant_id), provider)
    if not decision.allowed:
        return Refusal(decision.reason or "not authorized")
    mock = store.load_mock(dataset_id)
    if not mock:
        return Refusal("the data owner supplied no mock data for this dataset")

    request = RunRequest(
        code=code, data=mock, output_schema=output_schema, limits=limits or Limits()
    )
    ex = run_code(request)
    errors: list[str] = []
    if ex.output_raw is None:
        errors.append("code wrote nothing to $KEYHOLE_OUTPUT")
    else:
        try:
            errors = validate_output(json.loads(ex.output_raw), output_schema).errors
        except (ValueError, RecursionError):
            errors.append("output is not valid JSON")
    assert dataset is not None
    if run_channel_bits(output_schema) > dataset.max_bits_per_run:
        errors.append(
            f"schema exceeds the owner's cap of {dataset.max_bits_per_run:.2f} bits per run"
        )
    return MockRun(
        exit_code=ex.exit_code, timed_out=ex.timed_out, stdout=ex.stdout, stderr=ex.stderr,
        output_raw=ex.output_raw, conforms=not errors and ex.exit_code == 0, errors=errors,
    )
