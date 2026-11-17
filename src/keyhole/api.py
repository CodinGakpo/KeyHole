"""The embeddable API: run code against a registered dataset under its owner's exit policy.

This is the whole surface an agent framework needs. The data stays in the owner's registry; the
caller holds a dataset id, never the bytes. Write the code against the mock (``on="mock"``, full
stdout and tracebacks), then run it on the real data (``on="real"``), where the only thing that
comes back is a typed answer no wider than the owner allows, charged to the dataset's budget and
recorded in a signed receipt.

    import keyhole
    keyhole.list_datasets(principal="agent")
    keyhole.run("ds-…", code, {"type": "enum", "choices": ["low", "high"]}, principal="agent")
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Literal

from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.attest.sign import Signer
from keyhole.common.models import Limits
from keyhole.controlplane.cleanroom import (
    DatasetStore,
    Refusal,
    run_in_cleanroom,
    run_on_mock,
)
from keyhole.controlplane.store import Store
from keyhole.schema.bandwidth import run_channel_bits
from keyhole.schema.spec import OutputSchema


def list_datasets(principal: str, store: DatasetStore | None = None) -> list[dict[str, Any]]:
    """Datasets ``principal`` holds a grant for: what they are, their mock, and the exit policy."""
    store = store or DatasetStore()
    out = []
    for ds in store.list():
        if store.grant_for(ds.dataset_id, principal) is None:
            continue
        out.append({
            "dataset_id": ds.dataset_id,
            "description": ds.description,
            "files": ds.filenames,
            "mock": store.load_mock(ds.dataset_id),
            "max_bits_per_run": ds.max_bits_per_run,
            "budget_bits": ds.budget_bits,
            "bits_spent": store.bits_spent(ds),
        })
    return out


def run(
    dataset_id: str,
    code: str,
    output_schema: dict[str, Any] | OutputSchema,
    *,
    principal: str,
    on: Literal["mock", "real"] = "real",
    grant: str | None = None,
    timeout_seconds: int = 60,
    store: DatasetStore | None = None,
    signer: Signer | None = None,
    audit: Store | None = None,
) -> dict[str, Any]:
    """Run ``code`` on a dataset's mock or real files. Returns a plain dict.

    ``grant`` defaults to whichever grant the owner issued to ``principal``. ``audit``, if given,
    receives the owner's records of a real run (result, audit, receipt).
    """
    store = store or DatasetStore()
    schema = (
        output_schema if isinstance(output_schema, OutputSchema)
        else OutputSchema.from_dict(output_schema)
    )
    if grant is None:
        found = store.grant_for(dataset_id, principal)
        grant = found.grant_id if found else ""
    limits = Limits(timeout_seconds=timeout_seconds)

    if on == "mock":
        mock = run_on_mock(store, dataset_id, grant, principal, code, schema, limits)
        if isinstance(mock, Refusal):
            return {"on": "mock", "status": "refused", "reason": mock.reason}
        return {"on": "mock", "status": "ok" if mock.conforms else "needs_fixing", **asdict(mock)}

    outcome = run_in_cleanroom(
        store, dataset_id, grant, principal, code, schema,
        signer or load_or_create_dev_signer(), limits=limits,
    )
    if isinstance(outcome, Refusal):
        return {"on": "real", "status": "refused", "reason": outcome.reason}
    if audit is not None:
        audit.put_result(outcome.result)
        audit.put_audit(outcome.audit)
        audit.put_attestation(outcome.attestation)
    ds = store.get(dataset_id)
    assert ds is not None
    return {
        "on": "real",
        "status": outcome.result.status.value,
        "output": outcome.result.output,
        "reason": outcome.result.withheld_reason,
        "bits_charged": run_channel_bits(schema),
        "bits_spent": store.bits_spent(ds),
        "budget_bits": ds.budget_bits,
        "attestation_id": outcome.result.attestation_id,
    }
