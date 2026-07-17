"""Control-plane request handling.

Framework-agnostic handlers that map cleanly onto a Lambda + API Gateway HTTP API deployment
(the base hosting choice: scales to zero, ~$0 idle). Each handler takes a parsed request and a
:class:`~mark1.controlplane.store.Store`, so the same logic is exercised in unit tests with the
in-memory store and in the cloud with DynamoDB.

The cloud execution path (submit → Fargate → poll → gate) is wired in M5; this module currently
provides the request/response shapes and the in-memory synchronous path used for local serving.
"""

from __future__ import annotations

from mark1.attest.sign import Signer
from mark1.common.models import RunRequest, RunResult
from mark1.controlplane.gate import GateOutcome
from mark1.controlplane.runner import run_local
from mark1.controlplane.store import Store


def handle_create_run_local(request: RunRequest, store: Store, signer: Signer) -> RunResult:
    """Synchronous local run: execute, gate, persist, return the result.

    In the cloud this splits into an async submit (returns PENDING + run_id) and a later
    finalize step after the Fargate task completes; both reuse the same exit gate.
    """
    outcome: GateOutcome = run_local(request, signer)
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)
    return outcome.result


def handle_get_run(run_id: str, store: Store) -> RunResult | None:
    return store.get_result(run_id)
