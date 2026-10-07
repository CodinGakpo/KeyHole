"""The exit gate: releases conforming outputs, withholds everything else, always attests."""

import json

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.models import DataFlowEvent, DataFlowEventKind, Limits, RunRequest, utcnow
from keyhole.controlplane.budget import BudgetPolicy, InMemoryLedger
from keyhole.controlplane.gate import run_exit_gate
from keyhole.executor.entrypoint import ExecResult
from keyhole.schema.spec import OutputSchema, SchemaType


def _request(schema: OutputSchema, principal: str = "default", **limit_kw) -> RunRequest:
    return RunRequest(
        code="x", data={}, output_schema=schema, limits=Limits(**limit_kw), principal=principal
    )


def _exec(output, *, exit_code=0, timed_out=False, events=None, output_bytes=None) -> ExecResult:
    raw = None if output is None else json.dumps(output)
    return ExecResult(
        exit_code=exit_code,
        output_raw=raw,
        stdout="",
        stderr="",
        duration_ms=5,
        timed_out=timed_out,
        output_bytes=output_bytes if output_bytes is not None else (len(raw) if raw else 0),
        events=events or [],
    )


def test_conforming_output_is_released_and_attested():
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"])
    signer = Ed25519Signer.generate()
    outcome = run_exit_gate("r1", _request(schema), _exec("spam"), signer)

    assert outcome.result.status.value == "succeeded"
    assert outcome.result.output == "spam"
    assert outcome.attestation.released is True
    assert verify_attestation(outcome.attestation, signer.public_key_pem())


def test_nonconforming_output_is_withheld():
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"])
    signer = Ed25519Signer.generate()
    outcome = run_exit_gate("r2", _request(schema), _exec("phishing"), signer)

    assert outcome.result.status.value == "withheld"
    assert outcome.result.output is None
    assert outcome.attestation.released is False
    # Even a withheld run is attested (proving nothing was released).
    assert verify_attestation(outcome.attestation, signer.public_key_pem())


def test_oversized_output_is_withheld():
    schema = OutputSchema(type=SchemaType.STRING, max_length=1_000_000)
    signer = Ed25519Signer.generate()
    ex = _exec("x" * 10, output_bytes=999_999)
    outcome = run_exit_gate("r3", _request(schema, max_output_bytes=1024), ex, signer)
    assert outcome.result.status.value == "withheld"
    assert "exceeds" in outcome.result.withheld_reason


def test_non_json_output_is_withheld():
    schema = OutputSchema(type=SchemaType.INTEGER)
    signer = Ed25519Signer.generate()
    ex = ExecResult(0, "not json", "", "", 1, False, 8, [])
    outcome = run_exit_gate("r4", _request(schema), ex, signer)
    assert outcome.result.status.value == "withheld"


def test_timeout_is_reported():
    schema = OutputSchema(type=SchemaType.INTEGER)
    signer = Ed25519Signer.generate()
    ex = _exec(None, exit_code=None, timed_out=True)
    outcome = run_exit_gate("r5", _request(schema), ex, signer)
    assert outcome.result.status.value == "timeout"


def test_egress_attempts_recorded_in_attestation():
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    signer = Ed25519Signer.generate()
    events = [
        DataFlowEvent(kind=DataFlowEventKind.EGRESS_ATTEMPT, detail="1.2.3.4:443", denied=True),
        DataFlowEvent(kind=DataFlowEventKind.EGRESS_ATTEMPT, detail="evil.example", denied=True),
    ]
    outcome = run_exit_gate("r6", _request(schema), _exec(True, events=events), signer)
    assert outcome.attestation.egress_attempts == 2
    assert outcome.attestation.egress_denied == 2
    assert outcome.audit.egress_denied == 2


def test_secret_in_output_is_caught_by_backstop():
    schema = OutputSchema(type=SchemaType.STRING, max_length=200)
    signer = Ed25519Signer.generate()
    leaked = "AKIAIOSFODNN7EXAMPLE"
    outcome = run_exit_gate("r7", _request(schema), _exec(leaked), signer)
    assert outcome.result.status.value == "withheld"
    assert "DLP" in outcome.result.withheld_reason


def test_budget_withholds_a_conforming_output_once_the_cap_is_hit():
    # A 2-choice enum is 1 bit/run; a 1-bit budget allows exactly one release, then withholds.
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"])
    signer = Ed25519Signer.generate()
    ledger, budget = InMemoryLedger(), BudgetPolicy(max_exit_bits=1.0)

    req = _request(schema, principal="alice")
    first = run_exit_gate("b1", req, _exec("spam"), signer, ledger=ledger, budget=budget)
    assert first.result.status.value == "succeeded"
    assert first.result.cumulative_exit_bits == 1.0

    second = run_exit_gate("b2", req, _exec("ham"), signer, ledger=ledger, budget=budget)
    assert second.result.status.value == "withheld"
    assert second.result.output is None
    assert "budget exceeded" in second.result.withheld_reason
    # The over-budget run released nothing, so it must not have consumed any budget.
    assert ledger.spent("alice", None, utcnow()) == 1.0
