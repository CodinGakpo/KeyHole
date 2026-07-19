"""Dashboard service + page: summaries, detail, upload-verify, and a self-contained page."""

from mark1.attest.sign import Ed25519Signer, sign_attestation
from mark1.common.models import AuditRecord, DataFlowEvent, DataFlowEventKind, RunResult, RunStatus
from mark1.controlplane.gate import run_exit_gate
from mark1.controlplane.store import InMemoryStore
from mark1.dashboard import service
from mark1.dashboard.server import render_index
from mark1.executor.entrypoint import ExecResult
from mark1.schema.spec import OutputSchema, SchemaType


def _seed_run(store, signer, output='"spam"', run_id="run-1"):
    """Run a value through the real exit gate and persist the outcome, like the CLI does."""
    from mark1.common.models import Limits, RunRequest
    req = RunRequest(code="x", data={}, output_schema=OutputSchema(type=SchemaType.ENUM,
                     choices=["spam", "ham"]), limits=Limits())
    ex = ExecResult(0, output, "", "", 5, False, len(output), [
        DataFlowEvent(kind=DataFlowEventKind.OUTPUT_WRITTEN, detail="4 bytes"),
    ])
    outcome = run_exit_gate(run_id, req, ex, signer)
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)
    return outcome


def test_summaries_report_verified_true_for_a_real_signature():
    store, signer = InMemoryStore(), Ed25519Signer.generate()
    _seed_run(store, signer)
    rows = service.list_summaries(store, signer.public_key_pem())
    assert len(rows) == 1
    assert rows[0]["status"] == "succeeded"
    assert rows[0]["released"] is True
    assert rows[0]["verified"] is True


def test_summaries_verified_none_without_a_key():
    store, signer = InMemoryStore(), Ed25519Signer.generate()
    _seed_run(store, signer)
    assert service.list_summaries(store, None)[0]["verified"] is None


def test_run_detail_has_hashes_audit_and_verdict():
    store, signer = InMemoryStore(), Ed25519Signer.generate()
    _seed_run(store, signer)
    d = service.run_detail(store, "run-1", signer.public_key_pem())
    assert d["result"]["status"] == "succeeded"
    assert len(d["audit"]["code_sha256"]) == 64
    assert d["audit"]["events"][0]["kind"] == "output_written"
    assert d["verified"] is True
    assert service.run_detail(store, "nope", None) is None


def test_verify_upload_valid_then_tampered():
    signer = Ed25519Signer.generate()
    store = InMemoryStore()
    outcome = _seed_run(store, signer)
    payload = outcome.attestation.model_dump(mode="json")

    ok = service.verify_upload(payload, signer.public_key_pem())
    assert ok["valid"] is True and ok["algorithm"] == "ed25519"

    payload["output"] = "ham"  # tamper a signed claim
    assert service.verify_upload(payload, signer.public_key_pem())["valid"] is False


def test_verify_upload_rejects_non_attestation():
    out = service.verify_upload({"not": "an attestation"}, None)
    assert out["valid"] is False and "error" in out


def test_index_is_self_contained():
    html = render_index()
    assert "<title>Mark-1" in html
    assert "/api/runs" in html and "/api/verify" in html
    # No external requests: nothing loaded over the network (CSP-clean, offline-safe).
    assert "http://" not in html and "https://" not in html
    assert "cdn" not in html.lower()
