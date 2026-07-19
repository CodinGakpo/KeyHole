"""FileStore: persistent local run history for the dashboard."""

from mark1.attest.record import Attestation
from mark1.common.models import AuditRecord, RunResult, RunStatus
from mark1.controlplane.store import FileStore, InMemoryStore


def _result(run_id: str, status=RunStatus.SUCCEEDED) -> RunResult:
    return RunResult(run_id=run_id, status=status, output="spam", exit_bandwidth_bits=1.0,
                     attestation_id=f"att-{run_id}")


def _audit(run_id: str) -> AuditRecord:
    return AuditRecord(run_id=run_id, status=RunStatus.SUCCEEDED,
                       code_sha256="a"*64, data_sha256="b"*64, schema_sha256="c"*64)


def _attestation(run_id: str) -> Attestation:
    return Attestation(attestation_id=f"att-{run_id}", run_id=run_id, code_sha256="a"*64,
                       data_sha256="b"*64, schema_sha256="c"*64, output_sha256=None, output="spam",
                       exit_bandwidth_bits=1.0, egress_attempts=0, egress_denied=0, exit_code=0,
                       released=True)


def test_round_trip(tmp_path):
    store = FileStore(root=tmp_path)
    store.put_result(_result("run-1"))
    store.put_audit(_audit("run-1"))
    store.put_attestation(_attestation("run-1"))

    assert store.get_result("run-1").output == "spam"
    assert store.get_audit("run-1").code_sha256 == "a"*64
    assert store.get_attestation("att-run-1").released is True
    assert store.get_result("missing") is None


def test_survives_a_fresh_instance(tmp_path):
    FileStore(root=tmp_path).put_result(_result("run-x"))
    assert FileStore(root=tmp_path).get_result("run-x").run_id == "run-x"


def test_list_runs_is_newest_first(tmp_path):
    import os
    import time
    store = FileStore(root=tmp_path)
    for i in range(3):
        store.put_result(_result(f"run-{i}"))
        # nudge mtimes apart so ordering is deterministic
        os.utime(tmp_path / "results" / f"run-{i}.json", (time.time() + i, time.time() + i))

    runs = store.list_runs()
    assert [r.run_id for r in runs] == ["run-2", "run-1", "run-0"]
    assert len(store.list_runs(limit=2)) == 2


def test_inmemory_list_runs_newest_first():
    store = InMemoryStore()
    for i in range(3):
        store.put_result(_result(f"run-{i}"))
    assert [r.run_id for r in store.list_runs()] == ["run-2", "run-1", "run-0"]
