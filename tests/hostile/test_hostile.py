"""The marquee: hostile scripts that try to exfiltrate the supplied data.

Each test runs untrusted code end-to-end through the real local pipeline (executor + exit gate)
and asserts that exfiltration is structurally blocked or bounded, and that the attestation
records exactly what happened. Network-egress containment is enforced by the image +
infrastructure layer (egress-proxy sidecar, no-NAT subnet); those paths are asserted in the
gated cloud/integration suite, not here.
"""

import os

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.models import Limits, RunRequest, RunStatus, utcnow
from keyhole.controlplane.budget import BudgetPolicy, InMemoryLedger
from keyhole.controlplane.gate import NOT_RELEASED
from keyhole.controlplane.runner import run_local
from keyhole.schema.bandwidth import run_channel_bits
from keyhole.schema.spec import OutputSchema, SchemaType

# A stand-in "sensitive dataset" the untrusted code is allowed to read but must not leak.
SECRET_DATASET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(200))


@pytest.fixture
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


def _run(code: str, schema: OutputSchema, signer: Ed25519Signer, *, ledger=None, budget=None,
         principal="default", **limit_kw):
    limits = {"timeout_seconds": 8, "memory_mb": 256, **limit_kw}
    req = RunRequest(
        code=code,
        data={"customers.csv": SECRET_DATASET},
        output_schema=schema,
        limits=Limits(**limits),
        principal=principal,
    )
    return run_local(req, signer, ledger=ledger, budget=budget)


def test_dump_whole_dataset_to_output_is_rejected(signer):
    # Attack: read the dataset and try to return the whole thing.
    code = """
import os, json
data = open("customers.csv").read()
json.dump(data, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
    outcome = _run(code, schema, signer)

    assert outcome.result.status is RunStatus.WITHHELD
    assert outcome.result.output is None  # nothing released
    assert outcome.attestation.released is False
    # The attestation still binds the (unreleased) data hash and verifies.
    assert verify_attestation(outcome.attestation, signer.public_key_pem())


def test_encode_dataset_in_bounded_string_is_capped(signer):
    # Attack: smuggle the dataset into a bounded-string field. The length bound caps the leak.
    code = """
import os, json
data = open("customers.csv").read()
json.dump(data, open(os.environ["KEYHOLE_OUTPUT"], "w"))  # far longer than the bound
"""
    schema = OutputSchema(type=SchemaType.STRING, max_length=8)
    outcome = _run(code, schema, signer)

    # The oversized string doesn't conform -> nothing released.
    assert outcome.result.status is RunStatus.WITHHELD
    assert outcome.result.output is None


def test_bounded_channel_is_disclosed_when_used(signer):
    # A conforming small answer IS released - and the exact bytes are attested and
    # bandwidth-bounded.
    code = """
import os, json
data = open("customers.csv").read()
json.dump(data[:8], open(os.environ["KEYHOLE_OUTPUT"], "w"))  # fits the bound
"""
    schema = OutputSchema(type=SchemaType.STRING, max_length=8)
    outcome = _run(code, schema, signer)

    assert outcome.result.status is RunStatus.SUCCEEDED
    assert isinstance(outcome.result.output, str)
    assert len(outcome.result.output) <= 8
    # Bounded: at most 8 bytes * 8 bits = 64 bits can leave, and it's disclosed exactly.
    assert outcome.attestation.exit_bandwidth_bits == 64.0
    assert outcome.attestation.output == outcome.result.output
    assert verify_attestation(outcome.attestation, signer.public_key_pem())


def test_secret_printed_to_output_is_caught_by_backstop(signer):
    code = """
import os, json
json.dump("AKIAIOSFODNN7EXAMPLE", open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.STRING, max_length=64)
    outcome = _run(code, schema, signer)
    assert outcome.result.status is RunStatus.WITHHELD
    assert "DLP" in outcome.audit.withheld_reason


def test_stdout_is_not_an_exit_channel(signer):
    # Attack: dump the dataset to stdout instead of the typed output. stdout is not released.
    code = """
import os, json
print(open("customers.csv").read())          # goes nowhere the caller receives
json.dump("ham", open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])
    outcome = _run(code, schema, signer)
    assert outcome.result.status is RunStatus.SUCCEEDED
    assert outcome.result.output == "ham"  # only the typed value; stdout never reaches the caller


def test_fork_bomb_is_contained(signer):
    code = """
import os
while True:
    try:
        os.fork()
    except OSError:
        pass
"""
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    outcome = _run(code, schema, signer, timeout_seconds=5)
    # It must not succeed and must not hang the host; we simply get a non-released result back.
    assert outcome.result.status is not RunStatus.SUCCEEDED


def test_memory_hog_is_contained(signer):
    code = """
import os, json
blob = bytearray()
try:
    while True:
        blob.extend(b"x" * (10 * 1024 * 1024))
except MemoryError:
    pass
json.dump(True, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    outcome = _run(code, schema, signer, timeout_seconds=5, memory_mb=128)
    # Either it's killed (failed/timeout) or it caught MemoryError and returned True; both are safe.
    assert outcome.result.status in {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMEOUT}


def test_drip_exfiltration_over_runs_is_bounded_by_the_budget(signer):
    # Attack: leak the dataset one conforming bit at a time across many runs. Each run alone is
    # within schema, but the per-principal cumulative budget caps the TOTAL that can ever leave.
    # Emit the parity of the dataset length as a boolean (1 bit) — a legitimate-looking answer.
    code = """
import os, json
data = open("customers.csv").read()
json.dump(len(data) % 2 == 0, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.BOOLEAN)  # 1 bit per answer, log2(3) per run
    per_run = run_channel_bits(schema)
    ledger = InMemoryLedger()
    budget = BudgetPolicy(max_exit_bits=3 * per_run)  # exactly 3 runs, ever

    statuses = [
        _run(code, schema, signer, ledger=ledger, budget=budget, principal="agent-7").result.status
        for _ in range(6)
    ]

    # First three drip runs succeed; every run after the budget is exhausted is withheld.
    assert statuses[:3] == [RunStatus.SUCCEEDED] * 3
    assert all(s is RunStatus.WITHHELD for s in statuses[3:])
    # The cumulative leak never exceeds the cap, no matter how many times the attacker calls.
    assert ledger.spent("agent-7", None, utcnow()) == pytest.approx(3 * per_run)


def test_withheld_run_still_consumes_budget(signer):
    # "Was it released?" is itself information, so a withheld run is charged like any other.
    good = """
import os, json
json.dump(True, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    bad = """
import os, json
json.dump("not-a-boolean", open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    per_run = run_channel_bits(schema)
    ledger = InMemoryLedger()
    budget = BudgetPolicy(max_exit_bits=10.0)

    good_out = _run(good, schema, signer, ledger=ledger, budget=budget, principal="p")
    bad_out = _run(bad, schema, signer, ledger=ledger, budget=budget, principal="p")
    assert good_out.result.status is RunStatus.SUCCEEDED
    assert bad_out.result.status is RunStatus.WITHHELD
    assert ledger.spent("p", None, utcnow()) == pytest.approx(2 * per_run)


def _caller_view(outcome) -> tuple:
    """Everything a (possibly hostile) caller gets back that the code could try to influence."""
    r, a = outcome.result, outcome.attestation
    return (r.status, r.output, r.withheld_reason, r.exit_code,
            a.output, a.output_sha256, a.exit_code, a.released, a.egress_attempts, a.egress_denied)


def test_exit_code_side_channel_is_closed(signer):
    # Attack: smuggle a byte of the secret out through the process exit status (0-255, ~8 bits
    # per run) instead of the output, and through *how* the run fails. Every non-release outcome
    # must look identical to the caller, so none of it carries information.
    leak_byte = """
import sys
data = open("customers.csv").read()
sys.exit(ord(data[{i}]) or 1)
"""
    other_failures = [
        "import os; open(os.environ['KEYHOLE_OUTPUT'], 'w').write('not json')",  # invalid JSON
        "import os, json; json.dump('nope', open(os.environ['KEYHOLE_OUTPUT'], 'w'))",  # bad value
        "pass",  # no output at all
        "raise RuntimeError('boom')",  # crash
    ]
    schema = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])

    byte_runs = [_run(leak_byte.format(i=i), schema, signer) for i in range(4)]
    other_runs = [_run(code, schema, signer) for code in other_failures]

    # The code really did signal different values — the owner's audit sees them ...
    assert len({o.audit.exit_code for o in byte_runs}) > 1
    # ... but the caller sees one identical, opaque outcome for every one of these runs.
    views = {_caller_view(o) for o in byte_runs + other_runs}
    assert len(views) == 1
    (only,) = views
    assert only[0] is RunStatus.WITHHELD and only[2] == NOT_RELEASED and only[3] is None


@pytest.mark.skipif(
    not os.environ.get("KEYHOLE_CLOUD"),
    reason=(
        "network-egress containment is enforced by the egress proxy; asserted in the cloud suite"
    ),
)
def test_network_exfil_is_blocked(signer):  # pragma: no cover - runs only against cloud
    code = """
import os, json, socket
try:
    socket.create_connection(("example.com", 80), timeout=3)
    leaked = True
except OSError:
    leaked = False
json.dump(leaked, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    outcome = _run(code, schema, signer)
    assert outcome.result.output is False  # no egress path
