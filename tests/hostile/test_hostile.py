"""The marquee: hostile scripts that try to exfiltrate the supplied data.

Each test runs untrusted code end-to-end through the real local pipeline (executor + exit gate)
and asserts that exfiltration is structurally blocked or bounded, and that the attestation
records exactly what happened. Local runs go through bubblewrap where it is installed (the
sandbox tests at the end check it); cloud containment (no-NAT subnet, endpoint-only security
group, S3 endpoint policy) is probed by ``scripts/cloud_smoke.py`` against a live stack.
"""

import json
import os
import time

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.models import Limits, RunRequest, RunStatus, utcnow
from keyhole.controlplane.budget import BudgetPolicy, InMemoryLedger
from keyhole.controlplane.gate import NOT_RELEASED
from keyhole.controlplane.runner import run_local
from keyhole.executor import sandbox
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
    # Bounded: at most 8 bytes * 8 bits (plus a sliver for shorter strings) can leave, and
    # it's disclosed exactly.
    assert 64.0 < outcome.attestation.exit_bandwidth_bits < 64.01
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


# Fields the control plane mints itself, plus the hash of the code the caller submitted: none of
# them is something the running code can steer.
_MINTED = {"run_id", "attestation_id", "created_at", "signature", "code_sha256"}


def _caller_view(outcome) -> str:
    """Everything a (possibly hostile) caller gets back that the code could try to influence.

    The whole result and attestation, minus control-plane-minted ids — so a field added later is
    covered by the side-channel tests automatically instead of leaking unnoticed.
    """
    r = outcome.result.model_dump(mode="json", exclude=_MINTED)
    a = outcome.attestation.model_dump(mode="json", exclude=_MINTED)
    return json.dumps([r, a], sort_keys=True)


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
    r = byte_runs[0].result
    assert r.status is RunStatus.WITHHELD and r.withheld_reason == NOT_RELEASED
    assert r.exit_code is None


def test_run_duration_is_not_visible_to_the_caller(signer):
    # Attack: encode data in how long the run takes. The caller's view must not carry a clock.
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    fast = _run("import sys; sys.exit(3)", schema, signer)
    slow = _run("import sys, time; time.sleep(0.4); sys.exit(3)", schema, signer)
    assert _caller_view(fast) == _caller_view(slow)
    assert slow.audit.duration_ms >= 400  # the owner still sees it


def test_code_does_not_run_once_the_budget_is_spent(signer, tmp_path):
    # An exhausted caller must learn nothing more, so the code must not even execute.
    marker = tmp_path / "ran"
    code = f"open({str(marker)!r}, 'w').write('x')"
    schema = OutputSchema(type=SchemaType.BOOLEAN)
    ledger, budget = InMemoryLedger(), BudgetPolicy(max_exit_bits=0.5)  # less than one run
    outcome = _run(code, schema, signer, ledger=ledger, budget=budget)
    assert outcome.result.status is RunStatus.WITHHELD
    assert not marker.exists()


@pytest.mark.parametrize("code", [
    # stdout that is not valid UTF-8
    "import sys; sys.stdout.buffer.write(b'\\xff\\xfe'); sys.stdout.flush()",
    # an output integer too long for Python to parse
    "import os; open(os.environ['KEYHOLE_OUTPUT'], 'w').write('9' * 5000)",
    # JSON nested far past any schema
    "import os; open(os.environ['KEYHOLE_OUTPUT'], 'w').write('[' * 100000)",
])
def test_no_crash_path_escapes_the_gate(signer, code):
    # Attack: make the control plane itself blow up, a third outcome that is neither charged nor
    # attested. Every such run must come back as the same charged, attested "withheld".
    schema = OutputSchema(type=SchemaType.INTEGER)
    ledger, budget = InMemoryLedger(), BudgetPolicy(max_exit_bits=1000.0)
    plain = _run("pass", schema, signer)
    outcome = _run(code, schema, signer, ledger=ledger, budget=budget)
    assert outcome.result.status is RunStatus.WITHHELD
    assert outcome.result.withheld_reason == NOT_RELEASED
    assert ledger.spent("default", None, utcnow()) == pytest.approx(run_channel_bits(schema))
    assert verify_attestation(outcome.attestation, signer.public_key_pem())
    assert outcome.attestation.output == plain.attestation.output is None


@pytest.mark.parametrize("raw_schema,emit", [
    ({"type": "integer"}, "print(10**4000)"),                      # 13,000 bits as "64"
    ({"type": "number"}, "print(10**4000)"),
    ({"type": "number", "minimum": 0, "maximum": 1}, "print('NaN')"),
    ({"type": "string", "max_length": 12}, "import json; print(json.dumps(chr(0x1F600) * 12))"),
    ({"type": "enum", "choices": [0, 1]}, "print('true')"),          # a third spelling of 1
    ({"type": "enum", "choices": [0, 1]}, "print('1.0')"),
])
def test_values_wider_than_the_declared_bound_are_withheld(signer, raw_schema, emit):
    code = ("import os, sys, io\nbuf = io.StringIO(); sys.stdout = buf\n" + emit +
            "\nopen(os.environ['KEYHOLE_OUTPUT'], 'w').write(buf.getvalue())")
    outcome = _run(code, OutputSchema.from_dict(raw_schema), signer)
    assert outcome.result.status is RunStatus.WITHHELD
    assert outcome.result.output is None


def test_object_key_order_is_not_a_channel(signer):
    schema = OutputSchema.from_dict({"type": "object", "properties": {
        "a": {"type": "boolean"}, "b": {"type": "boolean"}, "c": {"type": "boolean"}}})
    emit = "import os; open(os.environ['KEYHOLE_OUTPUT'], 'w').write('%s')"
    one = _run(emit % '{"c":true,"a":true,"b":true}', schema, signer)
    two = _run(emit % '{"b":true,"c":true,"a":true}', schema, signer)
    assert one.result.status is RunStatus.SUCCEEDED
    assert _caller_view(one) == _caller_view(two)


@pytest.mark.skipif(
    not os.environ.get("KEYHOLE_CLOUD"),
    reason=(
        "cloud network containment is probed by scripts/cloud_smoke.py against a live stack"
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


# --- The box itself (bubblewrap) -----------------------------------------------------------------
# The exit gate bounds the answer; these check there is no way around the gate on a local run.

_needs_bwrap = pytest.mark.skipif(
    sandbox.choose_backend() != "bwrap", reason="needs bubblewrap (bwrap) for local isolation"
)
_PROBE = OutputSchema(type=SchemaType.BOOLEAN)


def _probe(body: str) -> str:
    """Code that reports, as a boolean, whether the attack in ``body`` set ``got = True``."""
    return ("import os, json\ngot = False\ntry:\n" +
            "\n".join("    " + line for line in body.splitlines()) +
            "\nexcept Exception:\n    pass\n"
            "json.dump(got, open(os.environ['KEYHOLE_OUTPUT'], 'w'))")


@_needs_bwrap
def test_sandbox_has_no_network(signer):
    out = _run(_probe("import socket\nsocket.create_connection(('1.1.1.1', 53), timeout=2)\n"
                      "got = True"), _PROBE, signer)
    assert out.result.output is False
    assert out.attestation.isolation == "bwrap"


@_needs_bwrap
def test_sandbox_cannot_read_the_signing_key_or_home(signer, monkeypatch, tmp_path):
    # Attack: skip the gate entirely — steal the signing key and forge receipts, or read other
    # datasets and the ledger straight from Keyhole's state directory.
    state = tmp_path / "keyhole-home"
    state.mkdir()
    (state / "dev-signing.key").write_text("PRIVATE KEY")
    monkeypatch.setenv("KEYHOLE_HOME", str(state))
    key = str(state / "dev-signing.key")
    assert _run(_probe(f"got = bool(open({key!r}).read())"), _PROBE, signer).result.output is False
    # Home is an empty tmpfs, except (at most) the one path leading to this interpreter.
    home = os.path.expanduser("~")
    listing = _probe(f"import os\ngot = len(os.listdir({home!r})) > 1")
    assert _run(listing, _PROBE, signer).result.output is False


@_needs_bwrap
def test_sandbox_cannot_leave_files_behind(signer):
    # Attack: drop the dataset somewhere outside the run directory for later pickup.
    drop = "/var/tmp/keyhole-drop-test"
    _run(_probe(f"open({drop!r}, 'w').write(open('customers.csv').read())\ngot = True"),
         _PROBE, signer)
    assert not os.path.exists(drop)


@_needs_bwrap
def test_background_process_does_not_outlive_the_run(signer):
    # Attack: fork a child that keeps running (and holding the data) after the run "ends".
    code = "import os, time\nif os.fork() == 0:\n    time.sleep(30)\ntime.sleep(30)"
    started = time.monotonic()
    out = _run(code, _PROBE, signer, timeout_seconds=2)
    assert time.monotonic() - started < 10
    assert out.audit.status is RunStatus.TIMEOUT


@_needs_bwrap
def test_code_that_forks_normally_still_works(signer):
    # The process cap must stop bombs without breaking ordinary subprocess/multiprocessing use.
    code = ("import os, json\npids = [os.fork() for _ in range(8)]\n"
            "if 0 in pids:\n    os._exit(0)\n"
            "[os.waitpid(p, 0) for p in pids]\n"
            "json.dump(True, open(os.environ['KEYHOLE_OUTPUT'], 'w'))")
    assert _run(code, _PROBE, signer).result.output is True
