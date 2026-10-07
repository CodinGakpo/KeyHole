"""End-to-end local demo of the Keyhole confidentiality guarantee.

Runs two programs against the same private dataset under the same 3-way classification schema:
  1. an honest classifier  -> a bounded, attested answer is released
  2. a malicious exfiltrator -> nothing is released (structurally withheld), yet still attested

No AWS required. Run with ``make demo`` or ``python scripts/demo.py``.
"""

from __future__ import annotations

from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.config import dev_pubkey_path
from keyhole.common.models import Limits, RunRequest
from keyhole.controlplane.runner import run_local
from keyhole.schema.spec import OutputSchema, SchemaType

DATASET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(500))
SCHEMA = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])

HONEST = """
import os, json
rows = open("customers.csv").read().splitlines()
label = "spam" if len(rows) > 100 else "ham"
json.dump(label, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""

MALICIOUS = """
import os, json
json.dump(open("customers.csv").read(), open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""


def _run(name: str, code: str) -> None:
    signer = load_or_create_dev_signer()
    req = RunRequest(
        code=code,
        data={"customers.csv": DATASET},
        output_schema=SCHEMA,
        limits=Limits(timeout_seconds=10),
    )
    outcome = run_local(req, signer)
    r = outcome.result
    verified = verify_attestation(outcome.attestation, dev_pubkey_path().read_bytes())
    print(f"\n[{name}]")
    print(f"  status:      {r.status.value}")
    print(f"  output:      {r.output!r}")
    if r.withheld_reason:
        print(f"  withheld:    {r.withheld_reason}")
    print(f"  bandwidth:   {r.exit_bandwidth_bits:.2f} bits (max that could leave)")
    print(f"  attestation: {r.attestation_id}  (signature {'VALID' if verified else 'INVALID'})")


def main() -> int:
    print("Keyhole local demo — same dataset, same schema, two programs")
    print(f"dataset: {len(DATASET)} bytes; exit schema: 3-way enum (~1.58 bits)")
    _run("honest classifier", HONEST)
    _run("malicious exfiltrator", MALICIOUS)
    print("\nThe dataset is ~%d bytes; the widest the exit can carry is ~1.58 bits." % len(DATASET))
    print("Bulk exfiltration is structurally impossible, not merely scanned-for.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
