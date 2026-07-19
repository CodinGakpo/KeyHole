"""End-to-end cloud smoke test: run an honest and a hostile program on real Fargate.

Reads deployment coordinates from the environment (populated from `terraform output`) and runs
three programs against the same private dataset:
  1. honest classifier   -> a bounded, attested answer is released
  2. malicious exfiltrator -> nothing is released (structurally withheld), yet still attested
  3. egress probe        -> proves the box has no internet path (returns False, released)

Requires the `cloud` extra (boto3) and AWS credentials. Invoked by the M5 verification flow.
"""

from __future__ import annotations

import os
import sys

from mark1.attest.keys import load_or_create_dev_signer
from mark1.attest.verify import verify_attestation
from mark1.common.config import dev_pubkey_path
from mark1.common.models import Limits, RunRequest
from mark1.controlplane.cloud_runner import CloudConfig, run_cloud
from mark1.schema.spec import OutputSchema, SchemaType

DATASET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(300))
SCHEMA = OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham", "other"])

HONEST = """
import os, json
rows = open("customers.csv").read().splitlines()
label = "spam" if len(rows) > 100 else "ham"
json.dump(label, open(os.environ["MARK1_OUTPUT"], "w"))
"""

MALICIOUS = """
import os, json
json.dump(open("customers.csv").read(), open(os.environ["MARK1_OUTPUT"], "w"))
"""

# Attempts real internet egress from inside the box; reports honestly whether it got out.
# In the contained subnet (no NAT, endpoints-only SG) this must release False.
EGRESS_PROBE = """
import os, json, socket
try:
    socket.create_connection(("example.com", 443), timeout=5)
    reached = True
except OSError:
    reached = False
json.dump(reached, open(os.environ["MARK1_OUTPUT"], "w"))
"""

BOOL_SCHEMA = OutputSchema(type=SchemaType.BOOLEAN)


def _config() -> CloudConfig:
    missing = [
        k
        for k in ("MARK1_REGION", "MARK1_CLUSTER", "MARK1_TASK_DEF", "MARK1_SUBNET", "MARK1_SG", "MARK1_BUCKET")
        if not os.environ.get(k)
    ]
    if missing:
        sys.exit(f"missing env: {', '.join(missing)} (populate from `terraform output`)")
    return CloudConfig(
        region=os.environ["MARK1_REGION"],
        cluster=os.environ["MARK1_CLUSTER"],
        task_definition=os.environ["MARK1_TASK_DEF"],
        subnet_id=os.environ["MARK1_SUBNET"],
        security_group_id=os.environ["MARK1_SG"],
        bucket=os.environ["MARK1_BUCKET"],
    )


def _run(name: str, code: str, config: CloudConfig, schema: OutputSchema = SCHEMA):
    signer = load_or_create_dev_signer()
    req = RunRequest(
        code=code, data={"customers.csv": DATASET}, output_schema=schema, limits=Limits(timeout_seconds=60)
    )
    outcome, task_arn = run_cloud(req, config, signer)
    r = outcome.result
    verified = verify_attestation(outcome.attestation, dev_pubkey_path().read_bytes())
    print(f"\n[{name}]  task={task_arn.rsplit('/', 1)[-1]}")
    print(f"  status:      {r.status.value}")
    print(f"  output:      {r.output!r}")
    if r.withheld_reason:
        print(f"  withheld:    {r.withheld_reason}")
    print(f"  bandwidth:   {r.exit_bandwidth_bits:.2f} bits")
    print(f"  attestation: {r.attestation_id} (signature {'VALID' if verified else 'INVALID'})")
    return r


def main() -> int:
    config = _config()
    print(f"Cloud smoke test on Fargate (cluster={config.cluster}, region={config.region})")
    honest = _run("honest classifier", HONEST, config)
    hostile = _run("malicious exfiltrator", MALICIOUS, config)
    probe = _run("egress probe (expects False)", EGRESS_PROBE, config, schema=BOOL_SCHEMA)

    ok = (
        honest.status.value == "succeeded"
        and hostile.status.value == "withheld"
        # The probe run must SUCCEED (a boolean is conforming) with output False:
        # the network, not the gate, is what stops egress.
        and probe.status.value == "succeeded"
        and probe.output is False
    )
    print("\nRESULT:", "PASS ✓" if ok else "FAIL ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
