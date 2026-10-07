# Chapter 5 — Architecture: how a run flows

## The shape of the system

Keyhole has four moving parts:

1. **Clients** — a CLI (`sbx`) and an MCP server (`run_confidential`), both thin wrappers over the
   same REST API.
2. **Control plane** — a Lambda behind an API Gateway HTTP API. Validates requests, launches
   sandboxes, runs the exit gate, signs attestations, records audit.
3. **Sandbox task** — an ephemeral ECS Fargate task: an init container that chowns the scratch
   volume, then the sandbox container (runs the untrusted code) under a read-only root filesystem.
   Egress is contained by the private subnet + run security group, not by an in-task sidecar (ch. 4).
4. **State & storage** — DynamoDB (run state + append-only audit), S3 (code, data, schema, output,
   attestation, data-flow log), ECR (images), KMS (encryption + attestation signing).

## A run, end to end

```
sbx run classify.py --data emails.csv --schema label.json
        │
        ▼
POST /runs  (code + data + schema + limits)
        │
        ▼
Control plane (Lambda)
  • validate the schema
  • write PENDING run + audit record (DynamoDB)
  • upload code + data + schema to S3 (KMS-encrypted)
  • ecs.run_task  →  Fargate task (init-chown + sandbox), hardened task def
        │
        ▼
Fargate task
  • network: private subnet, no NAT, endpoints-only SG (no internet route)
  • sandbox: download code/data/schema via S3 gateway endpoint (presigned)
  • executor: run code as non-root, no network, no creds, under a timeout
  • code writes its result to the designated typed output
  • executor records egress/file attempts → data-flow log
  • write output + data-flow log to S3;  task self-destructs
        │
        ▼
Control plane exit gate
  • validate output against the schema  (reject → release nothing)
  • compute exit bandwidth (bits)
  • backstop DLP scan (secondary)
  • emit KMS-signed attestation
  • finalize audit record
        │
        ▼
GET /runs/{id}         → released output + attestation
GET /runs/{id}/audit   → data-flow record
sbx attest verify      → independently verify the attestation
```

## Why each big choice

- **Fargate, one task per run.** VM-level task isolation, per-second billing (a run costs fractions
  of a cent), no hosts to manage. Cold start (~10–30 s) is acceptable for the base; warm pools are
  roadmap.
- **Egress enforced at the network layer (not a same-task sidecar).** Containment is a private
  subnet with no NAT plus a run security group whose only egress is to AWS service endpoints. A
  same-task egress-proxy *sidecar cannot* enforce this on Fargate — `awsvpc` containers share one
  network namespace, so the sidecar is a peer, not a gateway (discovered in M5; see ch. 4). The
  proxy image is retained for a future allowlisted-egress chokepoint (a separate proxy task).
- **Lambda control plane.** Scales to zero → ~\$0 when idle, which is what keeps the whole thing
  inside a <\$10/month budget. Fully expressible in Terraform for one-command deploy.
- **No NAT gateway.** A NAT gateway alone (~\$32/month) would blow the budget, so the network is
  designed around *not needing* one: default runs have no egress, and image/data I/O uses a **free
  S3 gateway endpoint** plus a minimal set of interface endpoints (ECR, Logs) that are made
  *opt-in at deploy time* so an idle deployment costs about nothing.
- **Data supplied into the box.** The caller uploads the data (delivered in-cloud via the S3
  gateway endpoint); the code never fetches data itself over the network. This keeps the
  "no network" guarantee clean. Mediated fetch from a private source is a roadmap extension.

## IAM: three roles, one of them empty

- **Control-plane role** (Lambda): scoped `ecs:RunTask`/`StopTask`, `iam:PassRole` for only the
  task/exec roles, scoped DynamoDB/S3/Logs, and KMS sign + encrypt.
- **Task execution role** (used by the ECS agent, not the code): ECR pull + Logs write only.
- **Task role** (the sandbox's own identity): **empty.** This is the "no reachable credentials"
  guarantee made concrete — even if the code hits the metadata endpoint, the credentials do
  nothing.

The full component/file breakdown is in [Chapter 6](06-components-and-repo.md).
