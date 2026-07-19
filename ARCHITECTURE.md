# Architecture

A short map; the narrative version is [`docs/book/05-architecture.md`](docs/book/05-architecture.md).

## Components

- **Clients** — `sbx` CLI and an MCP server (`run_confidential`), both thin wrappers over one REST
  API (and an in-process local path).
- **Control plane** — a Lambda behind an API Gateway HTTP API. Validates requests, launches
  sandboxes, runs the **exit gate**, signs attestations, records audit. Scales to zero.
- **Sandbox task** — an ephemeral ECS Fargate task: an init container chowns the scratch volume,
  then the sandbox container runs the untrusted code (empty task role, read-only root FS). Egress
  containment is enforced by the **network** — private subnet, no NAT, endpoints-only run security
  group — not by an in-task sidecar (Fargate `awsvpc` containers share one network namespace, so a
  sidecar cannot intercept its neighbours; see book ch. 4).
- **State & storage** — DynamoDB (`mark1_runs`, append-only `mark1_audit`), S3 (code/data/schema/
  output/attestation, SSE-KMS), ECR (images), KMS (encryption + attestation signing).

## A run

```
sbx run code.py --data d.csv --schema s.json
  → POST /runs (code + data + schema + limits)
  → control plane: validate schema, upload input bundle to S3, presign GET (input) + PUT (output)
  → ecs.run_task → Fargate: init-chown, then sandbox fetches the presigned bundle, runs the code
    (no internet route, empty task role, read-only root), PUTs the output envelope back to S3
  → control plane EXIT GATE: validate vs schema → bandwidth (+ cumulative budget) → DLP backstop
    → sign attestation → release or withhold
  → GET /runs/{id} returns released output + attestation; sbx verify checks it independently
```

## Key choices (and why)

- **Fargate, one task/run** — VM-level isolation, per-second billing, no host ops.
- **No NAT gateway** — a NAT alone (~$32/mo) would break the budget; default runs need no egress.
  Free S3 gateway endpoint + opt-in ECR/Logs interface endpoints keep idle ≈ $0.
- **Lambda control plane** — scales to zero; ~$0 idle; fully Terraform-expressible.
- **Empty task role** — the no-reachable-credentials guarantee, made concrete.
- **Same exit gate everywhere** — local and cloud runs share `controlplane/gate.py`, so the
  guarantee is identical across CLI, API, and MCP.
