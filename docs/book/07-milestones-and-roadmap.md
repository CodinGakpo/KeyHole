# Chapter 7 — Milestones & Roadmap

## The build order and its logic

The differentiator is built **first**, not last. The typed exit + bandwidth engine (M1) and
attestation (M2) are the parts that make Mark-1 *Mark-1*; everything before real AWS execution can
be developed and unit-tested against local Docker, which keeps the inner loop fast and the cloud
bill near zero.

| Milestone | What ships | Why here |
|---|---|---|
| **M0 — Scaffold + CI + contracts** | Repo layout, `pyproject.toml`, lint/type/test, CI. Define `common/models.py` + `schema/spec.py` first. Honest threat-model doc skeleton. | The contract every component shares must exist before the components. |
| **M1 — Local executor + typed exit + bandwidth** | Run code in local Docker, no egress; supply data; validate output against `OutputSchema`; reject non-conforming; compute exit bandwidth. Unit-tested. Minimal non-root, read-only-root-FS image. | This is the heart of the product; prove it locally before touching cloud. |
| **M2 — Attestation** | `attest/sign` (dev key locally, KMS in cloud) + standalone `attest/verify` + `sbx attest verify`. Binds code/data/schema/output hashes + egress verdict. | The verifiable guarantee; small and self-contained. |
| **M3 — Egress proxy / "no side exit"** | Deny-by-default proxy image; sandbox's only route is through it; every attempt logged. Two-container Docker-compose harness (bridge network) proves the proxy concept. *Note:* this enforcement model does **not** carry over to a same-task Fargate sidecar (ch. 4); the proxy is kept for a future separate-task chokepoint. | Prove the containment concept structurally. |
| **M4 — Terraform AWS infra** | All modules; `terraform apply` from an empty account succeeds and `destroy` cleans up; KMS key provisioned. No run yet. | Stand up the cloud substrate independently. |
| **M5 — Fargate execution end-to-end** ✅ | `launcher.py` → `ecs.run_task`; `run_cloud` uploads the input bundle to S3, presigns GET/PUT, launches the task, waits, fetches output, runs the exit gate + ed25519 attestation; task self-destructs. Verified on a real cluster: honest run released + attested, hostile exfil withheld + attested. As-built refinements: read-only-root needs an **init container to chown the scratch volume**; egress is enforced at the **subnet/route/SG layer**, not an in-task sidecar (see ch. 4). | The base happy path, in the cloud. |
| **M6 — Confidentiality hardening + hostile suite (the marquee)** ✅ | Empty task role, egress containment, metadata env-strip, timeouts, data-flow audit. `tests/hostile/` proves dump / encode-in-bounded-string / stdout / fork-bomb / memory-hog / **drip-exfiltration-across-runs** are all structurally blocked *and* attested. Cloud egress assertion scripted in `cloud_smoke.py` (runs each apply). | This milestone **is** the product. See [Chapter 8](08-verification.md). |
| **M7 — MCP server** ✅ | `run_confidential` over stdio (`mark1-mcp`), integration-tested **through the MCP wire**: honest run released + attested, exfiltration withheld. `principal` passthrough for budget-aware callers. | Small; reuses the exit gate. The headline demo. |
| **M8 — Polish** ✅ | Truthful README (status, mermaid architecture diagram, `make demo` transcript, MCP setup), ARCHITECTURE.md corrected to as-built, `sbx doctor` checks the mcp/cloud extras + dev key. | Make it legible and installable. |
| **M9 — Cloud control plane (beyond base)** ✅ | Lambda + API Gateway HTTP API with an **async submit/poll** lifecycle (fits the ~29s gateway timeout despite Fargate cold start), DynamoDB persistence (append-only audit), and **KMS-signed attestations** (ECDSA P-256; private key never leaves KMS). `sbx run` without `--local` drives the API. Verified live end-to-end then destroyed: honest released + KMS-attested, exfil withheld, attestation VALID vs the exported KMS public key (tamper → INVALID). | Makes the "one `terraform apply` → a confidential-execution API in your own account" pitch literally true. |

## Beyond the base (shipped)

- **Cumulative exit-bandwidth budget** — a per-principal ledger caps *total* released bits across
  runs, so drip exfiltration over many conforming runs is bounded too.
- **Bounded `array` schema type** — list answers with a required `max_items`, bandwidth still finite.
- **Web dashboard** (`sbx dashboard`) — a self-contained, read-only viewer of the run/audit trail
  whose signature element is the exit-bandwidth aperture gauge.
- **Multi-party clean room** — the enterprise form of the thesis. A **data-owner** registers a
  dataset (`sbx dataset add`) and grants a **code-provider** (`sbx dataset grant`); the provider runs
  against it by id + grant token (`sbx run --dataset --grant`) and **never receives the bytes**. The
  attestation binds *both* identities plus the dataset hash, so the owner gets proof of who ran what
  on their data and how little left. Ungranted providers are refused before anything runs; the
  bandwidth guarantee holds across principals. Local MVP — grants are bearer tokens (production:
  signed + time-boxed); infra-level IAM separation is the cloud follow-up.

## Definition of done for the base

`sbx run classify.py --data emails.csv --schema label.json` runs untrusted Python on the supplied
data in an ephemeral, zero-egress Fargate task; returns *only* a schema-conforming value plus a
KMS-signed attestation; the task is destroyed; the hostile exfiltration suite is green; the whole
platform deploys into a fresh AWS account with one `terraform apply` and stays under budget.

## The roadmap

Future features live in a dedicated, living document rather than being buried here:
see [`docs/FUTURE-SCOPE.md`](../FUTURE-SCOPE.md). It is the canonical list of what to build next,
grouped by theme (guarantee-strengthening, usability, scale, ecosystem, product). Chapter 8 covers
how each new claim must be backed by a test before it ships.
