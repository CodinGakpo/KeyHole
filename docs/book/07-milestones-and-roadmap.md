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
| **M3 — Egress proxy / "no side exit"** | Deny-by-default proxy image; sandbox's only route is through it; every attempt logged. Two-container compose mirroring the Fargate sidecar layout. | Prove containment structurally before deploying it. |
| **M4 — Terraform AWS infra** | All modules; `terraform apply` from an empty account succeeds and `destroy` cleans up; KMS key provisioned. No run yet. | Stand up the cloud substrate independently. |
| **M5 — Fargate execution end-to-end** | `launcher.py` → `ecs.run_task`; push images; supply data, run in cloud, exit-gated typed output + KMS-signed attestation returned via S3; task self-destructs. | The base happy path, in the cloud. |
| **M6 — Confidentiality hardening + hostile suite (the marquee)** | Empty task role, egress deny, metadata env-strip, seccomp, timeouts, complete data-flow audit verified. `tests/hostile/` proves every exfil path is blocked *and* attested. | This milestone **is** the product. See [Chapter 8](08-verification.md). |
| **M7 — MCP server** | `run_confidential` / `get_result` / `get_attestation`; wire into an AI agent — the "agent on private data, structural no-exfiltration" demo. | Small; reuses the API. The headline demo. |
| **M8 — Polish** | README (thesis + honesty + one-command deploy + demo gif), architecture diagram, schema & attestation reference docs, cost model, `sbx doctor`, quotas/Budgets surfaced. | Make it legible and installable. |

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
