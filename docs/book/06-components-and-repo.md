# Chapter 6 — Components & Repo Structure

## Guiding principle

Small, well-bounded units with clear interfaces. The three ideas that *are* the product — the
typed exit, the containment, and the attestation — each live in their own module so they can be
understood and tested in isolation. Clients (CLI, MCP) are thin; they carry no logic the API
doesn't.

## The monorepo layout

```
keyhole/
├── README.md  ARCHITECTURE.md  SECURITY.md  ROADMAP.md  STUDY-GUIDE.md  DEMO.md
├── pyproject.toml  Makefile  .pre-commit-config.yaml
├── .github/workflows/ci.yml
├── schemas/          # example output schemas: label.json, score.json, extract-field.json, top-labels.json
├── examples/         # classify.py (honest), exfil.py (hostile), customers.csv
├── src/keyhole/
│   ├── common/       # models.py (RunRequest/RunResult/AuditRecord/DataFlowEvent), hashing.py,
│   │                 #   config.py, api_client.py  — the shared contract
│   ├── schema/       # spec.py (OutputSchema), validate.py, bandwidth.py             ← the guarantee
│   ├── attest/       # record.py, sign.py (ed25519), kms_signer.py (KMS), keys.py,
│   │                 #   verify.py (standalone verifier)                             ← verifiability
│   ├── dlp/          # secret_scan.py, pii_scan.py  — secondary backstop only
│   ├── controlplane/ # gate.py (budget → validate → bandwidth → DLP → release → sign),
│   │                 #   runner.py (local), cloud_runner.py + launcher.py (Fargate), app.py (Lambda),
│   │                 #   budget.py, cleanroom.py, store.py, quotas.py
│   ├── executor/     # entrypoint.py (local subprocess executor), limits.py (rlimits)
│   ├── cli/          # main.py (argparse: run / dataset / verify / keygen / doctor / dashboard)
│   ├── mcp/          # server.py (run_confidential_tool over stdio)
│   └── dashboard/    # server.py + index.html (stdlib http.server, read-only)
├── images/
│   ├── sandbox-python/   # Dockerfile (slim, non-root) + run_in_sandbox.py (in-container runner)
│   └── egress-proxy/     # deny-by-default proxy, kept for future allowlisted egress
├── harness/egress/   # Docker harness for the egress-proxy containment test
├── infra/terraform/
│   ├── modules/ network/ controlplane/ execution/ state/ registry/ guardrails/
│   └── environments/dev/   # main.tf + tf.sh / stack.sh wrappers
├── tests/ unit/  integration/ (Docker egress, MCP wire)  hostile/ (marquee)
└── scripts/ (demo, showtime, build_lambda, cloud_smoke)  docs/
```

## What each unit does

| Unit | Responsibility | Depends on |
|---|---|---|
| `common/models.py` | The shared data contract every component speaks. Define first. | (nothing) |
| `schema/spec.py` | The set of allowed output types. | `common` |
| `schema/validate.py` | Enforce that an output conforms to a schema. | `schema/spec` |
| `schema/bandwidth.py` | Compute a schema's information content (bits). | `schema/spec` |
| `attest/record.py` / `sign.py` / `kms_signer.py` / `verify.py` | Build, sign (ed25519 locally, KMS in the cloud), and independently verify attestations. | `common` |
| `dlp/*` | Secondary secret/PII backstop over the small output. | `common` |
| `controlplane/gate.py` | The exit gate: budget → validate → bandwidth → DLP → release → charge → sign. | `schema`, `attest`, `dlp` |
| `controlplane/budget.py` / `cleanroom.py` | Cumulative per-caller bit budget; two-principal dataset grants. | `common` |
| `controlplane/launcher.py` | Build the hardened `ecs.run_task` call (empty task role, private subnet, no public IP). | `common` |
| `controlplane/store.py` / `quotas.py` | Run state + audit persistence; cost/concurrency guardrails. | `common` |
| `cli/*`, `mcp/*` | Thin clients: the local path in-process, the cloud path over the REST API. | `common/api_client` |
| `executor/entrypoint.py` | Local executor: run the code as an rlimited subprocess, capture the one output. | `common` |
| `images/sandbox-python/run_in_sandbox.py` | In-container runner: fetch the presigned bundle, run the code, PUT the output. | (ships in image) |
| `images/egress-proxy/` | Deny-by-default proxy for a future allowlisted-egress mode (not the enforcement point; see ch. 4). | (standalone) |
| `infra/terraform/*` | One-command deploy of the whole platform. | (AWS) |

## The critical files (where the ideas live)

- `src/keyhole/schema/validate.py` + `schema/bandwidth.py` — the typed-exit guarantee and its
  bandwidth accounting. **The novel core.**
- `src/keyhole/controlplane/gate.py` — the exit gate that ties validation, bandwidth, backstop, and
  attestation together.
- `src/keyhole/attest/sign.py` + `attest/verify.py` — the verifiable-guarantee piece.
- `src/keyhole/controlplane/launcher.py` — where the containment guarantees are encoded into the task
  definition.
- `infra/terraform/modules/network/` — the real proof there is no side network exit: no NAT, no
  internet route, endpoints-only security group.
- `tests/hostile/test_hostile.py` — the marquee: every exfiltration path blocked *and* attested.
