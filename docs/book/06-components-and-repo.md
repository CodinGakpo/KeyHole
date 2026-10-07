# Chapter 6 — Components & Repo Structure

## Guiding principle

Small, well-bounded units with clear interfaces. The three ideas that *are* the product — the
typed exit, the containment, and the attestation — each live in their own module so they can be
understood and tested in isolation. Clients (CLI, MCP) are thin; they carry no logic the API
doesn't.

## The monorepo layout

```
keyhole/
├── README.md ARCHITECTURE.md SECURITY.md ROADMAP.md
├── pyproject.toml  Makefile  .pre-commit-config.yaml
├── .github/workflows/ci.yml
├── schemas/          # example output schemas: label.json, score.json, extract-field.json
├── src/keyhole/
│   ├── common/       # models.py (RunRequest/OutputSchema/RunResult/Attestation/AuditRecord/DataFlowEvent),
│   │                 #   config.py, api_client.py  — the shared contract
│   ├── schema/       # spec.py (supported output types), validate.py, bandwidth.py   ← the guarantee
│   ├── attest/       # sign.py (KMS), verify.py (standalone verifier), record.py      ← verifiability
│   ├── dlp/          # secret_scan.py, pii_scan.py  — secondary backstop only
│   ├── controlplane/ # app.py, handlers/, launcher.py, store.py, quotas.py,
│   │                 #   gate.py (validate → bandwidth → attest → release/withhold)
│   ├── cli/          # main.py (Typer: run/result/attest verify/audit/status/doctor), stream.py
│   ├── mcp/          # server.py (run_confidential / get_result / get_attestation)
│   └── executor/     # entrypoint.py (runs in the sandbox), limits.py
├── images/
│   ├── sandbox-python/   # Dockerfile (slim, non-root, read-only root FS), seccomp.json
│   └── egress-proxy/     # tiny deny-by-default proxy w/ connection logging
├── infra/terraform/
│   ├── modules/ network/ controlplane/ execution/ state/ registry/ guardrails/
│   └── environments/dev/
├── tests/ unit/  integration/ (LocalStack)  hostile/ (marquee)
└── scripts/  docs/
```

## What each unit does

| Unit | Responsibility | Depends on |
|---|---|---|
| `common/models.py` | The shared data contract every component speaks. Define first. | (nothing) |
| `schema/spec.py` | The set of allowed output types. | `common` |
| `schema/validate.py` | Enforce that an output conforms to a schema. | `schema/spec` |
| `schema/bandwidth.py` | Compute a schema's information content (bits). | `schema/spec` |
| `attest/sign.py` / `verify.py` / `record.py` | Build, sign, and independently verify attestations. | `common` |
| `dlp/*` | Secondary secret/PII backstop over the small output. | `common` |
| `controlplane/gate.py` | The exit gate: validate → bandwidth → backstop → attest → release. | `schema`, `attest`, `dlp` |
| `controlplane/launcher.py` | Build the hardened `ecs.run_task` call (empty task role, private subnet, sidecar). | `common` |
| `controlplane/store.py` / `quotas.py` | Run state + audit persistence; cost/concurrency guardrails. | `common` |
| `cli/*`, `mcp/*` | Thin clients over the REST API. | `common/api_client` |
| `executor/entrypoint.py` | Runs inside the sandbox: fetch inputs, run code, capture typed output, record attempts. | (ships in image) |
| `images/egress-proxy/` | The single network chokepoint; deny-by-default + logging. | (standalone) |
| `infra/terraform/*` | One-command deploy of the whole platform. | (AWS) |

## The critical files (where the ideas live)

- `src/keyhole/schema/validate.py` + `schema/bandwidth.py` — the typed-exit guarantee and its
  bandwidth accounting. **The novel core.**
- `src/keyhole/controlplane/gate.py` — the exit gate that ties validation, bandwidth, backstop, and
  attestation together.
- `src/keyhole/attest/sign.py` + `attest/verify.py` — the verifiable-guarantee piece.
- `src/keyhole/controlplane/launcher.py` — where the containment guarantees are encoded into the task
  definition.
- `images/egress-proxy/` — the physical proof there is no side network exit.
- `tests/hostile/test_hostile.py` — the marquee: every exfiltration path blocked *and* attested.
