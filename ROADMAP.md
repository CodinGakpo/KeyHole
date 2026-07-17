# Roadmap

The base (marquee MVP) is milestones **M0–M8**; see
[`docs/book/07-milestones-and-roadmap.md`](docs/book/07-milestones-and-roadmap.md). The full,
themed list of future features lives in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md).

## Base milestones

- **M0 — Scaffold + CI + contracts** ✅ (package, models, schema types, tests, this repo)
- **M1 — Local executor + typed exit + bandwidth** ✅ (runs today via `sbx run --local`)
- **M2 — Attestation** ✅ (ed25519 local signer + standalone verifier; KMS signer for cloud)
- **M3 — Egress proxy / "no side exit"** — image written; local two-container harness pending
- **M4 — Terraform AWS infra** — modules scaffolded; not yet applied
- **M5 — Fargate execution end-to-end** — launcher param builder done; wiring pending
- **M6 — Confidentiality hardening + hostile suite** — local hostile suite green; cloud gating pending
- **M7 — MCP server** — tool implemented; transport wiring pending the `mcp` extra
- **M8 — Polish** — README/SECURITY/ARCHITECTURE done; demo gif + diagrams pending

## Beyond the base

Grouped in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md): hardware-anchored attestation (Nitro),
timing-channel mitigation, differential-privacy exit mode, wider/free-form exit opt-in, mediated
private-data fetch, warm pools, a web dashboard, the multi-party clean room, and more. Every new
security claim ships with a hostile test that tries to break it.
