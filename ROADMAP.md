# Roadmap

The base (marquee MVP) is milestones **M0–M8**; see
[`docs/book/07-milestones-and-roadmap.md`](docs/book/07-milestones-and-roadmap.md). The full,
themed list of future features lives in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md).

## Base milestones

- **M0 — Scaffold + CI + contracts** ✅ (package, models, schema types, tests, this repo)
- **M1 — Local executor + typed exit + bandwidth** ✅ (runs today via `sbx run --local`)
- **M2 — Attestation** ✅ (ed25519 local signer + standalone verifier; KMS signer for cloud)
- **M3 — Egress proxy / "no side exit"** ✅ (real-tunneling deny-by-default proxy; Docker harness proves containment: direct egress blocked, unlisted denied, only allowlisted permitted)
- **M4 — Terraform AWS infra** ✅ (free-tier data plane applied to a real account & verified: empty task role, no-NAT route table, deny-all SG, AES256 S3; then destroyed — full apply→destroy lifecycle, ~$0)
- **M5 — Fargate execution end-to-end** ✅ (`run_cloud`: presigned-S3 I/O, launch task, wait, gate, attest — verified on a real cluster: honest run released + attested, hostile exfil withheld + attested; then destroyed, ~$0)
- **M6 — Confidentiality hardening + hostile suite** ✅ (hostile suite green: dump/encode/stdout/fork-bomb/memory-hog/drip-exfiltration all structurally blocked; cloud gating proven on real Fargate in M5; a cloud egress-probe case is scripted in `cloud_smoke.py` and runs on every future apply)
- **M7 — MCP server** ✅ (`mark1-mcp` over stdio, integration-tested end-to-end through the MCP wire: honest run released + attested, exfiltration withheld)
- **M8 — Polish** ✅ (truthful README with architecture diagram + demo transcript + MCP setup; ARCHITECTURE.md matches as-built; `sbx doctor` checks extras)

## Beyond the base

**Shipped so far:**

- ✅ **Web dashboard** — `sbx dashboard` serves a self-contained, read-only viewer (stdlib
  `http.server`) over the local run history: ledger, per-run inspector (hashes, verdict, data-flow
  timeline), an exit-bandwidth aperture gauge, and drag-to-verify attestation checking.
- ✅ **M9 — Cloud control plane (deployable API)** — Lambda + API Gateway HTTP API, DynamoDB
  persistence (append-only audit), and **KMS-signed attestations** (ECDSA P-256; the private key
  never leaves KMS). `sbx run` without `--local` hits the API (async submit/poll). Verified live on
  real AWS: honest run released + KMS-attested, exfil withheld, attestation VALID against the
  exported KMS public key (tamper → INVALID), run + audit persisted; then destroyed (~$1/mo KMS,
  the rest free/pennies).
- ✅ **Cumulative exit-bandwidth budget** — a per-principal ledger caps *total* released bits across
  runs (optional rolling window), so drip exfiltration over many conforming runs is bounded, not
  just each run. Proven by `test_drip_exfiltration_over_runs`.
- ✅ **Bounded `array` schema type** — list-shaped answers with a required `max_items`, so their
  exit bandwidth (`max_items × item_bits`) is always finite and disclosed.

Grouped in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md): hardware-anchored attestation (Nitro),
timing-channel mitigation, differential-privacy exit mode, wider/free-form exit opt-in, mediated
private-data fetch, warm pools, a web dashboard, the multi-party clean room, and more. Every new
security claim ships with a hostile test that tries to break it.
