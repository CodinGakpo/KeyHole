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
- **M6 — Confidentiality hardening + hostile suite** — local hostile suite green; cloud gating proven end-to-end (M5); more hostile cloud cases pending
- **M7 — MCP server** — tool implemented; transport wiring pending the `mcp` extra
- **M8 — Polish** — README/SECURITY/ARCHITECTURE done; demo gif + diagrams pending

## Beyond the base

**Shipped so far:**

- ✅ **Cumulative exit-bandwidth budget** — a per-principal ledger caps *total* released bits across
  runs (optional rolling window), so drip exfiltration over many conforming runs is bounded, not
  just each run. Proven by `test_drip_exfiltration_over_runs`.
- ✅ **Bounded `array` schema type** — list-shaped answers with a required `max_items`, so their
  exit bandwidth (`max_items × item_bits`) is always finite and disclosed.

Grouped in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md): hardware-anchored attestation (Nitro),
timing-channel mitigation, differential-privacy exit mode, wider/free-form exit opt-in, mediated
private-data fetch, warm pools, a web dashboard, the multi-party clean room, and more. Every new
security claim ships with a hostile test that tries to break it.
