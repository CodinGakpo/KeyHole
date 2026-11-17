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
- **M7 — MCP server** ✅ (`keyhole-mcp` over stdio, integration-tested end-to-end through the MCP wire: honest run released + attested, exfiltration withheld)
- **M8 — Polish** ✅ (truthful README with architecture diagram + demo transcript + MCP setup; ARCHITECTURE.md matches as-built; `sbx doctor` checks extras)

## Beyond the base

**Shipped so far:**

- ✅ **Multi-party clean room** — a data-owner registers a dataset and grants a code-provider, who
  runs code against it by id + grant token without receiving the bytes; the attestation binds both
  identities + the dataset hash. Ungranted providers are refused; cross-principal exfiltration is
  withheld. (`sbx dataset add/grant`, `sbx run --dataset --grant`.)
- ✅ **Web dashboard** — `sbx dashboard` serves a self-contained, read-only viewer (stdlib
  `http.server`) over the local run history: ledger, per-run inspector (hashes, verdict, data-flow
  timeline), an exit-bandwidth aperture gauge, and drag-to-verify attestation checking.
- ✅ **M9 — Cloud control plane (deployable API)** — Lambda + API Gateway HTTP API, DynamoDB
  persistence (append-only audit), and **KMS-signed attestations** (ECDSA P-256; the private key
  never leaves KMS). `sbx run` without `--local` hits the API (async submit/poll). Verified live on
  real AWS: honest run released + KMS-attested, exfil withheld, attestation VALID against the
  exported KMS public key (tamper → INVALID), run + audit persisted; then destroyed (~$1/mo KMS,
  the rest free/pennies).
- ✅ **Cumulative exit-bandwidth budget** — a per-principal ledger caps the *total* bits a caller can
  learn across runs (optional rolling window). Proven by `test_drip_exfiltration_over_runs`.
- ✅ **Run-status side channel closed** — every non-release outcome is identical to the caller (the
  real outcome goes to the owner's audit record), and every run is charged log₂(N + 1) bits,
  released or not. Proven by `test_exit_code_side_channel_is_closed`.
- ✅ **Bounded `array` schema type** — list-shaped answers with a required `max_items`, so their
  exit bandwidth is always finite and disclosed.
- ✅ **Audit fixes** — a true bandwidth bound (canonical release, brute-force check), owner-set
  per-dataset policy and budget, mock-data runs, agent MCP tools and Python API, bubblewrap local
  sandbox, timing and crash channels closed, cloud control-plane hardening. See SECURITY.md.
- ✅ **Cloud clean room** — datasets, grants and policy registered through the API (owner key);
  dataset bytes loaded server-side; atomic per-dataset budget charged at admission.
- ✅ **Benchmarks** — canary leakage and leaderboard probing against a plain code tool
  (`make bench`).

## Next

- **Re-verify the cloud on AWS.** The API auth, S3 endpoint policy, separate in-task uids,
  envelope validation and run deadline are unit-tested but not yet applied to a live stack. Run
  `scripts/cloud_smoke.py` (now with DNS and foreign-bucket probes) before and after.
- **Close DNS in the cloud if the probe shows it open** (Route 53 Resolver DNS Firewall allowlist).
- **A live agent in the canary benchmark**, alongside the scripted one.
- **A hosted-sandbox backend** (E2B or Modal) behind the executor seam, to show Keyhole as the
  exit gate for the sandbox a team already uses. (Local bubblewrap and Docker backends ship.)
- **Mock runs and rolling budget windows in the cloud.**

Then, grouped in [`docs/FUTURE-SCOPE.md`](docs/FUTURE-SCOPE.md): hardware-anchored attestation
(Nitro), timing-channel mitigation, differential-privacy exit mode, wider/free-form exit opt-in,
mediated private-data fetch, warm pools, signed/time-boxed clean-room grants, and more. Every new
security claim ships with a hostile test that tries to break it.
