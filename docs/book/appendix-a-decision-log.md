# Appendix A — Decision Log (chronological)

The running record of decisions. Append new entries with dates; don't rewrite old ones. Reversals
get a new entry that references the one they overturn.

## 2026-07-17 → 2026-07-18 — Concept & design phase (Claude Fable)

| # | Decision | Rationale | Status |
|---|---|---|---|
| 1 | Cloud = **AWS** | Largest market; richest security surface. | Locked |
| 2 | Language = **Python** | Builder's strongest; lingua franca of security tooling. | Locked |
| 3 | Problem = **security product devs use** (secure-as-a-service) | Matches the builder's goal and skill intersection. | Locked |
| 4 | Ambition = **student / early-career**, solo, <\$10/mo | Must be buildable and cheap yet production-grade. | Locked |
| 5 | Concept = **AI-code sandbox** (over PR-preview envs, package firewall) | Most timely, clearest product path, hardest/most impressive. | Locked |
| 6 | Backend = **Fargate** (over Lambda / Firecracker-on-EC2 / local-only) | VM-level task isolation, per-second billing, no host ops. | Locked |
| 7 | Interfaces = **CLI + MCP server** | MCP lets AI agents use it directly — the 2026 use case. | Locked |
| 8 | **Rejected** "hardened against competitor's breaches" positioning | Reactive; an arms race; invites attackers to out-engineer. | Rejected |
| 9 | **Rejected** "declare what untrusted code may do" (policy-as-code) premise | Weak: you can't author an allow-policy for unpredictable untrusted code; shifts the boundary onto the user. | Rejected |
| 10 | **Rejected** heuristics/flight-recorder as the *headline* | At builder's request; kept honesty over cleverness. | Rejected |
| 11 | **Rejected** "self-hosted / local" as the core differentiator | Sidesteps the problem; data still lands in the cloud. | Rejected |
| 12 | Thesis = **confidentiality, not isolation** (exfiltration is the real unsolved problem) | Isolation is solved by incumbents; confidentiality isn't. | Locked |
| 13 | **Attestation in the base** (verifiable, KMS-signed) | Turns "trust us" into "verify it"; product-grade. | Locked |
| 14 | Exit model = **typed narrow exit (bandwidth argument)** over free-form + DLP | Content scans are defeated by encrypt-before-emit (confinement problem); bounding bandwidth actually holds. | Locked |
| 15 | Base scope excludes wider/free-form exit | Keep the guarantee crisp; free-form is a roadmap opt-in (best-effort). | Locked |
| 16 | Planning on **Fable**, implementation on **Opus** | User's model-allocation choice. | Noted |
| 17 | Documentation kept as a **chapterwise book** (`docs/book/`) recording every decision | The reasoning trail is part of the deliverable's value. | Locked |

## Open questions carried forward

- Which schema types cover the most real use cases for the flagship demo? (Ch 9)
- Minimal VPC endpoint set for a Fargate ECR pull without a NAT gateway? (Ch 9)
- When to anchor attestation in hardware (Nitro) rather than the control plane? (Ch 4, Ch 9)
