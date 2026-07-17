# Appendix B — Alternatives Considered & Rejected

The paths not taken, preserved because they show the shape of the decision space.

## Concept alternatives (Stage 1)

| Concept | What it was | Why not chosen |
|---|---|---|
| **PR preview environments** | Per-PR ephemeral deploys of a branch to isolated AWS. | Strong DevOps signal but crowded space; security is secondary. |
| **Package firewall proxy** | A proxy between devs and PyPI/npm that quarantines typosquats, brand-new packages, malicious install scripts. | Security-pure and real, but narrower; less of a "platform" story. |
| **AI-code sandbox** ✅ | Disposable, locked-down execution for untrusted / AI code via CLI + MCP. | **Chosen:** most timely, clearest product path, hardest engineering. |

## Backend alternatives (Stage 1)

| Backend | Why not chosen |
|---|---|
| **Lambda-based execution** | 15-min cap, awkward for arbitrary containers/network control; weaker isolation story. |
| **Firecracker microVMs on EC2** | The "real" E2B tech and maximum cred, but you manage EC2 hosts — hardest path for a solo MVP. Roadmap. |
| **Local Docker only** | Fastest to a demo, but weakens the cloud story if cloud slips. |
| **ECS Fargate** ✅ | VM-level task isolation, per-second billing, no host ops — the pragmatic answer. |

## Positioning alternatives (Stages 2–5)

| Positioning | Why rejected |
|---|---|
| **"Hardened against AgentCore's breaches"** | Reactive; arms race; invites attackers to out-engineer you. |
| **Policy-as-code + flight recorder + heuristics** | Rested on the weak premise of "authorize untrusted code"; put the boundary on the user. |
| **Self-hosted / your-own-account as the core value** | Sidesteps the hard problem; data still lands in the cloud. |
| **Confidentiality-first, bandwidth-bounded, attested** ✅ | Solves the real problem in place; a different category; honest and verifiable. |

## Exit-channel alternatives (Stage 7)

| Exit model | Why not chosen |
|---|---|
| **Free-form output + DLP + attestation** | Best-effort only — encrypt-before-emit defeats content scanning (confinement problem). The weaker, incremental story. |
| **Tiered: typed default, free-form opt-in** | More flexible and honest about trade-offs, but more surface to build and explain in the base. Deferred to roadmap. |
| **Typed narrow exit + attestation** ✅ | The guarantee becomes a *bandwidth argument* that actually holds. Chosen for the base. |

## Related industry approaches (for context)

| Approach | Relationship to Mark-1 |
|---|---|
| **E2B / Modal / Daytona / AWS AgentCore** | Isolation-first, free-form output. Different question (protect host from code). |
| **AWS Nitro Enclaves / confidential computing** | Protect a *trusted* workload's data from the host. Mark-1 protects a data owner from *untrusted* code. Nitro is a roadmap backend to strengthen attestation. |
| **AWS Clean Rooms / data clean rooms** | Multi-party privacy-preserving analytics. The multi-party clean-room is a roadmap direction for Mark-1. |
