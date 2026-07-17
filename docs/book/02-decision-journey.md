# Chapter 2 — The Decision Journey: every pivot and why

This chapter is the honest, blow-by-blow record of how the concept evolved. Each pivot was driven
by a specific weakness spotted in the previous idea. The rejections are the point.

## Stage 0 — Fixing the coordinates

Before any concept, four choices set the frame:

- **Cloud → AWS.** Largest job market and the richest security surface (IAM, CloudTrail, VPC).
- **Language → Python.** The builder's strongest language and the lingua franca of security
  automation.
- **Problem area → security, as a product developers use.** Not a narrow tool — something that *is*
  secure-as-a-service or improves security on the side.
- **Ambition → student / early-career.** Must be buildable solo, on a tiny budget, yet look
  production-grade.

## Stage 1 — Pick a concept: the AI-code sandbox

Three concepts were weighed: an AI-code sandbox service, per-PR preview environments, and a
package-firewall proxy. The **sandbox** won: most timely (2026 = everyone runs AI-generated code,
few run it safely), clearest product path, hardest and most impressive isolation engineering. See
[Appendix B](appendix-b-alternatives-considered.md) for the full comparison.

Backend chosen: **AWS Fargate** (serverless containers, VM-level task isolation, per-second
billing) over Lambda (too constrained), Firecracker-on-EC2 (too much ops for a solo MVP), and
local-Docker-only (weakens the cloud story). Interfaces: **CLI + MCP server** so AI agents can use
it directly.

## Stage 2 — The first hard question: "how is this different from AgentCore?"

The builder immediately challenged the premise: AWS already ships a managed code-interpreter
sandbox. Answering "we patched the specific attacks that hit theirs" was tempting — and **wrong**.

> **Pivot 1 — Rejected "hardened against the competitor's breaches."**
> **Why:** It's *reactive* — a point-in-time patch status dressed up as a product. It's an
> arms race you're always one step behind in, and it openly *invites* attackers to out-engineer
> you. A durable differentiator can't be "our box is harder to break."

## Stage 3 — Reframe to "governed, observable execution"

Next attempt: compete not on unbreakable isolation but on *governance + observability*. Every run
governed by a declarative policy (allow/deny lists) enforced at the Python runtime via audit hooks,
plus a behavioral "flight recorder," plus heuristics. A rule-based + heuristic + hybrid approach.

> **Pivot 2 — Rejected the "declare what untrusted code may do" premise.**
> **Why:** It's a *weak premise*. If the code is untrusted and AI-generated, the person running it
> usually *cannot* predict what it legitimately needs — so authoring an allow-policy per run is
> both friction and a false sense of security. It puts the security boundary in the user's hands,
> where a misconfiguration means exposure. Also dropped the heuristics-as-headline framing at the
> builder's request.

## Stage 4 — Reframe to "self-hosted in your own account"

Next attempt: the differentiator is *ownership* — deploy the whole thing into your own AWS account
with one `terraform apply`; your data never goes to a third-party SaaS.

> **Pivot 3 — Rejected "self-hosted / local" as the core differentiator.**
> **Why:** It *sidesteps* the hard problem instead of solving it. The data still lands in the
> cloud; "keep it in your own account" just relocates the risk, it doesn't neutralize it. For a
> security project, avoiding the cloud threat is avoidance, not an achievement. The builder's exact
> push: solve the problem, don't dodge it.

## Stage 5 — Name the real problem: confidentiality, not isolation

Stripping away the sidesteps left the actual hard, unsolved, cloud-native problem:
**data exfiltration.** Isolation is solved; confidentiality isn't. This became the thesis:
untrusted code can compute on data you supply, but the *only* thing that can leave is a single,
inspected result. The **confidential execution box.**

## Stage 6 — Make the guarantee verifiable

The builder pressed for *revolutionary and productizable*, not incremental. Answer: don't make the
confidentiality claim "trust our scanner" — make it **verifiable** with a cryptographically signed
attestation of exactly what ran and what came out.

> **Decision — Attestation is in the base**, not a roadmap nicety. It's the leap from "a secure
> sandbox" to "a verifiable confidential-compute primitive."

## Stage 7 — The crux: how the exit actually works

The final and most important decision. A free-form result inspected by DLP is **not** a real
guarantee — encrypt-before-emit defeats any content scan (this is the confinement problem, see
[Chapter 3](03-the-core-idea.md)). So:

> **Decision — Typed narrow exit (a bandwidth argument).** Untrusted code may return *only* a value
> matching a caller-declared narrow schema (int / enum / bounded string / small record). When the
> exit is a few bytes wide, bulk exfiltration is *structurally impossible*, not "scanned for." DLP
> becomes a secondary backstop; the **bandwidth bound is the guarantee.**

## Where it landed

Mark-1 = **confidential code execution with a bandwidth-bounded, attested exit.** Categorically
distinct from isolation-first sandboxes (free-form output) and from confidential-computing enclaves
like Nitro (which protect *trusted* workloads from the host, not *untrusted* code from leaking).
The full chronological log is [Appendix A](appendix-a-decision-log.md).
