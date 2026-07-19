# Mark-1 — Future Scope

The living list of features to build **after** the base (M0–M8). Grouped by theme. Nothing here is
required for the marquee MVP; everything here is a real direction the project can grow into. Each
item notes roughly why it matters and how hard it is. When you start one, move it into a milestone
and give it a hostile test (see [book Ch 8](book/08-verification.md)).

> **Rule for every item:** a new security claim ships only with a hostile test that tries to break
> it. New claim → new adversary script → assertion.

## A. Strengthen the guarantee

- **Hardware-anchored attestation (Nitro Enclaves).** Move signing into a hardware enclave so the
  attestation doesn't depend on trusting the control plane. *Why:* the strongest possible trust
  root. *Hard:* needs specific EC2 instance types (budget impact) and enclave tooling.
- **Timing / side-channel mitigation.** Fixed-duration runs, output-release quantization, resource
  normalization to shrink covert timing channels. *Why:* closes a currently out-of-scope class.
  *Medium.*
- **Differential-privacy exit mode.** Optional noise on numeric outputs so even the bounded answer
  doesn't reveal individual records. *Why:* addresses inference leakage. *Hard.*
- ✅ **Schema-bandwidth budget enforcement.** *Done* — a per-principal cumulative exit-bits ledger
  (`controlplane/budget.py`) enforced at the exit gate, with an optional rolling window. Repeated
  small leaks can no longer accumulate past the cap; proven by the `test_drip_exfiltration_over_runs`
  hostile test. *Why:* defends the residual channel over time.
- **Reproducible/deterministic execution.** Pin the environment and detect nondeterminism so an
  attestation is reproducible. *Why:* strengthens verifiability. *Medium.*

## B. Widen usefulness (without breaking the base guarantee)

- **Wider / free-form exit opt-in.** Explicitly downgraded to best-effort DLP, for callers who
  accept the trade-off. *Why:* flexibility. *Easy–Medium.* (Must be clearly labeled as a downgrade.)
- **Richer schema types.** ✅ *Bounded arrays done* (`array` with required `max_items` + `items`;
  bandwidth = `max_items × item_bits`, so a list answer can't become a hidden wide exit). Still to
  do: typed records, numeric tolerances, structured extraction schemas. *Why:* covers more real
  tasks. *Medium.*
- **Mediated data fetch (broker).** Let the box read a private DB/API through a broker that enforces
  access rules and logs everything — without granting the code general network. *Why:* removes the
  "upload all data first" constraint. *Hard.*
- **Streaming / long-running sessions.** Stateful sandboxes across an agent's iterative loop. *Why:*
  matches how agents actually work. *Hard.*
- **More languages.** Per-language executors (Node, Ruby) with the same typed-exit + containment
  model. *Why:* broadens the audience. *Medium each.*

## C. Scale & performance

- **Warm pools.** Pre-warmed Fargate tasks to kill the ~10–30 s cold start. *Why:* demo/UX. *Medium.*
- **Firecracker/microVM backend.** Sub-second starts and stronger isolation. *Why:* performance +
  cred. *Hard.*
- **Concurrency & quotas at scale.** Per-org fair scheduling, backpressure. *Medium.*

## D. Ecosystem & DX

- ✅ **Web dashboard.** *Done* — `sbx dashboard` serves a self-contained, read-only viewer
  (stdlib `http.server`, no framework/CDN) over the local run history: a run ledger, a per-run
  inspector (bound hashes, verdict, data-flow timeline), the **exit-bandwidth aperture** gauge, and
  drag-an-attestation signature verification. Pointing it at DynamoDB for cloud runs is a small
  follow-up. *Why:* makes the audit trail legible.
- **Policy-as-code CI gate.** Fail a build if a run would violate its declared exit schema. *Why:*
  DevSecOps integration. *Medium.*
- **SDKs.** Thin Python/TS client libraries over the REST API. *Easy.*
- **`sbx doctor` deep checks + cost estimator.** Preflight and per-run cost projection. *Easy.*
- **Attestation verification service / badge.** A public endpoint (or offline tool) that verifies an
  attestation and renders a shareable proof. *Medium.*

## E. Product / go-to-market

- **Multi-party clean room.** Model data-owner and code-provider as separate principals — "let an
  external party's AI run on MY data." *Why:* the real enterprise product. *Hard.*
- **Multi-tenant auth & orgs.** Beyond the single-deployer base. *Medium.*
- **Compliance mappings.** Map the attestation + audit trail to SOC2 / HIPAA / GDPR controls. *Why:*
  what regulated buyers actually need. *Medium.*
- **Managed-hosting option.** A hosted control plane for teams that don't want to self-deploy.
  *Medium.*

## F. Research-flavored bets

- **Compute-on-encrypted-data (FHE) exploration** for specific operators. *Very hard; long-term.*
- **Formal bandwidth proofs.** Machine-checked proof that a schema's exit bandwidth is what we
  claim. *Hard; high-signal.*
- **ML-based anomaly scoring** over data-flow records (as *advisory* signal, never the guarantee).
  *Medium.*
