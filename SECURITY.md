# Security Model & Threat Model

Keyhole's claims are deliberately **bounded and honest**. This document states exactly what is
guaranteed, what is bounded, and what is out of scope. The full reasoning is in
[`docs/book/04-security-and-threat-model.md`](docs/book/04-security-and-threat-model.md).

## The one-sentence model

> Untrusted code may read the supplied data and compute freely, but the only thing that can leave
> the sandbox is a value conforming to the caller's declared schema — bounding any leak to that
> schema's information content, disclosing the exact bytes released via a signed attestation, and
> making bulk exfiltration structurally impossible; covert timing channels and inference leakage
> are out of scope.

## Structurally guaranteed

The first three guarantees come from the **cloud deployment** (Fargate + network + IAM). Local runs
(`sbx run --local`) execute the code as a resource-limited subprocess that *can* reach the network;
locally, only the exit gate's guarantees apply.

- **No network egress.** Containment is enforced at the subnet/route/SG layer — a private subnet
  with no NAT and no internet route, and a run security group whose only egress is to AWS service
  endpoints (S3 prefix list + in-subnet ECR/Logs). Default runs cannot reach the general internet.
  (An in-task egress-proxy sidecar is *not* the enforcement point: Fargate `awsvpc` containers share
  one network namespace, so a sidecar cannot intercept its neighbours. The egress-proxy image and
  its Docker harness are retained for the future allowlisted-egress feature, which needs a different
  enforcement point.)
- **No reachable cloud credentials.** The sandbox task role is **empty** — the metadata endpoint
  vends credentials that can do nothing. (Fargate has no EC2 IMDS.)
- **No persistence.** Read-only root filesystem + ephemeral scratch; the task is destroyed after
  the run.
- **One bounded exit.** The result must validate against the caller's declared narrow schema before
  release. Non-conforming output releases nothing. The exit bandwidth (bits) is computed per run.

## Bounded, not zero

- The declared schema's own information content is a **residual channel**. A malicious script can
  choose the permitted value to encode a few bits. This is **bounded** to the schema's bandwidth
  and **disclosed** — the exact released bytes are recorded in the signed attestation. We never
  claim "zero leak."
- Repeated runs could accumulate that residual. A **per-caller cumulative budget** caps the total
  bits released across runs (`controlplane/budget.py`).

## Known gap: run status is a side channel

The budget charges only *released* runs, but every run's **status is visible to the caller**, and a
failed run reports its exit code (`controlplane/gate.py`). Code can therefore signal through *how*
it fails — up to ~8 bits per run via the exit code, uncharged and unlimited in run count.
Released-vs-withheld and timeout-vs-not carry smaller amounts the same way.

**Planned fix:** return one opaque non-release status with no detail to the caller (details stay in
the audit log for the data owner) and charge the budget for every run. The per-run bound then
becomes log₂(choices + 1) — the extra outcome is "not released". It ships with a hostile test that
attempts exactly this exfiltration.

## Out of scope (named, not hidden)

- **Covert timing / resource side channels.** Mitigations (fixed-duration runs) are on the roadmap.
- **Inference leakage.** A legitimate small answer may itself reveal something about the data; that
  is the caller's modeling concern.
- **Breaking AWS's own task isolation.** Keyhole relies on Fargate isolation as its substrate.

## Attestation trust root

In the cloud, attestations are signed by the control plane with a per-deployment **KMS key**
(ECDSA P-256; the private key never leaves KMS). Locally they are signed with an **ed25519 dev key**
under `~/.keyhole`. Either way the attestation proves what the control plane observed. Hardware-anchored attestation (Nitro Enclaves), which removes the need
to trust the control plane, is on the roadmap.

## Reporting

This is an early personal project, not a production security product. Do not rely on it for real
secrets yet. Issues and findings are welcome via the repository tracker.
