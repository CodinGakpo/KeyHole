# Security Model & Threat Model

Mark-1's claims are deliberately **bounded and honest**. This document states exactly what is
guaranteed, what is bounded, and what is out of scope. The full reasoning is in
[`docs/book/04-security-and-threat-model.md`](docs/book/04-security-and-threat-model.md).

## The one-sentence model

> Untrusted code may read the supplied data and compute freely, but the only thing that can leave
> the sandbox is a value conforming to the caller's declared schema — bounding any leak to that
> schema's information content, disclosing the exact bytes released via a signed attestation, and
> making bulk exfiltration structurally impossible; covert timing channels and inference leakage
> are out of scope.

## Structurally guaranteed

- **No network egress.** No NAT gateway, no internet route; an egress-proxy sidecar denies and logs
  any attempt. Default runs cannot reach the network.
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

## Out of scope (named, not hidden)

- **Covert timing / resource side channels.** Mitigations (fixed-duration runs) are on the roadmap.
- **Inference leakage.** A legitimate small answer may itself reveal something about the data; that
  is the caller's modeling concern.
- **Breaking AWS's own task isolation.** Mark-1 relies on Fargate isolation as its substrate.

## Attestation trust root

The base attestation is signed by the control plane using a per-deployment KMS key; it proves what
the control plane observed. Hardware-anchored attestation (Nitro Enclaves), which removes the need
to trust the control plane, is on the roadmap.

## Reporting

This is an early personal project, not a production security product. Do not rely on it for real
secrets yet. Issues and findings are welcome via the repository tracker.
