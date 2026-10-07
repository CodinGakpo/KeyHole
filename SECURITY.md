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
- **Run status is opaque.** Code could also signal through *how* a run fails (crash, timeout, exit
  code 0–255). So the caller sees only "released + value" or one fixed "withheld"; the real outcome,
  reason and exit code go to the data owner's audit record. One run therefore reveals at most
  log₂(N + 1) bits for a schema with N possible values. Proven by
  `test_exit_code_side_channel_is_closed`, which exits with secret bytes and checks that every
  non-release outcome looks identical to the caller.
- **Repetition is capped.** A **per-caller cumulative budget** charges every run log₂(N + 1) bits,
  released or not, and once it is spent every further run is withheld regardless of what the code
  does (`controlplane/budget.py`).
- **Caveat — audit access.** The cloud API has no authentication yet, so its owner-detail audit endpoint (`GET /runs/{id}/audit`) is readable by anyone with the URL. Opaque status holds only if the
  caller cannot read the owner's audit; the API needs authentication before that is true in the
  cloud. Locally, whoever supplies `--data` is the owner and sees the detail.

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
