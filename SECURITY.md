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
use **bubblewrap** when it is installed: no network, a private PID namespace, the user's home and
Keyhole's state (signing key, datasets, ledger) hidden, only the run directory writable.
`KEYHOLE_SANDBOX=docker` uses a throwaway container instead (no network, read-only root, all
capabilities dropped, memory and PID limits, removed on timeout). Without
either the code runs as a plain subprocess that can reach the network and read the user's
files, a warning is printed, and the receipt says `isolation: none`; then only the exit gate's
guarantees apply. Every receipt records which sandbox ran the code.

- **No network egress.** Containment is enforced at the subnet/route/SG layer — a private subnet
  with no NAT and no internet route, and a run security group whose only egress is to AWS service
  endpoints (S3 prefix list + in-subnet ECR/Logs). The S3 gateway endpoint policy admits only the
  artifacts bucket's `runs/` prefix and ECR's layer bucket, so a presigned URL for another bucket
  is not a way out. **Unverified:** whether the VPC resolver lets the box resolve public names,
  which would be a DNS channel; `scripts/cloud_smoke.py` now probes it, and a Resolver DNS Firewall
  allowlist is the fix if it does.
  (An in-task egress-proxy sidecar is *not* the enforcement point: Fargate `awsvpc` containers share
  one network namespace, so a sidecar cannot intercept its neighbours. The egress-proxy image and
  its Docker harness are retained for the future allowlisted-egress feature, which needs a different
  enforcement point.)
- **No reachable cloud credentials.** The sandbox task role is **empty** — the metadata endpoint
  vends credentials that can do nothing. (Fargate has no EC2 IMDS.)
- **No persistence.** Read-only root filesystem + ephemeral scratch; the task is destroyed after
  the run.
- **One bounded exit.** The result must validate against the declared schema before release, and
  what is released is a value rebuilt from the schema (the schema's own enum choice, objects in
  schema order, numbers as finite doubles), never the code's own object. Integers without both
  bounds must fit in 64 bits; strings without a charset are measured in UTF-8 bytes; the length of
  strings and arrays is priced as part of the channel. `tests/unit/test_bandwidth.py` enumerates
  every value the gate can release for a set of small schemas and checks the count against the
  bound.
- **The owner sets the policy.** A dataset carries its own per-run cap and total budget. A schema
  wider than the cap is refused before anything runs; the budget is keyed on the dataset, so it is
  shared by every caller and cannot be reset by switching identity. Out of budget, the code does
  not run at all. In the cloud the dataset's bytes never come from the caller (the control plane
  loads them from a prefix the sandbox cannot read), and the budget is charged by a single
  conditional DynamoDB update before launch, so concurrent submissions cannot overspend it.

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
- **Run duration is the owner's, not the caller's.** It is recorded in the audit record only.
  Timing observed from outside (how long the API call took) remains out of scope, below.
- **No crash path around the gate.** Unparseable output, absurdly long integers, deep nesting,
  non-UTF-8 output and executor errors all become the same charged, attested "withheld".
- **Audit access.** The cloud API requires a bearer token; the owner-detail audit route
  (`GET /runs/{id}/audit`) takes a different token from the one callers hold. Locally, whoever
  supplies `--data` is the owner and sees the detail.

## Found and closed

An audit of the first version (all reproduced, all now covered by hostile tests):

| Finding | Was | Now |
|---|---|---|
| Unbounded `integer`/`number` | priced 64 bits, released a 13,000-bit integer | held to 64 bits; NaN/Infinity rejected |
| `string` with no charset | 8 bits per *code point*; a 12-char emoji string carried ~241 bits | measured in UTF-8 bytes |
| `enum [0, 1]` | `1`, `1.0`, `true` (and 0 likewise) were all released: 7 outputs for "1 bit" | exact match; the schema's own value is released |
| Array/string length | a list of a one-value item priced at 0 bits; length carried ~10 | length priced |
| Object key order | survived into the released value: up to 44 extra bits | objects rebuilt in schema order |
| Clean-room schema | chosen by the code provider; a valid grant + a wide string schema released a whole 7,979-byte dataset | owner's per-run cap |
| Budget | opt-in by the caller, keyed on a self-declared name | the dataset's, always on |
| `duration_ms` | returned to the caller on every run, even budget-refused ones | owner-only |
| Crash paths | two inputs skipped the gate, the charge and the receipt | caught, charged, attested |
| Local runs | the code could read the signing key and forge receipts | bubblewrap hides it |
| Cloud receipts | integer outputs failed verification after the DynamoDB round trip | stored byte-exact |
| Cloud pending record | kept the private data indefinitely | keeps hashes only; deleted on finalize |
| Cloud result envelope | trusted, and forgeable by the code (same uid as the runner) | separate uid; validated |

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
