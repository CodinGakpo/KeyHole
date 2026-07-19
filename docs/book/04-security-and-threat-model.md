# Chapter 4 — Security & Threat Model: the honest scope

A security product is only as good as the precision of its claims. This chapter states exactly what
Mark-1 guarantees, what it bounds, and what it explicitly does not cover. This is the content that
belongs in the shipped `SECURITY.md`.

## The two structural guarantees

Mark-1 rests on two independent guarantees, both **structural** (properties of the architecture,
not behaviors of a scanner):

### 1. No side exits (containment)

The dataset must have nowhere to go *except* the declared result:

- **No network egress.** The sandbox runs in a private subnet with **no NAT gateway** and no
  internet route, behind a run security group whose only egress is to AWS service endpoints (the S3
  prefix list and in-subnet ECR/Logs interface endpoints). Default runs literally cannot reach the
  general internet. Containment is enforced at the **subnet/route/SG layer**, not by an in-task
  sidecar — see the M5 correction below.

  > **Correction (M5).** Earlier drafts of this chapter described an *egress-proxy sidecar* as "the
  > sandbox's only possible network path." Standing the system up on Fargate revealed this is not
  > how `awsvpc` works: every container in a task shares **one network namespace**, so a sidecar
  > cannot transparently intercept its neighbour's traffic — it is a peer, not a gateway. The honest
  > enforcement point is the network itself (private subnet, no NAT, endpoints-only security group),
  > which is where containment now lives. The egress-proxy image and its Docker harness are retained
  > for the future *allowlisted-egress* feature, which requires a genuine chokepoint (e.g. a separate
  > proxy task the sandbox is routed through) rather than a same-task sidecar.
- **No reachable cloud credentials.** The task's IAM role is **empty** — the container-metadata
  endpoint vends credentials that can do nothing. (Fargate has no EC2 instance-metadata service, so
  the classic instance-profile theft vector doesn't exist.) The executor also strips
  `ECS_CONTAINER_METADATA_URI*` from the child process environment.
- **No persistence.** Read-only root filesystem plus an ephemeral scratch space; the task is
  destroyed after the run.

### 2. Bounded front exit (the novel core)

The single result channel must **validate against the caller-declared schema** before anything is
released. A run whose output doesn't conform releases *nothing*. The exit's information content
(its bandwidth, in bits) is computed and recorded per run. See [Chapter 3](03-the-core-idea.md).

## What is provably guaranteed

- The data cannot leave via network, credentials, or persistent storage.
- The only value that can leave is one conforming to the schema you declared.
- Therefore **bulk exfiltration of the dataset is structurally impossible.**
- The signed **attestation** lets a third party verify all of the above for a specific run.

## What is bounded, not zero

- The declared schema's own information content is a **residual channel.** A malicious script can
  choose the permitted value (which enum, which characters in a bounded string) to encode a small
  number of bits. This is **bounded** (to the schema's bandwidth) and **disclosed** (the exact
  released bytes are attested). We never claim "zero leak."

### Accumulation across runs — the cumulative budget

The per-run bound says nothing about *repetition*. An adversary who can call the box N times, each
run individually within schema, could drip out N × bandwidth bits over time — the per-run guarantee
is silent on the total. Mark-1 closes this with a **per-principal cumulative exit-bandwidth budget**
(`controlplane/budget.py`): a ledger records the bits released to each caller and, optionally, only
within a rolling window (e.g. per day). At the exit gate, a conforming output is **withheld** once
releasing it would push the caller's total past the cap. Only *released* runs spend budget — a
withheld run leaks nothing, so it charges zero — and we charge the schema's conservative upper
bound, never less. The `test_drip_exfiltration_over_runs` hostile test proves a repeated
one-bit-per-run leak is capped no matter how many times the attacker calls. The budget is a
guardrail recorded in the audit trail, deliberately *outside* the signed attestation, so the
attestation schema and verifier stay stable.

### List answers without a hidden wide exit — the bounded array

Some real tasks return a short list (top-k labels, a few extracted fields). The `array` schema type
supports this but requires a `max_items` bound, exactly as `string` requires `max_length`: an
unbounded array would be a wide exit. Its bandwidth is `max_items × item_bits` — a conservative
upper bound that is always finite and shown to the caller — so a list can never smuggle a dataset
past the gate under the guise of "just a few items."

## What is explicitly out of scope (named, not hidden)

- **Covert timing / resource side channels.** A script could modulate its runtime or resource use
  to signal bits to an observer who can measure them. Mitigations (e.g. fixed-duration runs) are
  roadmap, not base.
- **Inference leakage.** A legitimate small answer may itself reveal something about the data (e.g.
  "is record #5 fraudulent? → yes"). Bounding the channel doesn't make a truthful answer private;
  that's the caller's modeling problem, not the sandbox's.
- **Breaking AWS's own isolation.** Mark-1 relies on Fargate task isolation as its Layer-1
  substrate. If that is breached, that's outside Mark-1's threat model (and AWS's responsibility).

## The trust boundary of the attestation

The attestation is signed by the control plane using a per-deployment KMS key. Its trust root is
therefore **the integrity of the control plane and that key.** This is honest and adequate for the
base: it proves to a *third party* what the control plane observed. A stronger future version would
anchor attestation in hardware (e.g. Nitro Enclaves) so it doesn't depend on trusting the control
plane — that's on the roadmap, not in the base.

## The defense-in-depth backstop (secondary)

A DLP / secret + PII scan still runs over the (small) output. It is **explicitly secondary** — a
backstop that might catch an obvious mistake, not the guarantee. The bandwidth bound is the
guarantee. Keeping this ordering clear is deliberate: it's the exact mistake (leaning on DLP as the
guarantee) that Chapter 3 exists to avoid.

## The one-sentence threat model

> *Untrusted code may read the supplied data and compute freely, but the only thing that can leave
> the sandbox is a value conforming to the caller's declared schema — bounding any leak to that
> schema's information content, disclosing the exact bytes released via a signed attestation, and
> making bulk exfiltration structurally impossible; covert timing channels and inference leakage
> are out of scope.*
