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
  internet route. An egress-proxy sidecar is the sandbox's only possible network path, and it
  denies and logs every attempt. Default runs literally cannot reach the network.
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
