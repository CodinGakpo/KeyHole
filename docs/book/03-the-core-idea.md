# Chapter 3 — The Core Idea: bound the exit, don't scan it

## The theorem that shapes everything

In 1973, Butler Lampson described the **confinement problem**: if a program can read secret data
and can produce *any* output an observer sees, you cannot in general stop it from leaking the
secret. The reason is **covert channels** — the program can encode the secret in the timing, size,
ordering, or content of whatever it's allowed to emit. This is not an engineering gap that a
cleverer scanner closes; it's a fundamental limit.

Any product that says *"run untrusted code on secret data with a guarantee of zero leakage"* while
letting that code return a **free-form result** is therefore hiding fine print. Concretely: a
data-loss-prevention (DLP) scanner over the output looks for the secret in the result — but the
code can just `gzip` or **encrypt** the data before emitting it, and the scanner sees noise. The
guarantee evaporates the moment an adversary bothers to try.

We treat this as a design constraint, not an inconvenience to paper over.

## The move: turn the guarantee into a bandwidth argument

If you can't reliably inspect *what* leaves, then **control how much can leave.**

Mark-1's rule: untrusted code may return **only a value that matches a caller-declared, narrow,
typed schema.** Not a free-form blob — a shape the caller commits to in advance:

- an **integer** (optionally range-bounded),
- a **number** or **boolean**,
- an **enum** — one choice from a fixed set of labels,
- a **bounded string** — a hard maximum length, optionally a restricted charset/regex,
- a **small fixed object** composed of the above.

Now the argument changes character entirely. If the only exit is, say, a 3-way enum, then **at most
~1.58 bits** can leave per run. If it's a 32-character bounded string, the exit is a few hundred
bits — enough for a legitimate answer, far too narrow to smuggle a dataset through. **Bulk
exfiltration of the data is structurally impossible**, because there is no channel wide enough to
carry it. We don't have to catch the leak; there's nowhere for it to go.

This is the difference between:

| Approach | Guarantee rests on | Defeated by |
|---|---|---|
| DLP over free-form output | *inspecting* what leaves | encrypt-before-emit (trivially) |
| **Typed narrow exit (Mark-1)** | *bounding how much* can leave | nothing within the declared bound |

## Being precise about what remains

The narrow exit is a **bound, not a zero.** Whatever bits the schema legitimately carries are a
residual channel: a malicious script *could* choose the enum value or the bounded-string content to
encode a few bits of the secret. Mark-1 does two honest things about this:

1. **States the bound.** For each run it computes and records the exit's information content (e.g.
   "this schema permits at most N bits to leave").
2. **Attests the actual bytes.** The signed attestation (see below) records the *exact* value that
   was released, so the residual channel is not just bounded but *disclosed*.

We never say "zero leak." We say: *the leak is bounded to the schema you chose, and here is exactly
what came out.* That is a claim that actually holds.

## Making it verifiable: attestation

The last piece turns "trust us" into "verify it yourself." On every run, the control plane emits a
**cryptographically signed attestation** binding together: the hash of the code, the hash of the
data, the hash of the schema, the fact that egress attempts were all denied, the exit code, and the
exact released output and its hash. Anyone holding the attestation can later verify:

> *This exact code ran on this exact data with zero network egress, and the only thing that came out
> was this bounded value.*

That verifiability is what elevates Mark-1 from "a secure sandbox" to a **verifiable
confidential-compute primitive** — the kind of artifact a compliance or audit function can actually
rely on.

## Why this is a different category, not a better competitor

- **Isolation-first sandboxes** (E2B, Modal, AgentCore): free-form output, protect the *host* from
  the code. Mark-1 protects the *data* from the code.
- **Confidential-computing enclaves** (AWS Nitro): protect a *trusted* workload's data from the
  *host/operator*. Mark-1 protects a data owner from *untrusted* code.

Nobody packages *untrusted code + sensitive data + bandwidth-bounded, attested exit.* That's the
whitespace Mark-1 occupies.

## The honest fit

This model is a natural fit for the tasks that dominate "AI on private data": **classify, score,
extract-a-field, decide, summarize-to-a-bounded-string.** Their legitimate answers are *small*. It
is deliberately **not** for "return arbitrary large output" workloads — that's what isolation-first
sandboxes are for. Choosing a sharp, defensible category over a fuzzy, all-things-to-all-people
pitch is itself one of the project's core decisions.
