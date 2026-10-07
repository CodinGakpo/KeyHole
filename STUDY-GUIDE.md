# Keyhole — Study Guide

How to present and defend this project. The order matters: **sell the problem first, then the
idea, then prove it, then go deep where they choose.** Parts 0–2 are what you say; Parts 3–8 are
what you need to know when they dig; Parts 9–11 are drills.

File:line references are real — open them as you read. Companion docs: `docs/book/00`→`09` is the
*why* behind every choice; `DEMO.md` is the live-demo runbook.

---

## Part 0 — The pitch (memorize the shape, not the words)

Engineers lose audiences by explaining the mechanism before anyone feels the problem. Always go:
**pain → why tools miss it → the one idea → proof → "where do you want to go deeper?"**

### The 30-second version

> "AI agents increasingly write and run code on data they shouldn't be able to take away —
> customer records, patient data, a partner's dataset. Today's sandboxes stop that code from
> breaking out, but they hand back whatever it returns, so the data walks out inside the answer.
> Keyhole flips it: before the code runs, you declare the shape of the answer — say, one of three
> labels. That's 1.58 bits; the customer file is 3,300 bits. It physically doesn't fit. A per-caller
> budget caps the total over many runs, and every run produces a signed receipt anyone can verify.
> I built it end to end, including a locked-down AWS deployment with KMS signing."

### The 2-minute version (five beats)

1. **Pain (20s).** "A hospital wants a vendor's AI to score its patient records. Today one side
   hands over its crown jewels — the hospital ships the data, or the vendor ships the model. With AI
   agents it's worse: the code was generated seconds ago and nobody reviewed it."
2. **Why tools miss it (15s).** "Sandboxes like E2B or Modal protect the *host* from the code. They
   return everything the code produces. The data leaks through the front door — the answer."
3. **The idea (15s).** "Keyhole — you can look through a keyhole, you can't carry the furniture out.
   You declare the answer's shape up front. Three labels is 1.58 bits. It's a limit on *size*, not a
   search for *content*, so encrypting the data first doesn't help the attacker."
4. **Proof (60s).** `make showtime` — let the visuals talk. Don't narrate what's on screen.
5. **Hand over (10s).** "I can go into the drip attack, the signed receipts, how the AWS network is
   sealed, or a hole I found in my own design. Where do you want to go?"

Beat 5 turns a presentation into a conversation where you're the expert. Whatever they pick, you
have a part of this guide for it.

**The single sentence under all of it:** *Confidentiality as a bandwidth argument, not a content
scan.*

---

## Part 1 — Positioning: never say "no equivalent"

A sharp interviewer will name a neighbor. If you claimed nothing like this exists, you lose
credibility on the spot. Claim the *combination* and show you know the field:

> "I didn't invent bounded leakage — it's an old idea from information-flow research, and
> differential privacy has a similar budget concept. What I built makes it a practical primitive for
> the case nothing else covers: untrusted or AI-written code, on private data, with a receipt."

| Neighbor | What it protects | The one-line distinction |
|---|---|---|
| **Sandboxes** (E2B, Modal, AgentCore, Firecracker) | host from code | "They contain the code; I constrain what it can *say*." |
| **TEEs** (Nitro Enclaves, SGX) | data from the operator | "They hide data from the cloud; the code inside can still return it. Complementary — Nitro is my roadmap for the signer." |
| **Data clean rooms** | data from queries | "They restrict SQL-style analyses; I allow arbitrary code and restrict the exit." |
| **DLP** | known patterns | "Encrypt-before-emit defeats any content scan. A bit limit can't be defeated by encoding." |
| **Differential privacy** | individuals in aggregates | "DP bounds what statistics reveal about a person; I bound how many bits any code can emit. Both use a budget." |
| **Quantitative information flow** (research) | — | "That's the theory my bandwidth number comes from: leakage measured in bits." |

Knowing the neighbors makes you sound *more* original, not less.

---

## Part 2 — The five core concepts

Each in ~30 seconds, without notes. Say them in this order — it's a chain:
**narrow schema → small bandwidth → bulk exfil impossible per run → budget bounds it across runs →
attestation proves it all happened.**

### 2.1 The confinement problem (Lampson, 1973)
You can *never* perfectly stop a program that sees secret data from signaling *some* of it out
(timing, resource use, its own legitimate output). That's a known impossibility. So we **don't
claim zero leak** — an interviewer would destroy that. We claim the leak is **bounded to a number
the caller chose and the attestation discloses.** This honesty is a strength. (Book ch. 4.)

### 2.2 The typed narrow exit
The caller declares, *in advance*, the exact shape of the one value the code may return: an enum, a
bounded integer, a length-bounded string, a bounded array, or a small closed object. Anything that
doesn't match is **not released**. Code: `src/keyhole/schema/spec.py`.

### 2.3 Exit bandwidth (the quantitative guarantee)
Every schema has a computable **upper bound in bits** on what one conforming value can carry. A
3-way enum = log₂(3) ≈ **1.58 bits**. That number *is* the guarantee. Code:
`src/keyhole/schema/bandwidth.py`.

### 2.4 The cumulative budget (drip defense)
One run leaks ≤ N bits; 10,000 runs leak 10,000 × N. A **per-principal ledger** caps the total
released bits across runs. Code: `src/keyhole/controlplane/budget.py`. (Its known gap: Part 7.)

### 2.5 The attestation
A signed record binding the code hash, data hash, schema hash, the exact output, the bandwidth, the
egress verdict, and (clean room) the owner/provider/dataset. Anyone with the public key verifies it
offline; tampering any field breaks the signature. Code: `src/keyhole/attest/`.

---

## Part 3 — Architecture in one picture

```
   caller (CLI / MCP / HTTP API)
      │  RunRequest { code, data, output_schema, limits, principal }
      ▼
 ┌─────────────────────── CONTROL PLANE (trusted) ───────────────────────┐
 │                                                                        │
 │   run the code ──► ExecResult (raw output bytes, exit code, events)    │
 │        │                                                               │
 │        ▼                                                               │
 │   ╔══════════════ THE EXIT GATE  (gate.py) ══════════════╗            │
 │   ║ 1. validate output vs schema   → fail ⇒ WITHHELD      ║            │
 │   ║ 2. compute exit bandwidth (bits)                      ║            │
 │   ║ 3. secondary DLP backstop      → hit  ⇒ WITHHELD      ║            │
 │   ║ 4. cumulative budget check     → over ⇒ WITHHELD      ║            │
 │   ║ 5. else RELEASE the value                             ║            │
 │   ║ 6. build + SIGN attestation (released OR withheld)    ║            │
 │   ╚═══════════════════════════════════════════════════════╝           │
 │        │                                                               │
 │        ▼   RunResult + Attestation + AuditRecord                       │
 └────────────────────────────────────────────────────────────────────────┘
```

**The most important architectural fact:** the untrusted code runs in **one trust domain** (the
sandbox — locally a subprocess, in the cloud a Fargate task); the **exit gate runs in another** (the
control plane). The code has *total freedom inside the box* and *zero authority over the gate*.
That's why the attacker can't "just change the schema" — it's on the wrong side of the boundary.

**The key invariant:** the *only* channel out of the box is the file named by the `KEYHOLE_OUTPUT`
env var. stdout, stderr, temp files, memory — none of them leave. (Run *status* is the exception —
see Part 7.)

**Be precise about local vs cloud.** Locally the code is an rlimited subprocess and *can* reach the
network; the local run demonstrates the exit gate. Network containment is the cloud layer's job
(Part 6). Never claim the local demo is network-isolated.

---

## Part 4 — Trace ONE run end to end (the code walk you must know)

The "open the files and narrate" skill. Follow a single honest local run.

**Step 1 — the request.** `RunRequest` (`common/models.py:40`) carries `code` (untrusted Python
source), `data` (`dict[filename → contents]`), `output_schema`, `limits`, and `principal` (the
code-provider identity the budget is keyed on). It's the *shared contract* every component speaks.

**Step 2 — execution.** `executor/entrypoint.py:run_code` → `_run_in` (line 47):
- writes each data file into a temp workdir (`work / Path(name).name` — flattened so a filename like
  `../etc/passwd` can't escape, line 53);
- writes the code to `__keyhole_code__.py`;
- sets a **minimal env** (line 63): `KEYHOLE_OUTPUT`, `PATH`, and *deliberately no AWS
  creds/metadata* — belt and braces even though the cloud task role is empty;
- runs `python -I` (isolated mode) as a subprocess (line 73) with a **timeout** and a `preexec_fn`
  that applies rlimits;
- reads whatever is at `KEYHOLE_OUTPUT` — that's `output_raw` — and returns an `ExecResult`.

The executor **does not judge** the output. Judging is the gate's job.

**Step 3 — the exit gate.** `controlplane/gate.py:run_exit_gate` (line 51). Read it top to bottom;
the ordering *is* the thesis (docstring, line 4). It hashes code/data/schema (lines 71-73), counts
egress attempts, then the decision cascade:
- timed out? → `TIMEOUT` (line 91)
- non-zero exit? → `FAILED` (line 94)
- no output file? → `FAILED` (line 97)
- output bigger than `max_output_bytes`? → `WITHHELD` (line 100)
- not valid JSON? → `WITHHELD` (line 109)
- **doesn't match the schema?** → `WITHHELD` (line 114) ← *the exfiltrator's fate*
- DLP backstop flags a secret/PII? → `WITHHELD` (line 123)
- over cumulative budget? → `WITHHELD` (line 129)
- **else → `SUCCEEDED`, released** (line 136), and the ledger is charged (line 141).

**Step 4 — validation.** `schema/validate.py:validate_output` (line 33). **Strict, no coercion** —
loose coercion would silently widen the exit (line 4). Subtlety at lines 116-127: a Python `bool` is
*not* accepted as an `int`/`number` (bool subclasses int, so it's excluded explicitly). Objects are
**closed** — undeclared properties are rejected (line 96).

**Step 5 — bandwidth.** `schema/bandwidth.py:bandwidth_bits` (line 23). Enum → log₂(n) (line 33).
Bounded int → log₂(span) (line 37). String → `max_length × log₂(charset size)` (line 48). Array →
`max_items × bandwidth(items)` (line 54). Object → sum of children (line 58). Unbounded scalars fall
back to 64 bits — **conservative: always overstates the channel, never understates** (line 9).

**Step 6 — attestation.** `attest/record.py`: the `Attestation` model (line 15). The **signed
claims** are exactly the fields in `build_claims` (line 55). The envelope (`algorithm`, `key_id`,
`signature`) is not signed — it carries the signature. Signed via `attest/sign.py:sign_attestation`
(line 80): canonical JSON bytes → `signer.sign()`.

**Step 7 — the result.** `GateOutcome` = `RunResult` (what the caller sees) + `Attestation` +
`AuditRecord` (the append-only trail).

> Rehearse this as a 2-minute spoken walk. Steps 2→3→4 cover 70% of any code question.

---

## Part 5 — Subsystem deep dives

### 5.1 Schema (`schema/spec.py`)
`OutputSchema` is a pydantic model with `extra="forbid"` (line 40) — no sneaking in extra fields. A
`model_validator` (line 63) allows only the fields relevant to the `type`, so a schema **can't be
quietly under-constrained** (under-constrained = wide exit). Guardrails: a string **must** declare
`max_length` (line 93); an array **must** declare `max_items` (line 104); an object caps at
`MAX_OBJECT_PROPERTIES = 16` (lines 18/111). This is where "narrow" is *enforced*.

### 5.2 The DLP backstop (`dlp/`)
`scan_secrets` + `scan_pii` run on the *serialized conforming output* (gate.py:121). It's a
*secondary* backstop, **not** the guarantee — it catches a schema wide enough to hold, say, a card
number. Never call DLP the primary defense: content scanning is exactly what Keyhole argues against
relying on. (Book ch. 3/4.)

### 5.3 Resource limits (`executor/limits.py`)
POSIX rlimits set in the child just before exec (`build_preexec`, line 20): address space (line 27),
CPU seconds (line 29), file size (line 33), and **`RLIMIT_NPROC = 256` against fork bombs** (line
35). Defense in depth — the *primary* resource ceiling in the cloud is Fargate task sizing.

### 5.4 Budget / drip defense (`controlplane/budget.py`)
`BudgetPolicy(max_exit_bits, window_seconds)` (line 24); `window_seconds=None` means forever.
`check_budget` (line 105) compares `spent + requested` against the cap. **Only released runs spend
budget** (line 10) — which is exactly the gap in Part 7. Two ledgers: `InMemoryLedger` (line 53) and
`FileLedger` (line 67, JSON under `~/.keyhole`). `FileLedger` **fails open** on a corrupt file (line
72) — a best-effort guardrail, not a signed record. Know it.

### 5.5 Attestation & verification (`attest/`)
Two signers behind one `Signer` protocol (`sign.py:29`):
- **`Ed25519Signer`** (line 36) — local dev; key outside the repo, `chmod 600`.
- **`KmsSigner`** (`attest/kms_signer.py`) — cloud; `ecdsa-p256-sha256` via `kms:Sign`. **The private
  key never leaves KMS.**

The signed claims are identical for both; only the signature bytes and envelope differ (sign.py:10).
One verifier handles both: `verify.py:verify_attestation` (line 23) branches on `att.algorithm`.
Verification is **stateless** — a third party needs only the record and the public key.

### 5.6 Multi-party clean room (`controlplane/cleanroom.py`)
`Dataset` (line 33) and `Grant` (line 41: unguessable `grant-<token>`, the dataset, and a grantee or
`"*"`). `DatasetStore` (line 61) is file-backed under `~/.keyhole/datasets/`. `load_files` (line 91)
— the bytes — is **server-side only, never returned to a provider**. `authorize()` (line 106) is a
pure function. `run_in_cleanroom` (line 119) authorizes first and on refusal **returns without
materializing data or running anything** (line 138); on success it builds a two-principal
`RunRequest` (line 142) and runs the same gate, so the attestation binds both identities.

**Volunteer:** grants are bearer tokens (production: signed + time-boxed), and separation is at the
control-plane layer (production: the provider's IAM can't read the dataset's S3).

---

## Part 6 — The cloud story (and the AWS gotcha that impresses)

### 6.1 The cloud run path (`controlplane/cloud_runner.py`)
Same gate, different substrate (docstring, line 3):
1. Upload `{code, data, timeout}` to **S3** (line 75).
2. **Presign** a GET (input) and PUT (output) URL (lines 77-84) — so the sandbox needs **no AWS
   credentials and the task role stays EMPTY**. The box can do exactly two S3 operations.
3. `ecs.run_task` in the private subnet (via `launcher.py`).
4. Wait for `STOPPED`; download the output envelope.
5. Run the **same `run_exit_gate`** (line 123).
6. Delete the run's S3 objects.

**Submit/finalize split** (lines 52 / 109): API Gateway times out at ~29s, but a Fargate cold start
can exceed that. So `POST /runs` launches and returns `202 PENDING`; `GET /runs/{id}` finalizes once
the task has stopped (`app.py:get_run`, line 76). A real distributed-systems decision — know it.

### 6.2 Hardened launch (`controlplane/launcher.py`)
`build_run_task_params` (line 25) is a **pure function**, so every containment choice is
unit-testable without AWS: empty task role, no NAT route, endpoint-only security group,
`assign_public_ip` **hard-wired False** (lines 23/45).

### 6.3 The control-plane API (`controlplane/app.py`)
Framework-agnostic handlers, so the same logic runs in tests (in-memory) and Lambda (DynamoDB).
`lambda_handler` (line 100) routes `POST /runs`, `GET /runs/{id}`, `/audit`, `/attestation`.
DynamoDB is the **append-only audit store**.

### 6.4 THE GOTCHA (this answer makes you look senior)
**Q: "How do you actually stop the code from making network calls?"**

"At the **subnet / route-table / security-group layer**, not an in-task sidecar proxy. Fargate's
`awsvpc` mode gives all containers in a task **one shared network namespace**, so a sidecar can't
be a *mandatory* chokepoint — the untrusted container can route around it. So containment is
structural: private subnet with **no NAT / no internet route**, a **deny-by-default security group**
that only reaches the S3/ECR/CloudWatch VPC endpoints, **no public IP**, and an **empty IAM task
role**. I kept the egress-proxy design for a possible separate-task chokepoint, and documented that
it doesn't carry over to a same-task sidecar."

That shows: a real AWS constraint, understood *why*, the correct fix, and honesty about the
abandoned approach. And you can add: *"I verified it on real AWS — the smoke test's internet probe
from inside the task returned False."*

---

## Part 7 — Threat model, hostile suite, and the hole I found

Every security claim ships with a hostile test that tries to break it (`tests/hostile/`):

| Attack | What it tries | Why it fails |
|---|---|---|
| **Bulk dump** | write the dataset to the output | fails schema → WITHHELD (bandwidth) |
| **Encode in bounded string** | smuggle data inside an allowed string | `max_length × log₂(charset)` *is* the disclosed bandwidth; budget caps accumulation |
| **stdout channel** | print the data | stdout isn't the exit |
| **Fork bomb** | exhaust the host | `RLIMIT_NPROC=256` + task sizing |
| **Memory hog** | OOM the host | `RLIMIT_AS` + task sizing |
| **Drip across runs** | leak a bit per released run | cumulative per-principal budget |
| **Clean room: ungranted** | run without a grant | `authorize()` refuses before data is materialized |
| **Clean room: cross-principal** | granted provider dumps the data | same bandwidth bound → WITHHELD |
| **Tamper attestation** | edit a signed field | signature INVALID |

`make hostile` runs them; `make test` → **90 passed, 2 skipped**.

### The hole: run status is a side channel

The budget charges only *released* runs (`gate.py:140`). But a failed run tells the caller its exit
code (`gate.py:96`: `"code exited with status {exit_code}"`). Exit codes span 0–255 — about
**8 bits per run, never charged, with no limit on runs.** Malicious code can exit with the next byte
of the file; ~414 runs drain the example dataset, even after the budget reports "exhausted".
Released-vs-withheld and timeout-vs-not are smaller versions of the same channel.

**The fix (planned):** collapse every non-release outcome into one opaque `withheld` status with no
detail returned to the caller (details stay in the owner's audit log), and charge **every** run.
The honest per-run bound then becomes log₂(choices + 1) — the +1 is "not released".

**How to tell it:** *"I found a hole in my own drip defense: failure codes were an uncharged side
channel — 8 bits a run. I closed it by making every non-release outcome look identical and charging
every run."* Finding and closing your own hole is the strongest security signal you can give. Being
caught with it is the worst.

### Out of scope (say so — it's honesty, not weakness)
- Covert *timing* channels (fixed-duration runs are future work).
- The residual within-schema channel (bounded, not zero).
- Hardware-level trust (the attestation trusts the control plane; Nitro Enclaves is the fix).

---

## Part 8 — The hard questions (with answers)

**Q1. "Can't the code just encode the data into the allowed output?"**
Yes — that's the residual channel and I raise it myself. A 3-way enum leaks ≤1.58 bits per run by
choosing *which* value. The per-principal budget caps the total. I never claim zero leak; I claim a
**provable, disclosed ceiling.**

**Q2. "Why can't the attacker disable the schema check?"**
The schema comes from the caller; the gate runs in a *different trust domain* than the code. You
can't unlock a box from inside it. In the cloud that boundary is real infrastructure (Fargate task
vs Lambda), and the signing key is in KMS where the box can't reach it.

**Q3. "How is this different from a container / E2B / Modal?"**
Those protect the *host* from the code and hand back *everything* it produced. I protect the *data*
from the code by narrowing the *return channel*. Theirs is "don't let code escape"; mine is "don't
let data escape."

**Q4. "Isn't a DLP scan enough?"**
No — that's the thesis. Encrypt-before-emit defeats any content scan. A bandwidth bound can't be
beaten by encoding: if only 1.58 bits fit, cleverness doesn't matter. DLP is a backstop only.

**Q5. "How do you actually block network egress?"** → Part 6.4.

**Q6. "What does the attestation prove, and to whom?"**
A signature over the code/data/schema hashes, the exact released value (or null), the bandwidth, the
egress verdict and the clean-room identities. Anyone with the public key verifies it **offline**.
Tamper any field → INVALID.

**Q7. "What's the weakest part / what would you build next?"**
(1) The status side channel (Part 7) — and how I'd close it. (2) The attestation trusts my control
plane; signing inside a **Nitro Enclave** makes it hardware-anchored. (3) Clean-room grants should
be signed and time-boxed, with IAM-level separation.

**Q8. "Doesn't the narrow exit block legitimate large outputs?"**
By design — that's the product boundary. Keyhole is for "untrusted code on sensitive data, small
answer back". If you need megabytes back, you're already trusting the code with bulk output. The
test: *is the data more sensitive than the answer is large?*

**Q9. "Real use cases?"** AI agent on private data; two-party clean room (hospital × vendor model,
bank × fraud vendor, ad measurement); untrusted marketplace plugins; scoring against a secret
benchmark.

**Q10. "Why trust your bandwidth numbers?"**
They're deliberately *conservative upper bounds* — unbounded scalars count as 64 bits, arrays assume
every element is max-entropy (`bandwidth.py:9`). The real leak is smaller than I claim, never larger.

**Q11. "What's actually novel here?"**
Not bounded leakage — that's from information-flow research (Part 1). The novelty is making it a
usable primitive for arbitrary, AI-generated code: a declared-width exit enforced outside the code's
trust domain, a cumulative bit budget, and a signed receipt — deployable into your own AWS account.

**Q12. "Can the code leak through *how* it fails?"**
Yes, today — and I found it myself (Part 7). Exit codes are an uncharged ~8-bit channel per run. The
fix: one opaque non-release status and charge every run, giving log₂(choices + 1) bits per run.

---

## Part 9 — Live demo

```bash
make showtime              # terminal 1 — press Enter between beats
make showtime-dashboard    # terminal 2 — http://127.0.0.1:8787, same runs
```

Six beats, each a real `sbx` command: **(1)** data vs exit — 3,312 bits vs 1.58; **(2)** honest code
→ RELEASED; **(3)** malicious code → WITHHELD; **(4)** drip attack — budget meter fills, run 6
refused; **(5)** clean room — partner runs, intruder refused; **(6)** receipt VALID → tamper one
field → INVALID. Rehearse with `make showtime ARGS=--auto`. Full runbook: `DEMO.md`.

Let the visual land before pressing Enter — beats 1 and 3 are where people get it. Don't deploy the
cloud live (5 minutes, cold starts); say you verified it on real AWS and tore it down, and offer to
walk the Terraform.

---

## Part 10 — Repo map

| Path (under `src/keyhole/`) | What | Priority |
|---|---|---|
| `schema/spec.py` | the narrow-exit definition + guardrails | ★★★ |
| `schema/bandwidth.py` | bits-per-schema accounting | ★★★ |
| `schema/validate.py` | strict output validation | ★★★ |
| `controlplane/gate.py` | **the exit gate** — the heart | ★★★ |
| `attest/record.py`, `sign.py`, `verify.py` | signed attestations | ★★★ |
| `executor/entrypoint.py` | run the code, capture the one output | ★★ |
| `executor/limits.py` | rlimits (fork bomb / memory) | ★★ |
| `controlplane/budget.py` | drip defense | ★★ |
| `controlplane/cleanroom.py` | two-principal clean room | ★★ |
| `controlplane/cloud_runner.py` | Fargate orchestration | ★★ |
| `controlplane/launcher.py` | hardened `run_task` | ★★ |
| `controlplane/app.py` | Lambda/API Gateway handlers | ★ |
| `common/models.py` | the shared data contract | ★★ |
| `infra/terraform/` (repo root) | AWS deploy | ★ |
| `tests/hostile/` (repo root) | the adversarial suite | ★★ |
| `docs/book/` (repo root) | the "why" behind every choice | ★★★ |

---

## Part 11 — Self-test (ready when you can do all of these from memory)

- [ ] Give the 30-second pitch, problem first, without mentioning a single file.
- [ ] Place Keyhole against sandboxes, TEEs, clean rooms, DLP and differential privacy in one line each.
- [ ] Explain the confinement problem and why you *don't* claim zero leak.
- [ ] Compute the bandwidth of a 3-way enum, an int in [0,255], a 10-char hex string.
- [ ] Name the gate order (validate → bandwidth → DLP → budget → release → sign).
- [ ] Explain why the attacker can't change the schema (trust-domain separation).
- [ ] Explain the drip attack, the budget, **and the status side channel + its fix.**
- [ ] Explain how egress is *actually* blocked and the awsvpc-sidecar gotcha.
- [ ] Explain what the attestation signs and how tampering is detected.
- [ ] Explain the clean-room model and what the attestation binds.
- [ ] Explain the submit/poll split (API Gateway's 29s timeout).
- [ ] Run `make showtime` cold, including the tamper → INVALID beat.
- [ ] Name three use cases and the "data more sensitive than the answer is large" test.
- [ ] Name three honest limitations.

Bandwidth answers: enum(3) = log₂3 ≈ **1.58**; int[0,255] = log₂256 = **8**; 10 hex chars =
10 × log₂16 = **40 bits**.
