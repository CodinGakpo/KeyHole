# Mark-1 — Study Guide

Everything you need to defend this project inside-out, grounded in the actual code (file:line
references are real — open them as you read). Work through it top to bottom; it's ordered from
"the one idea" outward to the details.

Companion docs: the **decision book** (`docs/book/00`→`09`) is the *why* behind every choice; this
guide is the *what* and *how* with code pointers. `DEMO.md` is the live-demo runbook.

---

## Part 0 — The one paragraph (memorize this cold)

> Isolation sandboxes (E2B, Modal, AWS AgentCore) protect the **host** from untrusted code — they
> stop code escaping the box. They do nothing about code that legitimately reads your data and then
> **leaks** it. Mark-1 protects the **data** from the code. Untrusted code may return **only** a
> value matching a caller-declared **narrow schema** (an enum, a bounded int, a small object). If
> the widest that exit can carry is 1.58 bits and the dataset is 20 KB, bulk exfiltration is
> **mathematically impossible, not scanned-for**. Every run emits a **signed attestation** proving
> exactly what code ran on exactly what data, with zero network egress, and exactly what bounded
> value came out — verifiable by anyone, offline.

The single sentence under that: **"Confidentiality as a bandwidth argument, not a content scan."**

---

## Part 1 — The five core concepts

You must be able to explain each of these in ~30 seconds without notes.

### 1.1 The confinement problem (Lampson, 1973)
You can *never* perfectly stop a program that can see secret data from signaling *some* of it out
(via timing, resource use, its own legitimate output, etc.). This is a proven impossibility. So we
**do not claim zero leak** — that would be a lie an interviewer could destroy. We claim the leak is
**bounded to a number the caller chose and the attestation discloses.** This honesty is a strength:
it shows you understand the theory. (Book ch. 4.)

### 1.2 The typed narrow exit
The caller declares, *in advance*, the exact shape of the one value the code may return: an enum, a
bounded integer, a length-bounded string, a bounded array, or a small closed object. Anything that
doesn't match is **not released** — nothing leaves. Code: `src/mark1/schema/spec.py`.

### 1.3 Exit bandwidth (the quantitative guarantee)
Every schema has a computable **upper bound in bits** on how much can leave through one conforming
value. A 3-way enum = log₂(3) ≈ **1.58 bits**. That number *is* the guarantee, made numeric. Code:
`src/mark1/schema/bandwidth.py`.

### 1.4 The cumulative budget (drip defense)
One run leaks ≤ N bits. But calling 10,000 times, encoding a bit each time, leaks 10,000 bits. So a
**per-principal ledger** caps *total* released bits across all runs. Code:
`src/mark1/controlplane/budget.py`.

### 1.5 The attestation
A signed record binding: code hash, data hash, schema hash, the exact output, the bandwidth, the
egress verdict, and (clean room) the owner/provider/dataset identities. Anyone with the public key
can verify it offline; tampering any field breaks the signature. Code: `src/mark1/attest/`.

**The chain of reasoning that ties them together (say it in this order):**
narrow schema → small bandwidth → bulk exfil structurally impossible per run → budget bounds it
across runs → attestation proves all of the above happened.

---

## Part 2 — Architecture in one picture

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

**The single most important architectural fact:** the untrusted code runs in **one trust domain**
(the sandbox — locally a subprocess, in cloud a Fargate task); the **exit gate runs in a different
trust domain** (the control plane). The code has *total freedom inside the box* and *zero authority
over the gate*. That separation is why the attacker can't "just change the schema" — it's on the
wrong side of the boundary.

**The key invariant:** the *only* channel out of the box is the value written to the file named by
the `MARK1_OUTPUT` env var. stdout, stderr, temp files, memory — none of them leave. The gate
stands on that one file.

---

## Part 3 — Trace ONE run end-to-end (the code walk you must know)

This is the "open the files and narrate" skill. Follow a single honest local run.

**Step 1 — the request.** `RunRequest` (`common/models.py:40`) carries `code` (untrusted Python
source, a string), `data` (`dict[filename → contents]`), `output_schema`, `limits`, and `principal`
(the code-provider identity the budget is keyed on). This model is the *shared contract* every
component speaks (CLI, MCP, control plane, executor all import it).

**Step 2 — execution.** `executor/entrypoint.py:run_code` →`_run_in` (line 47):
- writes each data file into a temp workdir (`work / Path(name).name` — flattened so a filename like
  `../etc/passwd` can't escape, line 53);
- writes the code to `__mark1_code__.py`;
- sets a **minimal env** (line 63): `MARK1_OUTPUT` = the output path, `PATH`, and *deliberately no
  AWS creds/metadata* — belt-and-suspenders even though the cloud task role is already empty;
- runs `python -I` (isolated mode) as a subprocess (line 73) with a **timeout** and a
  `preexec_fn` that applies rlimits;
- after exit, reads whatever is at `MARK1_OUTPUT` — that's `output_raw`. Returns an `ExecResult`
  (raw output, exit code, stdout/stderr, duration, `timed_out`, byte count, data-flow events).

Note: the executor **does not judge** the output. It just captures it. Judging is the gate's job.

**Step 3 — the exit gate.** `controlplane/gate.py:run_exit_gate` (line 51). Read this function
top-to-bottom; the ordering *is* the thesis (the docstring says so, line 4). It computes the three
hashes (code/data/schema, lines 71-73), counts egress attempts, then the decision cascade:
- timed out? → `TIMEOUT`, withheld (line 91)
- non-zero exit? → `FAILED` (line 94)
- no output file? → `FAILED` (line 97)
- output bigger than `max_output_bytes`? → `WITHHELD` (line 100)
- not valid JSON? → `WITHHELD` (line 109)
- **doesn't match the schema?** → `WITHHELD` (line 114) ← *this is the exfiltrator's fate*
- DLP backstop flags a secret/PII? → `WITHHELD` (line 123)
- over cumulative budget? → `WITHHELD` (line 129)
- **else → `SUCCEEDED`, released = True** (line 136), and the budget ledger is charged (line 141).

**Step 4 — validation.** `schema/validate.py:validate_output` (line 33). **Strict, no coercion**
(loose coercion would silently widen the exit — line 4). Note the subtlety at lines 116-125: a
Python `bool` is *not* accepted as an `int`/`number` (bool is a subclass of int in Python, so they
exclude it explicitly). Objects are **closed** — undeclared properties are rejected (line 93).

**Step 5 — bandwidth.** `schema/bandwidth.py:bandwidth_bits` (line 23). Enum → log₂(n) (line 33).
Bounded int → log₂(span) (line 37). String → `max_length × log₂(charset size)` (line 48). Array →
`max_items × bandwidth(items)` (line 54). Object → sum of children (line 58). Unbounded scalars fall
back to fixed machine widths (64 bits) — **conservative: it always overstates the channel, never
understates** (line 9). That conservatism is the honest choice.

**Step 6 — attestation.** `attest/record.py`: the `Attestation` model (line 15). The **signed
claims** are exactly the fields in `build_claims` (line 55) — the hashes, the output, the bandwidth,
the egress counts, `released`, and the three clean-room identities. The signature envelope
(`algorithm`, `key_id`, `signature`) is explicitly **not** signed (it carries the signature). Signed
via `attest/sign.py:sign_attestation` (line 80) — canonical JSON bytes → `signer.sign()`.

**Step 7 — the result.** The gate returns a `GateOutcome` = `RunResult` (what the caller sees) +
`Attestation` + `AuditRecord` (the append-only trail). Done.

> Rehearse this as a 2-minute spoken walk. If you can narrate steps 2→3→4 confidently, you've
> covered 70% of any code question.

---

## Part 4 — Subsystem deep-dives

### 4.1 Schema (`schema/spec.py`)
`OutputSchema` is a pydantic model with `extra="forbid"` (line 40) — you can't sneak extra fields.
A `model_validator` (line 63) enforces that only the fields relevant to the `type` are set, so a
schema **can't be quietly under-constrained** (an under-constrained schema = a wide exit). Key
guardrails: a string **must** declare `max_length` ("an unbounded string is a wide exit", line 90);
an array **must** declare `max_items` (line 99); an object caps at `MAX_OBJECT_PROPERTIES = 16`
(line 18/105). This is where "narrow" is *enforced*, not just hoped for.

### 4.2 The DLP backstop (`dlp/`)
`scan_secrets` + `scan_pii` run on the *serialized conforming output* (gate.py:121). **Important
framing:** this is a *secondary* backstop, **not** the guarantee. The guarantee is the bandwidth
bound. DLP is there to catch the pathological case where a schema is wide enough to hold, say, a
credit-card number. Never describe DLP as the primary defense — a content scan is exactly what
Mark-1 argues *against* relying on (encrypt-before-emit defeats scans; it can't defeat a bandwidth
bound). Book ch. 3/4.

### 4.3 Resource limits (`executor/limits.py`)
POSIX `rlimit`s set in the child just before exec (`build_preexec`, line 20): address space (memory
cap, line 27), CPU-seconds (line 29), file size (line 33), and **`RLIMIT_NPROC = 256` to blunt fork
bombs** (line 35). Honest caveat (line 3): these are *defense-in-depth*; the *primary* resource
ceiling in the cloud is the Fargate task sizing. On non-POSIX it degrades to a no-op and only the
wall-clock timeout applies.

### 4.4 Budget / drip defense (`controlplane/budget.py`)
`BudgetPolicy(max_exit_bits, window_seconds)` (line 24) — `window_seconds=None` means "forever."
`check_budget` (line 105) compares `spent + requested` against the cap. **Only *released* runs spend
budget** — a withheld run leaked nothing, so it charges 0 (line 10). Two ledger implementations:
`InMemoryLedger` (tests/local, line 53) and `FileLedger` (line 67, JSON under `~/.mark1`, so spend
accumulates across separate CLI invocations). The `FileLedger` **fails open** to "no spend yet" on a
corrupt file (line 72) — it's a best-effort guardrail, not a signed record; know this, it's an
honest limitation. Proven by the `test_drip_exfiltration_over_runs` hostile test.

### 4.5 Attestation & verification (`attest/`)
Two signer backends behind one `Signer` protocol (`sign.py:29`):
- **`Ed25519Signer`** (line 36) — local dev; key persisted outside the repo, `chmod 600`.
- **`KmsSigner`** (`attest/kms_signer.py`) — cloud; `algorithm="ecdsa-p256-sha256"`, calls
  `kms:Sign`. **The private key never leaves KMS.**

The *signed claim set is identical* for both — only the signature bytes and the `algorithm`/`key_id`
envelope differ (sign.py:10). So one verifier handles both: `verify.py:verify_attestation` (line 23)
branches on `att.algorithm` (ed25519 at line 37, ECDSA-P256 at line 41). Verification is
**dependency-light and stateless** (line 2) — a third party needs only the record + the public key.
Tamper any signed field → canonical bytes change → `InvalidSignature` → returns False.

**The demo money-shot** rests here: change `data_owner` in a signed attestation JSON, re-verify →
INVALID. You saw it: exit code 1.

### 4.6 Multi-party clean room (`controlplane/cleanroom.py`)
Two principals instead of one. `Dataset` (line 33: id, owner, `data_sha256`, filenames) and `Grant`
(line 41: an unguessable `grant-<token>` bearer token, the dataset it's for, and a `grantee`
provider name or `"*"`). `DatasetStore` (line 61) is file-backed under `~/.mark1/datasets/{meta,
data,grants}`. Crucially, `load_files` (line 91) — the actual bytes — is **server-side only, never
returned to a provider**.

`authorize()` (line 106) is a **pure function**: dataset exists? grant exists? grant matches *this*
dataset? grantee is `"*"` or the provider? Any "no" → `Decision(False, reason)`.

`run_in_cleanroom` (line 119): authorize first; on refusal **return without materializing data or
running anything** (line 138 — the provider only ever learns "denied"). On success, build a
two-principal `RunRequest` (`principal=provider`, `data_owner=dataset.owner`, `dataset_id=...`, line
142) and call the same `run_local`. The attestation then binds both identities + the dataset hash.

**Honest limitations to volunteer:** grants are *bearer tokens* (unguessable, but not
signed/expiring — production would sign + time-box them); and the owner/provider separation is at
the *control-plane layer* (the registry holds the bytes) — true *infra-level* separation (the
provider's IAM literally can't read the dataset's S3) is the noted cloud follow-up.

---

## Part 5 — The cloud story (and the AWS gotcha that impresses)

### 5.1 The cloud run path (`controlplane/cloud_runner.py`)
Same exit gate, different execution substrate. Flow (docstring, line 3):
1. Upload `{code, data, timeout}` bundle to **S3** (line 75).
2. **Presign** a GET (input) and PUT (output) URL (lines 77-84). *Why:* the sandbox uses these URLs
   to read input and write output, so **it needs no AWS credentials and the task role stays EMPTY**.
   This is elegant — the box can do exactly two S3 operations and nothing else.
3. `ecs.run_task` in the private subnet with the run security group (via `launcher.py`).
4. Wait for the task to reach `STOPPED`; download the output envelope from S3.
5. Run the **same `run_exit_gate`** (line 123) — the guarantee is identical to local.
6. Delete the run's S3 objects.

**Submit/finalize split** (lines 52 / 109): `submit_cloud` launches and returns immediately;
`finalize_cloud` runs after the task stops. *Why it exists:* API Gateway has a ~29-second timeout,
but a Fargate cold start + run can exceed that. So the HTTP API does **async submit/poll**: `POST
/runs` launches and returns `202 PENDING`; `GET /runs/{id}` finalizes once the task has stopped
(`app.py:get_run`, line 76). Know this — it's a real distributed-systems design decision.

### 5.2 Hardened launch (`controlplane/launcher.py`)
`build_run_task_params` (line 25) is a **pure function** so every containment choice is unit-testable
without AWS. `LauncherConfig` (line 15) documents them: the task definition carries the **empty task
role**; the subnet has **no route to a NAT gateway**; the security group's egress is limited to the
S3/ECR/Logs VPC endpoints (no internet); `assign_public_ip` is **hard-wired False** (line 23/45).

### 5.3 The control-plane API (`controlplane/app.py`)
Framework-agnostic handlers (line 1) so the same logic runs in unit tests (in-memory store) and in
Lambda (DynamoDB). `lambda_handler` (line 100) routes API Gateway v2 events: `POST /runs` →
`submit_run`, `GET /runs/{id}` → `get_run` (finalizes if stopped), plus `/audit` and `/attestation`
sub-routes. `submit_run` (line 53) does a quota check, launches, and persists a `PENDING` result +
the finalize context. DynamoDB is the **append-only audit store**.

### 5.4 THE GOTCHA (this one answer makes you look senior)
**Q: "How do you actually stop the code from making network calls?"**

A: "At the **subnet / route-table / security-group layer** — *not* an in-task sidecar proxy. The
reason is specific: Fargate's `awsvpc` mode gives all containers in a task **one shared network
namespace**, so a proxy sidecar can't be a *mandatory* chokepoint — the untrusted container could
just route around it to the shared interface. So containment is structural: the task runs in a
private subnet with **no NAT / no internet route**, a **deny-by-default security group** that only
reaches the S3/ECR/CloudWatch VPC endpoints, **no public IP**, and an **empty IAM task role**. I kept
the deny-by-default egress-proxy design (M3) for a possible future *separate-task* chokepoint, but
I was honest in the docs that it doesn't carry over to a same-task sidecar."

That answer shows: you hit a real AWS constraint, understood *why*, chose the correct fix, and were
honest about the abandoned approach. (Book ch. 4; README M5 note.)

---

## Part 6 — The threat model & hostile suite (the marquee)

The project's discipline: **every security claim ships with a hostile test that tries to break it.**
`tests/hostile/` is where you prove you're not just asserting safety. Be able to name these:

| Attack | What it tries | Why it fails |
|---|---|---|
| **Bulk dump** | write the whole dataset to the output | fails schema validation → WITHHELD (bandwidth) |
| **Encode-in-bounded-string** | smuggle data inside an allowed string | the string's `max_length × log₂(charset)` *is* the disclosed bandwidth — bounded, and the budget caps accumulation |
| **stdout channel** | print the data instead of writing output | stdout is not the exit; only `MARK1_OUTPUT` leaves |
| **Fork bomb** | exhaust the host | `RLIMIT_NPROC=256` + task sizing |
| **Memory hog** | OOM the host | `RLIMIT_AS` + task sizing |
| **Drip across runs** | leak 1 bit per run, many runs | cumulative per-principal budget |
| **Clean-room: ungranted provider** | run on data without a grant | `authorize()` refuses *before* the data is materialized |
| **Clean-room: cross-principal exfil** | granted provider dumps the data | same bandwidth bound holds across principals → WITHHELD |
| **Tamper attestation** | edit a signed field | canonical bytes change → signature INVALID |

Run them live: `make hostile`. Full suite: `make test` → **90 passed, 2 skipped**.

**What's explicitly out of scope (say so — it's honesty, not weakness):**
- Covert *timing* channels (fixed-duration runs are future work).
- The residual within-schema channel (bounded, not zero — the confinement problem).
- Hardware-level trust (the attestation currently trusts the control plane; Nitro Enclaves is the
  future fix so you don't have to).

---

## Part 7 — The hard interview questions (with answers)

**Q1. "Can't the code just encode the data into the allowed output?"**
Yes — that's the residual covert channel and I raise it myself. A 3-way enum leaks ≤1.58 bits per
run; the code can choose *which* value to encode a bit. My defense is the cumulative per-principal
budget capping total bits across runs. I never claim zero leak — the confinement problem proves
that's impossible. I claim a **provable, disclosed ceiling.**

**Q2. "Why can't the attacker disable the schema check?"**
The schema comes from the caller on the request; the exit gate runs in a *different trust domain*
than the code. The code has full freedom inside the box and zero authority over the gate. You can't
unlock a box from inside it. In cloud that boundary is real infra (Fargate task vs Lambda control
plane), and the signing key is in KMS where the box can't reach it.

**Q3. "How is this different from just running code in a container / E2B / Modal?"**
Those are isolation-first: they protect the *host* from the code and hand you back *everything* the
code produced. That's the opposite of what I want. I protect the *data* from the code by making the
*return channel* narrow. Different threat model — theirs is "don't let code escape," mine is "don't
let data escape."

**Q4. "Isn't a DLP scan enough?"**
No, and that's the whole thesis. A content scan is defeated by encrypt-before-emit — the code
encrypts the data, the scanner sees noise, the attacker decrypts it later. A **bandwidth** bound
isn't: if only 1.58 bits fit through the exit, it doesn't matter how cleverly they're encoded. DLP
is my *secondary* backstop, never the guarantee.

**Q5. "How do you actually block network egress?"** → the Part 5.4 gotcha answer.

**Q6. "What does the attestation actually prove, and to whom?"**
It's a signature over: the code hash, data hash, schema hash, the exact released value (or null), the
bandwidth, the egress verdict, and the clean-room identities. Anyone with the signer's public key can
verify it **offline** — no access to my system. It proves *this exact code ran on this exact data,
zero egress, and only this bounded value came out.* Tamper any field and it's INVALID.

**Q7. "What would you build next / what's the weakest part?"**
Two things. (1) The attestation trusts my control plane — moving signing into a **Nitro Enclave**
makes it hardware-anchored so you don't have to trust me. (2) Clean-room grants are bearer tokens
and separation is control-plane-level — production wants **signed, time-boxed grants + infra-level
IAM separation** so the provider's role literally can't read the dataset's S3.

**Q8. "Doesn't the narrow exit block legitimate large outputs?"**
Yes, by design — that's the product boundary. Mark-1 is for "run untrusted code on sensitive data,
get a small answer" (a label, a score, a count, a few extracted records via bounded arrays). If you
need megabytes back, you're already trusting the code with bulk output and you'd use an isolation
sandbox. The mental test: *is the data more sensitive than the answer is large?*

**Q9. "Real use cases?"** → AI agent analyzing private data; two-party clean room (hospital records ×
vendor model; bank txns × fraud vendor; ad measurement); untrusted marketplace plugins on user data;
GDPR/residency-bounded compute; scoring models against a secret benchmark.

**Q10. "Why should I trust your bandwidth numbers?"**
They're deliberate *conservative upper bounds* — unbounded scalars fall back to full machine width
(64 bits), arrays assume every element is max-entropy. It always overstates the channel, never
understates it (`bandwidth.py:9`). If anything the real leak is smaller than I claim.

---

## Part 8 — Live demo (pointer)

Full runbook with narration: **`DEMO.md`**. The 90-second spine:
1. `make demo` — honest released, exfil withheld, both attested.
2. `sbx run examples/classify.py …` → released, 1.58 bits.
3. `sbx run examples/exfil.py …` → **withheld** (exit 3).
4. clean room: register → grant → provider runs → **intruder refused** (exit 4).
5. `sbx verify att.json` → VALID; tamper `data_owner` → **INVALID** (exit 1).
6. `sbx dashboard` → the exit-bandwidth aperture gauge.

Do **not** deploy the cloud live (money, ~30s cold start). Talk to `infra/terraform/` and say you
verified it live and tore it down.

---

## Part 9 — Repo map (where everything lives)

| Path | What | Read priority |
|---|---|---|
| `schema/spec.py` | the narrow-exit definition + guardrails | ★★★ |
| `schema/bandwidth.py` | bits-per-schema accounting | ★★★ |
| `schema/validate.py` | strict output validation | ★★★ |
| `controlplane/gate.py` | **the exit gate** — the heart | ★★★ |
| `attest/record.py`,`sign.py`,`verify.py` | signed attestations | ★★★ |
| `executor/entrypoint.py` | run the code, capture the one output | ★★ |
| `executor/limits.py` | rlimits (fork bomb / memory) | ★★ |
| `controlplane/budget.py` | drip defense | ★★ |
| `controlplane/cleanroom.py` | two-principal clean room | ★★ |
| `controlplane/cloud_runner.py` | Fargate orchestration | ★★ |
| `controlplane/launcher.py` | hardened `run_task` | ★★ |
| `controlplane/app.py` | Lambda/API Gateway handlers | ★ |
| `common/models.py` | the shared data contract | ★★ |
| `infra/terraform/` | one-command AWS deploy | ★ |
| `tests/hostile/` | the adversarial suite | ★★ |
| `docs/book/` | the "why" behind every choice | ★★★ |

---

## Part 10 — Self-test (you're ready when you can do all of these from memory)

- [ ] State the thesis in one sentence and the difference from E2B/Modal.
- [ ] Explain the confinement problem and why you *don't* claim zero leak.
- [ ] Compute the bandwidth of a 3-way enum, a bounded int [0,255], a string(max_length=10, hex).
- [ ] Name the exit-gate decision order (validate → bandwidth → DLP → budget → release → attest).
- [ ] Explain why the attacker can't change the schema (trust-domain separation).
- [ ] Explain the drip attack and the cumulative-budget defense.
- [ ] Explain how egress is *actually* blocked and the awsvpc-sidecar gotcha.
- [ ] Explain what the attestation signs and how tamper-detection works.
- [ ] Explain the clean-room two-principal model and what the attestation binds.
- [ ] Explain the submit/poll split and why (API Gateway 29s timeout).
- [ ] Run the whole demo cold, including the tamper→INVALID beat.
- [ ] Name three real use cases and the "is the data more sensitive than the answer is large?" test.
- [ ] Name three honest limitations (bounded-not-zero, bearer-token grants, no hardware attestation).

Answers to the bandwidth arithmetic: enum(3) = log₂3 ≈ **1.58**; int[0,255] = log₂256 = **8**;
string(10 hex chars) = 10 × log₂16 = 10 × 4 = **40 bits**.
