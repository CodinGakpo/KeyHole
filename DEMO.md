# Keyhole — live demo runbook

Local, no AWS. `make showtime` takes ~3 minutes at your pace; the manual fallback below takes about
the same. Rehearse both before the day.

## One-time setup (before the interview, not during)

```bash
cd ~/Project/keyhole
python -m venv .venv && source .venv/bin/activate
python -m pip install -e '.[dev]'
sbx doctor                       # crypto: ok, dev key: ok
make showtime ARGS=--auto        # full dry run, no pauses (~12 s)
```

Use the venv's `sbx` (`source .venv/bin/activate`), not a global one.

## Before you type anything: the opener

Don't start with the terminal. Start with the problem (STUDY-GUIDE Part 0):

> "A hospital wants a vendor's AI to score its patient records. Today one side hands over its crown
> jewels. Sandboxes don't fix it — they stop code breaking *out*, then hand back whatever it
> returns. Keyhole limits what the answer can *be*. Let me show you."

## The demo: `make showtime`

```bash
make showtime              # terminal 1 — press Enter to advance
make showtime-dashboard    # terminal 2 (optional) — http://127.0.0.1:8787, same runs
```

Every command it shows is the real `sbx` CLI; state lives in a throwaway `~/.keyhole-showtime`,
wiped on each start. One line to say per beat — let the screen do the rest:

| Beat | On screen | Say |
|---|---|---|
| 1. Data vs exit | 3,312-bit bar vs a 1.58-bit sliver; 2,090-square grid | "The code sees all of this. Only this much can come out." |
| 2. Honest code | `classify.py` → green **RELEASED** `"spam"` | "Fits the schema, passes the scans, gets signed and released." |
| 3. Malicious code | `exfil.py` → red **WITHHELD** | "Nobody searched for the data. It just doesn't fit." |
| 4. Drip attack | budget meter fills over 5 runs, run 6 refused | "Small leaks add up, so each caller has a total bit budget." |
| 5. Clean room | partner runs on acme's data; intruder **REFUSED** | "The partner computed on data it never received." |
| 6. Proof | receipt **VALID** → change one field → **INVALID** | "Anyone can check this offline. Touch one byte and it breaks." |

Beats 1 and 3 are where people get it — pause there. After the finale, hand over:
*"Want to go into the budget, the receipts, the AWS lockdown, or a hole I found in my own design?"*

## Manual fallback (if showtime misbehaves)

```bash
# 2. Honest run — released
sbx run examples/classify.py --data customers.csv=examples/customers.csv \
    --schema schemas/label.json --local

# 3. Exfiltration attempt — withheld, exit code 3
sbx run examples/exfil.py --data customers.csv=examples/customers.csv \
    --schema schemas/label.json --local

# 4. Drip attack — runs 1–5 released, run 6 withheld
for i in 1 2 3 4 5 6; do
  sbx run examples/classify.py --data customers.csv=examples/customers.csv \
      --schema schemas/label.json --local --principal mallory --budget-bits 8 | grep -E "status|budget"
done

# 5. Clean room — note the ids each command prints
sbx dataset add customers.csv=examples/customers.csv --owner acme          # → ds-XXXX
sbx dataset grant ds-XXXX --to partner-ai                                  # → grant-XXXX
sbx run examples/classify.py --dataset ds-XXXX --grant grant-XXXX \
    --principal partner-ai --schema schemas/label.json --save-attestation att.json
sbx run examples/classify.py --dataset ds-XXXX --grant grant-XXXX \
    --principal intruder --schema schemas/label.json                       # refused, exit 4

# 6. Proof — verify, tamper, verify
sbx verify att.json                                                        # VALID
python -c "import json,pathlib; p=pathlib.Path('att.json'); d=json.loads(p.read_text()); d['data_owner']='evil'; p.write_text(json.dumps(d))"
sbx verify att.json                                                        # INVALID, exit 1

sbx dashboard                                                              # http://127.0.0.1:8787
```

The drip ledger persists in `~/.keyhole/ledger.json`; use a fresh `--principal` name for a rerun.

## "How do you know it's not just the happy path?"

```bash
make hostile     # the adversarial suite: dump, encode, stdout, fork bomb, memory hog, drip, clean room
make test        # everything: 90 passed, 2 skipped
```

## Be precise about what the local demo proves

The local run proves the **exit gate**: schema, bandwidth, budget, receipts. The code runs as a
resource-limited subprocess and *can* reach the network locally. Network containment is the cloud
layer's job — say so if asked, then use the cloud answer below.

## If asked about the cloud

Don't deploy live (≈5 minutes to come up, 30–60 s cold start per run). Say:

> "It deploys into your own AWS account with one command — Fargate in a subnet with no internet
> route and an empty IAM role, a Lambda + API Gateway control plane, DynamoDB audit, and a KMS key
> so the signing key never leaves KMS. I ran it end to end on real AWS: the honest answer came back
> KMS-signed, the exfiltrator was withheld, and an internet probe from inside the sandbox failed.
> Then I tore it down to ≈ $0."

Then show `infra/terraform/` and STUDY-GUIDE Part 6.4 (the awsvpc sidecar gotcha). To actually
deploy before an interview: `infra/terraform/environments/dev/stack.sh up` (and `down` after).
