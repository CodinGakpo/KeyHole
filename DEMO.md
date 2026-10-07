# Keyhole — live demo runbook

Everything here runs **locally, no AWS, ~10 seconds total.** Tested working.

## One-time setup (do this before the interview, not during)

```bash
cd ~/Project/keyhole
python -m pip install -e '.[dev]'
export PATH="$HOME/.local/bin:$PATH"     # so `sbx` is found (add to ~/.zshrc to make permanent)
sbx doctor                                # should print crypto: ok, dev key: ok
```

## Showtime (the visual version of everything below)

```bash
make showtime              # terminal 1: paced, press Enter between beats
make showtime-dashboard    # terminal 2: http://127.0.0.1:8787 over the same runs
```
Runs the real `sbx` commands in a throwaway `~/.keyhole-showtime` (wiped on each start).
Rehearse without pauses: `make showtime ARGS=--auto`.

## The 90-second story (run these in order, narrate as you go)

### 0. The one-liner that proves it works at all
```bash
make demo
```
> "Same dataset, same schema, two programs. Honest one gets a bounded answer released.
> Malicious one tries to dump the data — nothing comes out. Both are cryptographically attested."

### 1. Honest run — a bounded answer is released
```bash
sbx run examples/classify.py --data customers.csv=examples/customers.csv \
    --schema schemas/label.json --local
```
> "The code sees the whole customer file. The only thing it's *allowed* to return is one of
> three enum values — so at most 1.58 bits can ever leave. It returns `spam`. Released."

### 2. Exfiltration attempt — structurally withheld
```bash
sbx run examples/exfil.py --data customers.csv=examples/customers.csv \
    --schema schemas/label.json --local
```
> "Identical setup, but this program dumps the entire dataset into the output. The exit gate
> checks it against the schema, it doesn't conform, and **nothing is released.** Exit code 3.
> Not scanned for and blocked — structurally impossible, because the exit can't carry that many bits."

### 3. Multi-party clean room — an external party's AI on YOUR data
```bash
# Owner registers a dataset (bytes stay in the registry).
sbx dataset add customers.csv=examples/customers.csv --owner acme
#   -> note the dataset id, e.g. ds-9415bc8e0812

# Owner grants a specific code-provider.
sbx dataset grant ds-XXXX --to partner-ai
#   -> note the grant token, e.g. grant-1303fb...

# The provider runs by id + grant. They NEVER receive the bytes.
sbx run examples/classify.py --dataset ds-XXXX --grant grant-XXXX \
    --principal partner-ai --schema schemas/label.json --save-attestation att.json

# An un-granted party is refused before anything runs.
sbx run examples/classify.py --dataset ds-XXXX --grant grant-XXXX \
    --principal intruder --schema schemas/label.json
#   -> refused (exit 4); the data was never materialized
```
> "Two separate principals. The provider runs code on acme's data without ever seeing it, and the
> attestation binds *both* identities plus the dataset hash."

### 4. The proof — verify, then tamper
```bash
sbx verify att.json                       # VALID
# now tamper with a signed claim:
python -c "import json,pathlib; p=pathlib.Path('att.json'); d=json.loads(p.read_text()); d['data_owner']='evil'; p.write_text(json.dumps(d))"
sbx verify att.json                       # INVALID (exit 1)
```
> "Anyone can verify the signed attestation offline. Change a single bound field — the owner —
> and it's immediately INVALID. The proof is tamper-evident."

### 5. The visual — dashboard
```bash
sbx dashboard                             # -> http://127.0.0.1:8787   (Ctrl-C to stop)
```
> "A read-only forensic view of every run. The signature element is the exit-bandwidth aperture:
> a log-scale gauge from 1 bit to 1 MB, so a bounded exit reads as the sliver it is. Drag an
> attestation file onto it to verify."

## The suite (if they ask "how do you know it's not just the happy path?")
```bash
make test        # 90 passed, 2 skipped
make hostile     # just the adversarial exfiltration suite
```

## If asked about the cloud
Don't deploy live (costs money, ~30s cold start, risky on someone else's clock). Say:
> "It deploys into your own AWS account with one `terraform apply` — Lambda + API Gateway,
> DynamoDB audit, and a KMS signing key so the attestation private key never leaves KMS. I
> verified it live end-to-end and tore it down to ~$0. Happy to walk the Terraform."
Then show `infra/terraform/` and the README's *Deploy the cloud API* section.
