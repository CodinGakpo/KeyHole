# Chapter 8 — Verification: the hostile exfiltration suite

## The principle

A security claim you haven't tried to break is a hope, not a guarantee. Keyhole's marquee
verification is a suite of **hostile scripts** — code that actively tries to steal the supplied
data by every avenue — with assertions that each attempt is **structurally blocked or bounded**
*and* faithfully recorded in the attestation/audit. A green run of this suite is the product's
proof and the centerpiece of the whole project.

## The test layers

- **Unit (fast, no cloud).** The core lives here: `schema/validate.py` + `bandwidth.py`
  (conforming outputs pass, non-conforming rejected, bandwidth computed correctly), `attest`
  sign→verify round-trip including **tamper detection**, `launcher.py` parameter construction
  (empty task role, private subnet, no public IP), backstop DLP, quotas, budget, clean room, and the
  control-plane handlers against an in-memory store.
- **Integration (local).** The MCP server driven over its real stdio wire
  (`test_mcp_transport.py`), and a Docker harness for the egress proxy (`test_egress_containment.py`,
  opt-in). No LocalStack layer: cloud wiring is kept in pure functions that unit tests cover.
- **Integration (real AWS, manual).** `stack.sh up`, then `scripts/cloud_smoke.py` runs an honest
  classifier, an exfiltrator and an internet probe on real Fargate, then `stack.sh down`. Kept off CI
  to protect the budget.

## The hostile suite

Each script runs every CI cycle against the local executor, and (gated) against real
Fargate. Each asserts a control holds **and** that the data-flow record captured the attempt.

| Script | Attempts to… | Expected result |
|---|---|---|
| `net_exfil_dns.py` | leak via DNS queries | no egress path; blocked + logged by the proxy |
| `net_exfil_tcp.py` | open an outbound socket | connection blocked + logged |
| `cred_theft.py` | pull cloud creds from the metadata endpoint | credentials are useless / AccessDenied |
| `dump_dataset_to_output.py` | return the whole dataset as the result | **schema validation rejects it; nothing released** — the headline structural win |
| `encode_dataset_in_string_field.py` | smuggle data into a bounded-string field | leak is capped to the declared bandwidth; the exact bytes are attested — an honest demonstration of the *bounded, disclosed* residual channel |
| `secret_in_output.py` | print a secret in the small output | backstop DLP flags + withholds |
| `fork_bomb.py` / `cpu_spin.py` / `mem_hog.py` | exhaust resources | timeout + limits kill the task cleanly; platform unaffected |

## What "green" demonstrates

A passing suite shows all three of Keyhole's claims at once:

1. **Typed answers are released and attested** — the product does useful work.
2. **Bulk exfiltration is structurally impossible** — the core guarantee holds against active
   attack, not just careless code.
3. **The residual channel is bounded and disclosed** — the honest limit is demonstrated, not
   hidden.

## The rule for every future feature

Any new capability that makes a new security claim must arrive with a hostile test that tries to
violate it. New claim → new adversary script → assertion. This is how the roadmap in
[`docs/FUTURE-SCOPE.md`](../FUTURE-SCOPE.md) grows without eroding trust: the test suite is the
contract.
