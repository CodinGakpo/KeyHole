# Mark-1

**Confidential code execution with a bandwidth-bounded, attested exit.**

Run untrusted or AI-generated code on your private data in the cloud, and get back **only a small,
typed, cryptographically-attested answer** — so the data *structurally* cannot leave.

```bash
# Classify some private emails without letting the code exfiltrate them.
sbx run classify.py --data emails.csv=./emails.csv --schema schemas/label.json --local
# → status: succeeded   output: "spam"   bandwidth: 1.58 bits   attestation: att-…

# A script that tries to dump the whole dataset instead:
sbx run exfil.py --data emails.csv=./emails.csv --schema schemas/label.json --local
# → status: withheld    output does not conform to the declared schema  (nothing released)
```

## Why it's different

Isolation-first sandboxes (E2B, Modal, AWS AgentCore) stop code from **escaping the box** — they
protect the *host* from the code. They do nothing to stop code that legitimately reads your data
from **leaking** it. Mark-1 protects the **data** from the code:

- Untrusted code may return **only** a value matching a caller-declared **narrow schema** (int /
  enum / bounded string / small object). A few-byte exit makes **bulk exfiltration structurally
  impossible** — a bandwidth argument, not a content scan that encrypt-before-emit defeats.
- Every run emits a **signed attestation**: *this exact code ran on this exact data with zero
  egress, and only this bounded value came out* — verifiable by anyone.
- Deploys into **your own AWS account** with one `terraform apply`. Designed for < ~$10/month, ≈ $0
  idle. An MCP server lets AI agents use it directly.

Built on the confinement problem (Lampson, 1973): we never claim "zero leak." We claim the leak is
**bounded to the schema you chose and disclosed in the attestation.** See [`SECURITY.md`](SECURITY.md).

## Status

Early build. The confidentiality core (typed exit, bandwidth accounting, attestation, exit gate,
local executor) is implemented and tested and runs today via `sbx run --local`. The AWS deployment
(Terraform, Fargate, images) is scaffolded and not yet applied.

## Layout

| Path | What |
|---|---|
| `src/mark1/schema/` | The typed narrow exit + bandwidth accounting — the core guarantee. |
| `src/mark1/attest/` | Signed, verifiable attestations. |
| `src/mark1/controlplane/gate.py` | The exit gate: validate → bandwidth → backstop → attest → release. |
| `src/mark1/executor/` | Local executor (fast dev loop) matching the cloud contract. |
| `src/mark1/cli/`, `src/mark1/mcp/` | Thin CLI and MCP clients. |
| `infra/terraform/` | One-command AWS deploy (no NAT; ≈ $0 idle). |
| `images/` | Sandbox + egress-proxy container images. |
| `tests/hostile/` | The marquee: hostile scripts that try to exfiltrate — and can't. |
| `docs/book/` | The decision book: every design choice and why. |
| `docs/FUTURE-SCOPE.md` | The roadmap of future features. |

## Develop

```bash
python -m pip install -e '.[dev]'
make test        # unit + hostile suite
make lint
sbx doctor       # check your environment
```

## License

MIT.
