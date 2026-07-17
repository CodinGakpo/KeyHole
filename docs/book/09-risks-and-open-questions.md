# Chapter 9 — Risks & Open Questions

Honest engineering names its risks before they bite. These are the ones known at design time.

## Product risks

- **Usefulness vs. the narrow exit.** The typed-exit model excludes "return arbitrary large output"
  workloads *by design*. That's the price of the guarantee. **Mitigation:** target the
  classify/score/extract/decide sweet spot and be explicit that this is a *different category* from
  isolation-first sandboxes, not a worse version of one.
  **Open question:** which schema types cover the most real use cases for the flagship demo?

- **"Is it revolutionary enough?"** The differentiation rests on being a distinct category
  (confidentiality-first, bandwidth-bounded, attested). **Mitigation:** the attestation and the
  bandwidth argument are the two things no incumbent packages together; keep both in the base.

## Security risks (and how the design already answers them)

- **Residual schema-bandwidth channel.** Real, but *bounded and disclosed* — the honest core, not a
  hidden flaw. **Rule:** scope every README/marketing claim to exactly the bandwidth bound; never
  say "zero leak."

- **Covert timing / resource side channels.** Out of scope for the base; named in `SECURITY.md`.
  Fixed-duration runs are a roadmap mitigation.

- **Attestation trust root.** The base attestation is signed by the control plane + KMS, so it
  proves what the control plane observed. **Open question / roadmap:** anchor attestation in
  hardware (Nitro Enclaves) so it doesn't require trusting the control plane.

## Cost / budget risks

- **VPC interface endpoints.** ECR + Logs interface endpoints run ~\$7/month each — the real budget
  pressure, since a NAT gateway is deliberately excluded. **Mitigation:** make endpoint/egress
  infra *opt-in at deploy* so an idle deployment costs ≈ \$0.
  **Open question:** confirm the minimal endpoint set needed for a Fargate ECR image pull without a
  NAT gateway.

- **Data size.** Supplying/hashing large datasets has cost and time bounds. **Mitigation:** cap
  input size; document limits.

## Operational risks

- **Fargate cold start (~10–30 s).** Hurts demo feel. **Mitigation:** warm pools are roadmap; the
  local Docker executor keeps the dev loop snappy in the meantime.

- **LocalStack Fargate fidelity is limited.** Don't over-trust it for execution correctness — the
  local Docker executor is the real fast-loop fidelity; LocalStack is for wiring/params.

- **Thin auth in the base** (API key / SigV4, single deployer). Multi-user and the multi-party
  clean-room are deferred.

## Technical pins

- Pin the sandbox image and any Lambda runtime to a stable supported Python (e.g. 3.12). Audit-hook
  and typing features assume ≥ 3.8.

## The meta-rule

Every item above is either **already answered by the design** (and says so) or **explicitly
deferred with a mitigation.** Nothing is left as an unexamined "we'll figure it out." When a future
decision resolves an open question, record it in [Appendix A](appendix-a-decision-log.md).
