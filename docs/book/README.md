# The Mark-1 Book

A chapter-by-chapter record of what Mark-1 is, why it exists, and **every design decision** made
along the way — including the ideas that were tried and rejected. This is the narrative companion
to the execution spec (see the approved plan in `/home/adi/.claude/plans/` and, once written, the
formal spec under `docs/superpowers/specs/`).

> **One-line pitch:** Run untrusted or AI-generated code on your private data in the cloud, and get
> back only a small, typed, cryptographically-attested answer — so the data *structurally* cannot
> leave.

## Table of Contents

0. [Preface — How to read this book](00-preface.md)
1. [The Problem — untrusted code meets private data](01-the-problem.md)
2. [The Decision Journey — every pivot and why](02-decision-journey.md)
3. [The Core Idea — bound the exit, don't scan it](03-the-core-idea.md)
4. [Security & Threat Model — the honest scope](04-security-and-threat-model.md)
5. [Architecture — how a run flows](05-architecture.md)
6. [Components & Repo Structure](06-components-and-repo.md)
7. [Milestones & Roadmap](07-milestones-and-roadmap.md)
8. [Verification — the hostile exfiltration suite](08-verification.md)
9. [Risks & Open Questions](09-risks-and-open-questions.md)

**Appendices**
- [A — Decision Log (chronological)](appendix-a-decision-log.md)
- [B — Alternatives Considered & Rejected](appendix-b-alternatives-considered.md)

## Status

- **Concept & design:** locked (this book).
- **Implementation:** not started. Planning was done on Claude Fable; implementation intended on
  Claude Opus.
- **Repo:** greenfield. This `docs/book/` is the first content committed.

## How this book stays true

Every chapter states not just *what* was decided but *what was rejected and why*. If a future
decision reverses something here, add a dated entry to [Appendix A](appendix-a-decision-log.md)
rather than silently editing history — the value of this book is the reasoning trail.
