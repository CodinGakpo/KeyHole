# Chapter 0 — Preface: How to read this book

## What Keyhole is

Keyhole is a **confidential code-execution sandbox**. You give it untrusted or AI-generated Python
plus some private data, it runs the code in an isolated, zero-egress AWS environment, and it hands
back **only a small, typed, cryptographically-attested answer**. The design goal is that your data
*structurally cannot leave* — not because a scanner caught it on the way out, but because there is
no wide enough exit for it to leave through.

## Why this book exists

This is a marquee portfolio/passion project. For a project whose whole point is *judgment* —
security judgment, architectural judgment, product judgment — the reasoning matters as much as the
code. This book records that reasoning so that:

- A reviewer (or future employer) can see *how* the idea was pressure-tested, not just the polished
  result.
- The builder can resume work months later without re-deriving why each decision was made.
- The many rejected directions are preserved, because **the rejections are the most instructive
  part** — they show the traps that were seen and avoided.

## Who built it and under what constraints

- Solo builder, student / early-career, strongest in Python.
- Cloud: AWS. Budget: under ~$10/month, running on AWS free-tier credits.
- Long-lived passion project: a tight, impressive **base (MVP)** plus a documented roadmap of
  add-ons. No end date.

## The two documents

| Document | Purpose |
|---|---|
| **This book** (`docs/book/`) | The narrative + every decision + rejected alternatives. Read to understand *why*. |
| **The plan / spec** (`/home/adi/.claude/plans/...`, later `docs/superpowers/specs/`) | The execution blueprint: milestones, file layout, verification. Read to understand *how to build*. |

## A note on intellectual honesty

Keyhole's security claim is deliberately *bounded*. It is built on a 1970s theoretical result (the
confinement problem) that says the strong version of what it does is impossible. Rather than hide
that, the design leans into it: it promises exactly what provably holds and names what it cannot
do. Chapter 3 and Chapter 4 make this precise. If you take one thing from this book, take that the
honesty *is* the design.
