# Chapter 1 — The Problem: untrusted code meets private data

## The setting

Two things are now simultaneously true:

1. **Everyone runs untrusted code.** AI agents generate code and execute it as a normal step in
   their loop. Developers paste snippets, run notebooks from strangers, install packages whose
   contents nobody reads. Executing code you didn't write is no longer the exception; it's the
   default.
2. **That code increasingly touches private data.** The valuable AI use cases are not "run this
   toy script" — they're "analyze *my* customer table," "extract fields from *my* documents,"
   "classify *my* support tickets." The code and the sensitive data meet in the same process.

Put those together and you get the core question this project exists to answer:

> **How can you let untrusted code compute over your private data without it being able to steal
> that data?**

## Why the existing answers don't answer it

The sandbox market is crowded — E2B, Modal, Daytona, AWS Bedrock AgentCore Code Interpreter, and
many more. But they almost all solve a *different* problem. They are **isolation-first**:

- Their job is to stop the code from **escaping the box** and harming the *host* or other tenants.
- They succeed at this. Firecracker microVMs, gVisor, and similar give strong isolation.

Isolation protects *the platform from the code*. It says nothing about protecting **your data from
the code** once the code is legitimately allowed to read it. An isolation-first sandbox will
happily let untrusted code read your dataset and then `print()` it, POST it to an attacker, or
encode it into its output. The box didn't break — but your data still walked out the front door.

This gap is not hypothetical. In early 2026, public research against a major managed sandbox
demonstrated data exfiltration via DNS (escaping the "sandboxed" network mode) and extraction of
cloud credentials via the metadata service. The lesson we took from it is *not* "that product is
bad" — it's that **the whole isolation-first category leaves the confidentiality question
unanswered.**

## Why "just don't send data to the cloud" is a non-answer

An early instinct was to dodge the problem: run everything locally / self-hosted so the data never
leaves your environment. We rejected this (see [Chapter 2](02-decision-journey.md)). For a project
whose subject is *cloud* security, refusing to engage with the cloud is avoidance, not a solution.
The data lands in the cloud regardless — that's where the compute and the datasets live. The
interesting, honest, and marketable problem is to **solve exfiltration in the cloud, in place**,
not to retreat from it.

## What a real solution has to look like

From the above, a genuine solution must:

- Assume the data **is** in the cloud, next to the compute.
- Assume the code **is** untrusted and **can** read the data.
- Prevent the data from **leaving** — and do so in a way that survives an adversary actively trying
  to smuggle it out, not just a careless script.
- Be **honest** about what it can and cannot guarantee, because (as Chapter 3 shows) the strongest
  version of this is provably impossible.

Chapter 2 is the story of how we arrived at a design that meets this bar. Chapter 3 is the idea
itself.
